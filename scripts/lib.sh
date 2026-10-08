# shellcheck shell=bash
# Shared settings for the bench's shell scripts (bash 3.2 or later). Source it:
#
#   . "<repo>/scripts/lib.sh"
#
# BENCH_HOME           where the running bench lives: its generated PKI and keys, step-ca, Vault, the Veraison
#                      deployment, configuration and logs. Never in git. Default ~/.attestation-bench; TACRA_BENCH,
#                      its former name, is honoured.
# VERAISON_DEPLOYMENT  the native Veraison deployment. Default $BENCH_HOME/veraison.
#
# It puts the bench's own tools first on PATH (step, step-ca, vault, the protoc plug-ins, the Python environment) and
# sets BENCH_REPO, BENCH_OS (darwin, linux) and BENCH_ARCH (amd64, arm64), plus the pins of scripts/versions.env.

BENCH_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_HOME="${BENCH_HOME:-${TACRA_BENCH:-$HOME/.attestation-bench}}"
VERAISON_DEPLOYMENT="${VERAISON_DEPLOYMENT:-$BENCH_HOME/veraison}"
PATH="$BENCH_HOME/bin:$BENCH_HOME/tools/bin:$BENCH_HOME/venv/bin:$PATH"
GOWORK=off
export BENCH_REPO BENCH_HOME VERAISON_DEPLOYMENT PATH GOWORK

# shellcheck source=scripts/versions.env
. "$BENCH_REPO/scripts/versions.env"

BENCH_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64 | amd64) BENCH_ARCH=amd64 ;;
  arm64 | aarch64) BENCH_ARCH=arm64 ;;
  *) BENCH_ARCH="$(uname -m)" ;;
esac
export BENCH_OS BENCH_ARCH

# Every listener of the local trust zone; all bind 127.0.0.1.
BENCH_PORTS="8200 8443 8453 8463 9000 9101 9102 9103 9104 9443 10443 18443 19443 50051"
export BENCH_PORTS

# The Go modules that make lint and make test cover: all but the proof of concept's est module, kept as the SIG wrote
# it: its go.mod takes the EST server from a checkout beside the repository (../../globalsign-est), and its test does
# not build against the current EST code.
BENCH_GO_MODULES="bundle cai e2e gen/go hwcheck hwcheck/vlekcheck platform rrp"
export BENCH_GO_MODULES

bench_say() { printf '== %s\n' "$*"; }
bench_die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# bench_retry LOG COMMAND...: a copy to or from a VM, tried up to three times, 10 s apart. Such a copy fails now and
# then for a reason of the cloud's (a dropped connection, an SSH key the VM has not taken yet); each failure goes to
# LOG with its time, so the run directory shows it. Returns the last try's status.
bench_retry() {
  local log=$1 rc=0 try
  shift
  for try in 1 2 3; do
    if "$@" 2>>"$log"; then return 0; else rc=$?; fi
    echo "$(bench_now) try $try of 3 failed, exit $rc: $1" >>"$log"
    [ "$try" = 3 ] || sleep 10
  done
  return "$rc"
}

# The time now, UTC, as the run records write it (vm-deleted.txt: when the VM was found gone).
bench_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# bench_guest_run LOG SCRIPT CMD...: runs SCRIPT (bash) in a VM through CMD, an SSH command that takes the remote
# command as its last argument (`gcloud compute ssh VM ... --command`, `ssh ... user@host`), so that a broken SSH
# session does not end the run. The script is written to a directory of its own in the VM (~/bench-run-<id>) and
# started there detached from the session (setsid, nohup), its output and exit status kept beside it (out, rc); short
# calls, retried, print the output as it grows and read the status when it ends. It is started once: when the call
# that starts it breaks after the VM ran it, the call made again finds the directory and starts nothing. Each failed
# call goes to LOG. Returns the script's status, or 255 if it was not started, or not over within BENCH_GUEST_TIMEOUT
# seconds (default 1800).
#
# BENCH_CHAOS_SSH=1 tests this on a real VM, by breaking SSH sessions on purpose from the VM's side: the call that
# starts the script breaks its own session a second after the script started, as when that call's answer is lost;
# from the script's 20th second to its 35th the VM breaks every SSH session of the bench's user to it; and the
# script's status is held back until its 40th second, so that the calls asking for it fall in that window however
# short the script. The run must end as it would have without; LOG says the test was on.
bench_guest_run() {
  local log=$1 script=$2 b64 d off=0 rc="" deadline chunk out last="" LC_ALL=C # C: lengths in octets, as tail -c counts
  shift 2
  b64="$(printf '%s\n' "$script" | base64 | tr -d '\n')"
  # a call takes at least one 3 s turn, so the second of two calls never starts in the same second as the first
  d="bench-run-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
  # setsid where there is one (every Linux VM): a session of its own, which the SSH session's end does not reach
  local chaos="" wrap="bash ~/$d/run.sh > ~/$d/out 2>&1; echo \$? > ~/$d/rc"
  if [ "${BENCH_CHAOS_SSH:-}" = 1 ]; then
    wrap="t0=\$(date +%s); bash ~/$d/run.sh > ~/$d/out 2>&1; r=\$?; w=\$((t0 + 40 - \$(date +%s))); [ \$w -le 0 ] || sleep \$w; echo \$r > ~/$d/rc"
    echo "$(bench_now) BENCH_CHAOS_SSH=1: the VM breaks this call's session once the script started, and every SSH session to it from the script's 20th second to its 35th" >>"$log"
    chaos=" && { \$s nohup bash -c 'sleep 20; e=\$((\$(date +%s) + 15)); while [ \$(date +%s) -lt \$e ]; do pkill -KILL -u \$(id -u) -x \"sshd|sshd-session\"; sleep 0.1; done' > /dev/null 2>&1 < /dev/null & } && sleep 1 && pkill -KILL -u \$(id -u) -x 'sshd|sshd-session'"
  fi
  bench_retry "$log" "$@" "mkdir ~/$d 2>/dev/null || exit 0; echo $b64 | base64 -d > ~/$d/run.sh && { s=; command -v setsid >/dev/null 2>&1 && s=setsid; \$s nohup bash -c '$wrap' > /dev/null 2>&1 < /dev/null & }$chaos" ||
    return 255
  deadline=$(($(date +%s) + ${BENCH_GUEST_TIMEOUT:-1800}))
  while [ -z "$rc" ] && [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 3
    # the status, read first (empty while the script runs; once it is there, the output is whole), then the output
    # since the last call, a marker and the status; a call that fails (the session broke) is written to LOG and made
    # again at the next turn
    if ! chunk="$("$@" "r=\$(cat ~/$d/rc 2>/dev/null); tail -c +$((off + 1)) ~/$d/out 2>/dev/null; printf '\n@@bench-rc@@%s' \"\$r\"" 2>>"$log")"; then
      echo "$(bench_now) a call to the VM failed; asking again" >>"$log"
      continue
    fi
    case "$chunk" in *@@bench-rc@@*) ;; *) continue ;; esac
    out="${chunk%$'\n'@@bench-rc@@*}"
    rc="${chunk##*@@bench-rc@@}"
    printf '%s' "$out"
    off=$((off + ${#out}))
    [ -z "$out" ] || last="${out: -1}"
  done
  if [ -z "$rc" ]; then
    echo "$(bench_now) the script in the VM did not end within ${BENCH_GUEST_TIMEOUT:-1800} s" >>"$log"
    return 255
  fi
  # a newline, if the output does not end with one
  if [ -n "$last" ] && [ "$last" != $'\n' ]; then echo; fi
  return "$rc"
}

# bench_require_up: exits unless every service of the bench runs (e2e/scripts/bench.sh status). What needs the running
# trust zone (make test-live, the attack runs' checks through the live verifiers and their pre-play) fails without
# it; it never skips.
bench_require_up() {
  local status
  status="$("$BENCH_REPO/e2e/scripts/bench.sh" status 2>&1)" || true
  if [ -z "$status" ] || grep -qv ' running' <<<"$status"; then
    printf '%s\n' "$status" | sed 's/^/  /' >&2
    bench_die "the bench is not up: make setup, or make start, first"
  fi
}

# bench_clock_offset FILE CMD...: the guest's clock against this machine's, the RRP's, over one call through CMD (an
# SSH command that takes the remote command as its last argument): this machine's clock before the call, the guest's
# during it, this machine's after. The offset is the guest's minus the middle of the call, within half its length.
bench_clock_offset() {
  local file=$1 t0 g t1
  shift
  t0="$(python3 -c 'import time; print(f"{time.time():.3f}")')"
  g="$("$@" 'date -u +%s.%N' 2>/dev/null | tail -1)" || g=""
  t1="$(python3 -c 'import time; print(f"{time.time():.3f}")')"
  python3 - "$t0" "$g" "$t1" >"$file" <<'PY'
import sys

t0, g, t1 = float(sys.argv[1]), sys.argv[2].strip(), float(sys.argv[3])
print(f"this machine (the RRP), before the call: {t0:.3f}")
print(f"the guest, during it: {g or 'no answer'}")
print(f"this machine, after it: {t1:.3f}")
try:
    print(f"guest minus RRP: {float(g) - (t0 + t1) / 2:+.3f} s, within {(t1 - t0) / 2:.3f} s")
except ValueError:
    print("guest minus RRP: not measured, the guest did not answer")
PY
}

# bench_sha256 FILE: the hex digest, with whichever tool the system has
bench_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# bench_fingerprint: one SHA-256 over the bench's programs and configuration (BENCH_HOME/bin and /config), names and
# contents. bench.sh start records it when it starts every service; make setup compares, and restarts services that
# run older programs or configuration.
bench_fingerprint() {
  python3 - "$BENCH_HOME" <<'PY'
import hashlib, os, sys
h = hashlib.sha256()
for top in ("bin", "config"):
    for root, dirs, files in os.walk(os.path.join(sys.argv[1], top)):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(root, f)
            with open(p, "rb") as fh:
                h.update(os.path.relpath(p, sys.argv[1]).encode() + b"\0" + fh.read())
print(h.hexdigest())
PY
}

# bench_seal DIR: writes DIR/sha256sums.txt, the SHA-256 of every other file under DIR in path order. It is a run
# directory's last step: later, `shasum -a 256 -c sha256sums.txt` (or sha256sum -c) inside DIR shows that nothing in
# it has changed.
bench_seal() {
  local tmp
  tmp="$(mktemp)"
  if (
    cd "$1" || exit 1
    find . -type f ! -name sha256sums.txt -print0 | LC_ALL=C sort -z \
      | if command -v sha256sum >/dev/null 2>&1; then xargs -0 sha256sum; else xargs -0 shasum -a 256; fi
  ) >"$tmp"; then
    chmod 644 "$tmp" && mv "$tmp" "$1/sha256sums.txt"
  else
    rm -f "$tmp"
    return 1
  fi
}

# bench_go_tool NAME MODULE@VERSION DIR: installs that version of a Go program into DIR with go install, unless it is
# there already; says which
bench_go_tool() {
  local name=$1 spec=$2 dir=$3 ver="${2##*@}" out
  if [ -x "$dir/$name" ] && go version -m "$dir/$name" 2>/dev/null | awk '$1 == "mod" {print $3}' | grep -qx "$ver"; then
    echo "  $name $ver: present"
    return 0
  fi
  if ! out="$(env GOBIN="$dir" CGO_ENABLED=0 go install "$spec" 2>&1)"; then
    printf '%s\n' "$out" >&2
    return 1
  fi
  echo "  $name $ver: installed"
}

# wait for a TCP port on 127.0.0.1 (30 s)
bench_wait_port() {
  local _
  for _ in $(seq 1 120); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.25; done
  echo "port $1 did not open" >&2
  return 1
}

# Hardware runs create their VMs in the account the cloud's own CLI is signed in to; the bench keeps no cloud
# credentials. Their settings come from the environment:
#
#   GCP_PROJECT  the Google Cloud project. Default: gcloud's own (gcloud config get-value project)
#   GCP_ZONE     default us-central1-c, where the reference runs ran SEV-SNP (n2d-standard-2) and TDX (c3-standard-4)
#   AWS_REGION   default us-east-2, where the reference runs ran SEV-SNP (c6a.large)
#   AWS_AZ       default: zone "a" of AWS_REGION
#
# bench_gcp and bench_aws check that the CLI is installed and signed in (bench_gcp also finds the project), say where
# the VMs will go, and stop with what to do when something is missing.
GCP_ZONE="${GCP_ZONE:-us-central1-c}"
AWS_REGION="${AWS_REGION:-us-east-2}"
AWS_AZ="${AWS_AZ:-${AWS_REGION}a}"
bench_gcp() {
  command -v gcloud >/dev/null 2>&1 || bench_die "gcloud is not installed: https://cloud.google.com/sdk/docs/install"
  GCP_PROJECT="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
  [ -n "$GCP_PROJECT" ] ||
    bench_die "no Google Cloud project: set GCP_PROJECT=<project id>, or run: gcloud config set project <project id>"
  [ -n "$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null)" ] ||
    bench_die "gcloud is not signed in: run gcloud auth login"
  [ "$(gcloud projects describe "$GCP_PROJECT" --format='value(projectId)' 2>/dev/null)" = "$GCP_PROJECT" ] ||
    bench_die "Google Cloud project $GCP_PROJECT does not exist or your account cannot see it: gcloud projects list"
  CLOUDSDK_CORE_DISABLE_PROMPTS=1
  export GCP_PROJECT GCP_ZONE CLOUDSDK_CORE_DISABLE_PROMPTS
  bench_say "Google Cloud: project $GCP_PROJECT, zone $GCP_ZONE"
}
bench_aws() {
  command -v aws >/dev/null 2>&1 || bench_die "the AWS CLI is not installed: https://aws.amazon.com/cli/"
  AWS_PAGER=""
  export AWS_REGION AWS_AZ AWS_PAGER
  aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1 ||
    bench_die "the AWS CLI is not signed in: run aws configure, or aws sso login"
  bench_say "AWS: region $AWS_REGION, zone $AWS_AZ"
}
