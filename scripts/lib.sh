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
BENCH_PORTS="8200 8443 8453 8463 9000 9101 9102 9103 9443 10443 18443 19443 50051"
export BENCH_PORTS

# The Go modules that make lint and make test cover: all but the proof of concept's est module, kept as the SIG wrote
# it: its go.mod takes the EST server from a checkout beside the repository (../../globalsign-est), and its test does
# not build against the current EST code.
BENCH_GO_MODULES="bundle cai client e2e gen/go hwcheck hwcheck/vlekcheck platform rrp server"
export BENCH_GO_MODULES

bench_say() { printf '== %s\n' "$*"; }
bench_die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# sha256 FILE: the hex digest, with whichever tool the system has
# The time now, UTC, as the run records write it (vm-deleted.txt: when the VM was found gone).
bench_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

bench_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
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
