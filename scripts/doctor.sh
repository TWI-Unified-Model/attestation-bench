#!/usr/bin/env bash
# Checks that this machine can run the bench: the tools setup needs (with versions), the cloud tools the hardware runs
# need, free ports and disk space. For each missing tool it prints the install command for macOS (Homebrew) and for
# Debian or Ubuntu (apt). Exit status 0 when every required tool is present.
#
#   scripts/doctor.sh            (make doctor)
set -uo pipefail
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

missing=0
warn=0
ok() { printf '  ok       %-12s %s\n' "$1" "$2"; }
need() { printf '  MISSING  %-12s %s\n' "$1" "$2"; missing=$((missing + 1)); }
note() { printf '  warning  %-12s %s\n' "$1" "$2"; warn=$((warn + 1)); }

# version_ge A B: A >= B for dotted versions (no sort -V: macOS has none)
version_ge() {
  local IFS=. i a b
  read -r -a a <<<"$1"
  read -r -a b <<<"$2"
  for i in 0 1 2; do
    [ "${a[$i]:-0}" -gt "${b[$i]:-0}" ] && return 0
    [ "${a[$i]:-0}" -lt "${b[$i]:-0}" ] && return 1
  done
  return 0
}

hint() { # brew-package apt-package
  if [ "$BENCH_OS" = darwin ]; then echo "brew install $1"; else echo "sudo apt-get install -y $2"; fi
}

tool() { # command brew-package apt-package [what for]
  if command -v "$1" >/dev/null 2>&1; then ok "$1" "${4:-}"; else need "$1" "$(hint "$2" "$3")"; fi
}

echo "attestation-bench doctor: $BENCH_OS/$BENCH_ARCH, BENCH_HOME=$BENCH_HOME"
echo
echo "Required:"
if command -v go >/dev/null 2>&1; then
  gv="$(go env GOVERSION | sed 's/^go//')"
  if version_ge "$gv" "$GO_MIN"; then ok go "$gv (need $GO_MIN or later)"; else need go "$gv is older than $GO_MIN: https://go.dev/dl/"; fi
else
  need go "https://go.dev/dl/ (Go $GO_MIN or later)"
fi
if command -v python3 >/dev/null 2>&1; then
  pv="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
  if ! version_ge "$pv" 3.10; then
    need python3 "$pv is older than 3.10: $(hint python@3.12 python3)"
  elif ! python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then
    need python3 "$pv has no venv/ensurepip: $(hint python@3.12 python3-venv)"
  else
    ok python3 "$pv"
  fi
else
  need python3 "$(hint python@3.12 'python3 python3-venv')"
fi
if [ "$BENCH_OS" = darwin ] && ! xcode-select -p >/dev/null 2>&1; then
  need xcode-clt "xcode-select --install (git, make, the C compiler Veraison's SQLite stores need)"
else
  tool git git git
  tool make make make
  tool cc gcc gcc "C compiler (Veraison's SQLite stores use cgo)"
fi
tool curl curl curl
tool unzip unzip unzip
tool openssl openssl openssl
tool shasum perl perl "SHA-256 of every run's files"
tool jq jq jq
tool nc netcat netcat-openbsd "port checks"
tool sqlite3 sqlite sqlite3 "Veraison's stores"
tool protoc protobuf protobuf-compiler "Veraison's build"
tool envsubst gettext gettext-base "Veraison's deployment"
if [ "$BENCH_OS" = darwin ]; then
  tool gsort coreutils coreutils "GNU sort for Veraison's deployment"
elif ! sort --help 2>/dev/null | grep -q -- -V; then
  need sort "$(hint coreutils coreutils) (GNU sort)"
else
  ok sort "GNU sort"
fi

echo
echo "For hardware runs (make demo, attacks, redirect with PLATFORM=gcp-snp, gcp-tdx or aws-snp; not needed locally):"
for c in gcloud aws ssh; do
  if command -v "$c" >/dev/null 2>&1; then ok "$c" ""; else
    case "$c" in
      gcloud) note gcloud "https://cloud.google.com/sdk/docs/install (GCP SEV-SNP and TDX)" ;;
      aws) note aws "https://aws.amazon.com/cli/ (AWS SEV-SNP)" ;;
      ssh) note ssh "$(hint openssh openssh-client)" ;;
    esac
  fi
done

echo
echo "Ports (the trust zone listens on 127.0.0.1):"
busy=""
for p in $BENCH_PORTS; do nc -z 127.0.0.1 "$p" 2>/dev/null && busy="$busy $p"; done
if [ -z "$busy" ]; then
  ok ports "all free: $BENCH_PORTS"
elif [ -f "$BENCH_HOME/step-ca.pid" ] && kill -0 "$(cat "$BENCH_HOME/step-ca.pid")" 2>/dev/null; then
  ok ports "in use by this bench (running):$busy"
else
  note ports "in use by something else:$busy (make stop, or stop the other service; lsof -nP -iTCP:PORT -sTCP:LISTEN)"
fi

echo
avail_kb="$(df -Pk "$(dirname "$BENCH_HOME")" | awk 'NR==2 {print $4}')"
if [ "${avail_kb:-0}" -lt 8000000 ]; then note disk "$((avail_kb / 1024)) MB free; setup needs about 8 GB"; else ok disk "$((avail_kb / 1024 / 1024)) GB free"; fi

echo
if [ "$missing" -gt 0 ]; then
  echo "$missing required tool(s) missing: install them, then run make doctor again."
  exit 1
fi
if [ "$warn" -gt 0 ]; then echo "Ready for make setup ($warn warning(s) above)."; else echo "Ready for make setup."; fi
