#!/usr/bin/env bash
# Computes again the measurement of each SEV-SNP launch approved from its provider's published firmware (an entry of
# approved-launches.json with "firmware": AWS's, which AWS signs no endorsement of): downloads the binary, checks it is
# the one the entry pins (SHA-256), and runs the pinned sev-snp-measure on it with the entry's options. Prints a line
# per launch, ok or FAIL; exits 1 on any FAIL.
#
#   trust/firmware-check.sh [APPROVED]        (APPROVED: default trust/approved-launches.json)
#
# make trust-check runs it on the bench's approved launches, and the Demo Bank at start on the bank's.
set -euo pipefail
# shellcheck source=SCRIPTDIR/../scripts/lib.sh
. "$(cd "$(dirname "$0")/.." && pwd)/scripts/lib.sh"
approved="${1:-$BENCH_REPO/trust/approved-launches.json}"
bad=0
derived="$(python3 - "$approved" <<'PY'
import json, sys
for e in json.load(open(sys.argv[1]))["sev-snp"]:
    f = e.get("firmware")
    if f:
        tool, version, *args = f["measure"].split()
        print("|".join([e["measurement"], f["binary"], f["sha256"], version, " ".join(args)]))
PY
)"
while IFS='|' read -r m url sum version args; do
  [ -n "$m" ] || continue
  have="$("$BENCH_HOME/venv/bin/python3" -m pip show sev-snp-measure 2>/dev/null | sed -n 's/^Version: //p')"
  if [ "$have" != "$version" ]; then
    echo "FAIL sev-snp-measure $version is not in $BENCH_HOME/venv (found: ${have:-none}): make setup installs it" >&2
    bad=1
    continue
  fi
  tmp="$(mktemp -d)"
  if ! curl -sfL -m 120 -o "$tmp/ovmf.fd" "$url"; then
    echo "FAIL could not download $url" >&2
    bad=1
  elif [ "$(bench_sha256 "$tmp/ovmf.fd")" != "$sum" ]; then
    echo "FAIL $url is not the binary approved-launches.json pins (SHA-256 $sum)" >&2
    bad=1
  else
    # shellcheck disable=SC2086  # args: the tool's options, as approved-launches.json writes them
    got="$("$BENCH_HOME/venv/bin/sev-snp-measure" $args --ovmf "$tmp/ovmf.fd" 2>&1)"
    if [ "$got" = "$m" ]; then
      echo "ok   the approved launch ${m:0:16}... is the measurement of $url (sev-snp-measure $version $args)"
    else
      echo "FAIL $url measures ${got:0:96}, not the approved ${m:0:16}..." >&2
      bad=1
    fi
  fi
  rm -rf "${tmp:?}"
done <<<"$derived"
exit "$bad"
