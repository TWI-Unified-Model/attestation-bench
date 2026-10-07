#!/usr/bin/env bash
# The tests that need the running bench, and no hardware (make test-live):
#   - the EST server's wire format through the live server (e2e/scripts/est-wire-check.py);
#   - the Evidence of every committed attack run from 6 October 2026 on, appraised again by the live verifiers, with
#     the run's own records as the RRP's (rrpverify service): Veraison for SEV-SNP, which fetches AMD's CRL, and the
#     TDX verifier for TDX, which fetches Intel's collateral. Each run's honest Evidence must pass and each of its
#     changed bindings must fail, as when it ran. The runs of September bound their Evidence with the RRP identifier
#     before the Target, the order TACRA later reversed, so today's RRP refuses them all: they are left out.
# Fails, and never skips, when the bench is not up.
#
#   scripts/test-live.sh        (make test-live)
set -euo pipefail
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
cd "$BENCH_REPO"

bench_say "the running bench ($BENCH_HOME)"
bench_require_up
echo "  every service running"

failed=""
bench_say "the EST server's wire format, through the live server"
if python3 "$BENCH_REPO/e2e/scripts/est-wire-check.py" --home "$BENCH_HOME" | sed 's/^/  /'; then :; else
  failed="$failed est-wire-format"
fi

bench_say "the committed attack runs' Evidence, appraised again by the live verifiers"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp:?}"' EXIT
(cd hwcheck && GOWORK=off go build -o "$tmp/rrpverify" ./cmd/rrpverify)
read -r tdx_url tdx_ca < <(python3 -c 'import json, sys
v = json.load(open(sys.argv[1]))["tacra"]["verifiers"]["tdx"]
print(v["url"], v["ca"])' "$BENCH_HOME/config/est-server.json")
runs=0 checks=0
for d in hwcheck/evidence/*; do
  r="$(basename "$d")"
  case "$r" in *-gcp-sev-snp | *-aws-sev-snp | *-gcp-tdx) ;; *) continue ;; esac
  [ "${r:0:8}" -ge 20261006 ] || continue # the run directory begins with its date, YYYYMMDD
  read -r nb na <"$d/rrp-clock-window.txt"
  verifier=()
  case "$r" in *-gcp-tdx) verifier=(-url "$tdx_url" -submod TDX -ca "$tdx_ca") ;; esac
  if ! "$tmp/rrpverify" service -in "$d" -handles "$d/handles.json" -not-before "$nb" -not-after "$na" \
    -out "$tmp/$r.json" ${verifier[@]+"${verifier[@]}"} >"$tmp/$r.txt" 2>&1; then
    printf '  FAIL  %-30s %s\n' "$r" "$(tail -1 "$tmp/$r.txt")"
    failed="$failed $r"
    continue
  fi
  summary="$(tail -1 "$tmp/$r.txt" | sed -E 's/; written .*//')"
  if [[ "$summary" =~ ^([0-9]+)\ checks,\ 0\ not\ as\ expected$ ]] && [ "${BASH_REMATCH[1]}" -gt 0 ]; then
    printf '  ok    %-30s %s\n' "$r" "$summary"
    runs=$((runs + 1)) checks=$((checks + BASH_REMATCH[1]))
  else
    printf '  FAIL  %-30s %s\n' "$r" "$summary"
    { grep '^BAD' "$tmp/$r.txt" || true; } | head -5 | sed 's/^/        /'
    failed="$failed $r"
  fi
done
[ "$runs" -gt 0 ] || failed="$failed no-runs"
if [ -n "$failed" ]; then bench_die "live tests failed:$failed"; fi
echo "test-live: the EST wire format as expected; $runs committed runs appraised again, $checks checks as expected"
