#!/usr/bin/env bash
# The repository's unit tests: go test in every Go module of BENCH_GO_MODULES (scripts/lib.sh). Exits non-zero on
# any failure.
#
#   scripts/test.sh        (make test)
#
# TACRA_EST_IMPL, the impl/ directory of a github.com/nikolaichuk7/tacra-est checkout with its .venv, adds the check of
# the hpke-auth bundle against that reference implementation (bundle); without it the test is skipped and says so.
set -euo pipefail
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
cd "$BENCH_REPO"
failed=""
bench_say "go test, every module"
for m in $BENCH_GO_MODULES; do
  if out="$(cd "$m" && go test -count=1 ./... 2>&1)"; then
    printf '  ok    %-18s packages with tests: %2s, without: %2s\n' "$m" "$(grep -c '^ok' <<<"$out")" \
      "$(grep -c 'no test files' <<<"$out")"
  else
    printf '  FAIL  %s\n' "$m"
    grep -v -e '^ok' -e 'no test files' <<<"$out" | sed 's/^/        /'
    failed="$failed $m"
  fi
done
if [ -n "$failed" ]; then bench_die "tests failed in:$failed"; fi
echo "test: every module passes"
