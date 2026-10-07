#!/usr/bin/env bash
# The repository's unit tests: go test in every Go module of BENCH_GO_MODULES (scripts/lib.sh), and the Python
# scripts' tests (scripts/tests: the run verdicts, judged on the committed reference runs). Exits non-zero on any
# failure.
#
#   scripts/test.sh        (make test)
#
# TACRA_EST_IMPL, the impl/ directory of a github.com/nikolaichuk7/tacra-est checkout with its .venv, adds the check of
# the hpke-auth bundle against that reference implementation (bundle); without it the test is skipped and says so.
set -euo pipefail
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
cd "$BENCH_REPO"
bench_say "third-party sources: the Go modules build against them (third_party/fetch.sh)"
"$BENCH_REPO/third_party/fetch.sh"

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
bench_say "Python, scripts/tests"
if out="$(python3 -m unittest discover -s scripts/tests 2>&1)"; then
  printf '  ok    %-18s %s\n' scripts/tests "$(grep -E '^Ran [0-9]+ tests?' <<<"$out")"
else
  printf '  FAIL  scripts/tests\n'
  printf '%s\n' "$out" | sed 's/^/        /'
  failed="$failed scripts/tests"
fi
if [ -n "$failed" ]; then bench_die "tests failed in:$failed"; fi
echo "test: every Go module and the Python tests pass"
