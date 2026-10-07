#!/usr/bin/env bash
# The repository's unit tests: go test in every Go module of BENCH_GO_MODULES (scripts/lib.sh); in each third-party
# component, the tests of the Go packages our patches change, run in the patched sources; and the Python scripts'
# tests (scripts/tests: the run verdicts, judged on the committed reference runs). Exits non-zero on any failure.
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
bench_say "our patches' tests, in the third-party sources they change"
for up in third_party/*/UPSTREAM; do
  c="$(basename "$(dirname "$up")")"
  # the directories of the Go files the patch series changes, as package patterns of the patched sources (third_party/
  # <c>/src); they are tested outside the bench's Go workspace, with the component's own go.mod
  pkgs=()
  while IFS= read -r d; do pkgs+=("$d"); done < <(cat "third_party/$c/patches/"*.patch | awk '
    /^diff --git a\// { f = substr($3, 3); if (f !~ /\.go$/) next
      n = split(f, part, "/"); print (n == 1 ? "." : "./" substr(f, 1, length(f) - length(part[n]) - 1)) }' | sort -u)
  if [ "${#pkgs[@]}" -eq 0 ]; then
    printf '  ok    %-18s no Go code in its patches\n' "$c"
  elif out="$(cd "third_party/$c/src" && GOWORK=off go test -count=1 "${pkgs[@]}" 2>&1)"; then
    printf '  ok    %-18s packages with tests: %2s, without: %2s\n' "$c" "$(grep -c '^ok' <<<"$out")" \
      "$(grep -c 'no test files' <<<"$out")"
  else
    printf '  FAIL  third_party/%s\n' "$c"
    grep -v -e '^ok' -e 'no test files' <<<"$out" | sed 's/^/        /'
    failed="$failed third_party/$c"
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
echo "test: every Go module, our patches' tests and the Python tests pass"
