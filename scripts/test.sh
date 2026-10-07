#!/usr/bin/env bash
# The repository's unit tests: go test in every Go module of BENCH_GO_MODULES (scripts/lib.sh); in each third-party
# component, the tests our patches add, run in the patched sources, and no others; and the Python scripts' tests
# (scripts/tests: the run verdicts, judged on the committed reference runs). Exits non-zero on any failure.
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
bench_say "our tests in the third-party sources: the test files our patches add, and no others"
for up in third_party/*/UPSTREAM; do
  c="$(basename "$(dirname "$up")")"
  src="third_party/$c/src"
  # Ours are the test files the pinned upstream commit (the sources' HEAD, third_party/fetch.sh) does not have, wherever
  # the series puts them. Upstream's tests are not run: some of them use mocks, as the EST fork's tests use its mock CA.
  ours=()
  while IFS= read -r f; do
    git -C "$src" cat-file -e "HEAD:$f" 2>/dev/null || ours+=("$f")
  done < <(git -C "$src" ls-files -- '*_test.go')
  if [ "${#ours[@]}" -eq 0 ]; then
    printf '  ok    %-18s no tests in its patches\n' "$c"
    continue
  fi
  ran=0 cfail=""
  for d in $(printf '%s\n' "${ours[@]}" | xargs -n1 dirname | sort -u); do
    names=()
    for f in "${ours[@]}"; do
      [ "$(dirname "$f")" = "$d" ] || continue
      while IFS= read -r t; do names+=("$t"); done < <(sed -nE 's/^func (Test[A-Za-z0-9_]*)\(.*/\1/p' "$src/$f")
    done
    pkg="./$d"
    [ "$d" = . ] && pkg=.
    # the package's test binary links no mock: a mock that upstream test code set up at start would run with ours
    if mocks="$(cd "$src" && GOWORK=off go list -deps -test "$pkg" | grep -i -E 'mock|fake|stub')"; then
      printf '  FAIL  %-18s %s: its test binary links %s\n' "$c" "$d" "$(tr '\n' ' ' <<<"$mocks")"
      cfail=1
      continue
    fi
    re="^($(IFS='|'; echo "${names[*]}"))\$"
    if out="$(cd "$src" && GOWORK=off go test -count=1 -v -run "$re" "$pkg" 2>&1)"; then
      missing=""
      for t in "${names[@]}"; do grep -q -- "^--- PASS: $t " <<<"$out" || missing="$missing $t"; done
      if [ -n "$missing" ]; then
        printf '  FAIL  %-18s %s: did not run:%s\n' "$c" "$d" "$missing"
        cfail=1
        continue
      fi
      ran=$((ran + ${#names[@]}))
    else
      printf '  FAIL  third_party/%s, %s\n' "$c" "$d"
      grep -E -- '^(--- FAIL|FAIL|ok)|Error|error' <<<"$out" | sed 's/^/        /'
      cfail=1
    fi
  done
  if [ -n "$cfail" ]; then
    failed="$failed third_party/$c"
  else
    printf '  ok    %-18s our tests: %2s, in %s file(s)\n' "$c" "$ran" "${#ours[@]}"
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
echo "test: every Go module, our tests in the third-party sources and the Python tests pass"
