#!/bin/bash
# Runs matrix_test.go in every variant checkout, on the pinned go-sev-guest and on v0.15.0; prints MX| lines.
set -u
MX=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$MX/harness/matrix.txt}
: > "$OUT"
for name in main flag der derflag roots; do
  d="$MX/$name"
  cp "$MX/harness/matrix_test.go" "$d/scheme/sevsnp/matrix_test.go"
  for gsg in pin v0.15.0; do
    ( cd "$d" || exit 1
      git checkout -q -- go.mod go.sum
      if [ "$gsg" = v0.15.0 ]; then go get github.com/google/go-sev-guest@v0.15.0 >/dev/null 2>&1 || { echo "MX|$name|$gsg|go get failed|||" ; exit 0; }; fi
      ver=$(go list -m -f '{{.Version}}' github.com/google/go-sev-guest)
      MX_VARIANT=$name MX_GSG="$ver" go test ./scheme/sevsnp/ -run '^Test_Matrix$' -count=1 -v 2>&1 | grep '^MX|' || echo "MX|$name|$ver|test did not run (build error?)|||"
      git checkout -q -- go.mod go.sum
    ) >> "$OUT"
  done
  rm -f "$d/scheme/sevsnp/matrix_test.go"
done
echo "rows: $(grep -c '^MX|' "$OUT")"
