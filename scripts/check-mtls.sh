#!/usr/bin/env bash
# Mutual TLS between the running bench's components (tacra-est requirement N23), on this machine, no hardware: for every
# channel, the right caller is admitted at TLS 1.3, and an unauthenticated caller, a caller in the wrong role and
# TLS 1.2 are refused. Writes a run directory with the results and what was tested.
#
#   scripts/check-mtls.sh        (make check-mtls)
#
# RUNS_DIR: where run directories go (default BENCH_HOME/runs).
set -euo pipefail
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
RUNS_DIR="${RUNS_DIR:-$BENCH_HOME/runs}"
OUT="$RUNS_DIR/$(date -u +%Y%m%dT%H%M%SZ)-bench-mtls"
mkdir -p "$OUT"
git -C "$BENCH_REPO" rev-parse --short=12 HEAD >"$OUT/code-rev.txt"
"$BENCH_REPO/e2e/scripts/veraison-build-info.sh" >"$OUT/veraison-build.txt"
python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("rats_model") or "passport")' \
  "$BENCH_HOME/config/vault-gateway.json" >"$OUT/rats-model.txt"
if python3 "$BENCH_REPO/e2e/scripts/bench-mtls-check.py" "$OUT/mtls.json" >"$OUT/run.log" 2>&1; then rc=0; else rc=$?; fi
tail -1 "$OUT/run.log"
echo "run directory: $OUT"
exit "$rc"
