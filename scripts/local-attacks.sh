#!/usr/bin/env bash
# The substitution suite on this machine, with the bench's software stand-in TEE (no hardware, no cloud; NO security:
# platform/simtee.go). It is the hardware check's scenario (hwcheck/scripts/gcp-snp-hwcheck.sh) with the stand-in in
# place of the guest: the RRP mints the Freshness Handles, hwrun produces Evidence for the five Freshness Kinds,
# Enrollment and Retrieval, and rrpverify plays the RRP. For each token it checks the honest Evidence, then one attack
# per changed input, each by the conduit, which can hand the RRP any token and any inputs:
#   the Target (substitution), the RRP identifier (redirection to another RRP), the CSR or CEKpub (key substitution),
#   the freshness element (replay or stale freshness), the attestation key (a key that is not the platform's),
#   the launch measurement (an unapproved launch), a timestamp an hour outside the window.
# Every attack must be refused for its own reason; a refusal that also refuses the honest Evidence proves nothing and
# is reported as inconclusive. It runs twice: in process (rrpverify verify) and through the bench's sim-verifier
# (rrpverify service), as an RRP asks it.
#
#   scripts/local-attacks.sh        (make attacks)
#
# RUNS_DIR: where run directories go (default BENCH_HOME/runs).
set -euo pipefail
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
B="$BENCH_HOME"
HW="$BENCH_REPO/hwcheck"
RUNS_DIR="${RUNS_DIR:-$B/runs}"
OUT="$RUNS_DIR/$(date -u +%Y%m%dT%H%M%SZ)-local-sim-attacks"
BIN="$(mktemp -d)"
trap 'rm -rf "${BIN:?}"' EXIT
mkdir -p "$OUT"
git -C "$BENCH_REPO" rev-parse --short=12 HEAD >"$OUT/code-rev.txt"
echo "software stand-in TEE (platform.SimTEE): no hardware, no isolation, no security" >"$OUT/platform.txt"
M="$(tr -d '[:space:]' <"$B/sim-measurement.hex")"

echo "== build hwrun and rrpverify"
(cd "$HW" && go build -trimpath -o "$BIN/hwrun" ./cmd/hwrun && go build -modfile=go.v015.mod -trimpath -o "$BIN/rrpverify" ./cmd/rrpverify)
(cd "$BIN" && shasum -a 256 hwrun rrpverify) >"$OUT/binaries.sha256"

echo "== the RRP mints the Freshness Handles; the stand-in produces the Evidence"
"$BIN/rrpverify" mint -out "$OUT/handles.json"
NB="$(date -u +%s)"
"$BIN/hwrun" -tee sim -sim-key "$B/secrets/sim-tee-ak.jwk" -sim-measurement "$M" -handles "$OUT/handles.json" \
  -out "$OUT" | tee "$OUT/hwrun-stdout.txt"
NA="$(date -u +%s)"
echo "$NB $NA" >"$OUT/rrp-clock-window.txt"

echo "== the RRP's checks, in process"
"$BIN/rrpverify" verify -in "$OUT" -handles "$OUT/handles.json" -sim-key "$B/gateways/sim-tee-ak.pub.jwk" \
  -sim-measurement "$M" -not-before "$NB" -not-after "$NA" -out "$OUT/rrpverify-sim.json" >"$OUT/rrpverify-sim.txt"
tail -1 "$OUT/rrpverify-sim.txt"

echo "== the same checks through the bench's sim-verifier (https://localhost:8463)"
"$BIN/rrpverify" service -in "$OUT" -handles "$OUT/handles.json" -url https://localhost:8463 -ca "$B/tls/root.crt" \
  -submod SIM -not-before "$NB" -not-after "$NA" -out "$OUT/rrpverify-service.json" >"$OUT/rrpverify-service.txt"
tail -1 "$OUT/rrpverify-service.txt"

bench_seal "$OUT"
echo "== run directory: $OUT"
if grep -q ' 0 not as expected' "$OUT/rrpverify-sim.txt" && grep -q ' 0 not as expected' "$OUT/rrpverify-service.txt"; then
  echo "every attack refused for its own reason, every honest check passed"
else
  echo "!! some checks were not as expected: see rrpverify-sim.txt and rrpverify-service.txt" >&2
  exit 1
fi
