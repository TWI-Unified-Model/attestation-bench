#!/usr/bin/env bash
# The end-to-end run on this machine, with the bench's software stand-in TEE: no hardware, no cloud, no cost, and NO
# security (platform/simtee.go). It is the cloud runs' scenario (e2e/scripts/gcp-snp-e2e.sh) except where the
# workload runs: the workload (e2e-attester: the SIG's CAI with the SimTEE plug-in) and the CAS Client (caapi-est)
# run here, next to the bench, and reach the EST server on 127.0.0.1:18443 directly. For each of the 10 Targets the
# workload acquires its credential (an X.509 certificate from step-ca, or an API key from Vault) and presents it to the
# RATS-unaware Relying Party.
#
#   scripts/local-e2e.sh        (make demo)
#
# Refusal scenarios, one at a time, where every Target must be refused for the scenario's own reason:
#   SIM_DEBUG=1                 the stand-in reports a debuggable instance
#   SIM_LABEL="other workload"  the stand-in reports the launch measurement of another workload (not approved)
#
# The run ends with its verdict (scripts/verdict.py) and exits 1 unless the run came out as expected.
# RUNS_DIR: where run directories go (default BENCH_HOME/runs).
set -euo pipefail
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
B="$BENCH_HOME"
HERE="$BENCH_REPO"
RUNS_DIR="${RUNS_DIR:-$B/runs}"
SIM_DEBUG="${SIM_DEBUG:-}"
SIM_LABEL="${SIM_LABEL:-}"
MODEL="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('rats_model') or 'passport')" "$B/config/vault-gateway.json")"
# What the run must show (scripts/verdict.py): every Target admitted; or, in a refusal scenario, every Target refused,
# with the RRP's reason and, where the verifier refuses, the cause the stand-in's verifier found.
SCENARIO=""
EXPECT=(--expect admitted)
CONTRAINDICATED='not affirming: SIM is "contraindicated"'
if [ -n "$SIM_DEBUG" ]; then
  SCENARIO="$SCENARIO-debug"
  EXPECT=(--expect refused --reason "$CONTRAINDICATED" --cause "the instance is debuggable")
fi
if [ -n "$SIM_LABEL" ]; then
  SCENARIO="$SCENARIO-unapproved"
  EXPECT=(--expect refused --reason "$CONTRAINDICATED" --cause "matches no reference value")
fi
case "$SCENARIO" in
  "" | -debug | -unapproved) ;;
  *) bench_die "one refusal scenario at a time: SIM_DEBUG or SIM_LABEL" ;;
esac
OUT="$RUNS_DIR/$(date -u +%Y%m%dT%H%M%SZ)-local-sim-e2e-${MODEL}${SCENARIO}"
BIN="$(mktemp -d)"
CAS_PID=""
cleanup() { # the CAS Client and the programs built for the run: once the workload is done, and on any exit
  if [ -n "$CAS_PID" ]; then
    kill "$CAS_PID" 2>/dev/null || true
    wait "$CAS_PID" 2>/dev/null || true # reaped here, so bash reports no "Terminated"
    CAS_PID=""
  fi
  rm -rf "${BIN:?}"
}
trap cleanup EXIT
mkdir -p "$OUT/bench-logs"

echo "== bench"
"$HERE/e2e/scripts/bench.sh" status | tee "$OUT/bench-status.txt"
if grep -q stopped "$OUT/bench-status.txt"; then echo "!! start the bench first: make start"; exit 1; fi
if nc -z 127.0.0.1 50061 2>/dev/null; then echo "!! port 50061 (the CAS Client) is taken on this machine"; exit 1; fi
{ echo "attestation-bench $(git -C "$HERE" rev-parse --short=12 HEAD)$(git -C "$HERE" diff --quiet HEAD -- platform cai bundle rrp e2e/cmd || echo -dirty)"
  "$HERE/third_party/describe.sh" globalsign-est veraison-services go-gen-ref | grep -v -e '/src-fork ' -e '/src-der '
  "$HERE/e2e/scripts/veraison-build-info.sh"; } >"$OUT/code-revs.txt"
echo "$MODEL" >"$OUT/rats-model.txt"
echo "software stand-in TEE (platform.SimTEE): no hardware, no isolation, no security" >"$OUT/platform.txt"
for f in est-server ca-gateway vault-gateway rup tdx-verifier sim-verifier; do wc -l <"$B/$f.log" >"$OUT/bench-logs/.$f.start"; done
wc -l <"$VERAISON_DEPLOYMENT/logs/vts.log" >"$OUT/bench-logs/.vts.start"
wc -l <"$VERAISON_DEPLOYMENT/logs/verification.log" >"$OUT/bench-logs/.verification.start"

echo "== build the workload and the CAS Client"
(cd "$HERE/e2e" && go build -trimpath -o "$BIN/e2e-attester" ./cmd/e2e-attester && go build -trimpath -o "$BIN/caapi-est" ./cmd/caapi-est)
(cd "$BIN" && shasum -a 256 e2e-attester caapi-est) >"$OUT/binaries.sha256"

echo "== the workload's configuration (public material, and the path of the stand-in's key)"
curl -sf --cacert "$B/tls/root.crt" --cert "$B/tls/clients/operator.crt" --key "$B/tls/clients/operator.key" \
  https://127.0.0.1:9102/tacra/v1/origin-keys >"$BIN/origin-keys.json"
TEE=sim B="$B" BIN="$BIN" python3 "$HERE/e2e/scripts/guest_config.py"
measurement="$(tr -d '\n' <"$B/sim-measurement.hex")"
[ -z "$SIM_LABEL" ] || measurement="$(printf '%s' "$SIM_LABEL" | shasum -a 384 | cut -d' ' -f1)"
python3 - "$BIN/e2e-attester.json" "$B/secrets/sim-tee-ak.jwk" "$measurement" "${SIM_DEBUG:+1}" <<'PY'
import json, sys
p, key, m, debug = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1"
c = json.load(open(p))
c.update(sim_key_file=key, sim_measurement_hex=m, sim_debug=debug)
json.dump(c, open(p, "w"), indent=1)
PY
cp "$BIN/e2e-attester.json" "$OUT/e2e-attester.json"

echo "== the CAS Client (caapi-est, the conduit) on 127.0.0.1:50061"
"$BIN/caapi-est" -listen 127.0.0.1:50061 -est localhost:18443 -anchor "$B/tls/root.crt" >"$OUT/caapi-est.log" 2>&1 &
CAS_PID=$!
bench_wait_port 50061 || { echo "!! caapi-est did not start (see $OUT/caapi-est.log)"; exit 1; }

echo "== the workload: acquire, then present to the Relying Party"
NB="$(date -u +%s)"
"$BIN/e2e-attester" -config "$BIN/e2e-attester.json" -out "$OUT/results.json" 2>&1 | tee "$OUT/e2e-attester-stdout.txt"
NA="$(date -u +%s)"
echo "$NB $NA" >"$OUT/run-window.txt"
cleanup # the CAS Client stops before the run directory is sealed, so its log is complete

echo "== bench logs for the run"
for f in est-server ca-gateway vault-gateway rup tdx-verifier sim-verifier; do
  tail -n +"$(($(cat "$OUT/bench-logs/.$f.start") + 1))" "$B/$f.log" | grep -v "TLS handshake error" >"$OUT/bench-logs/$f.log" || true
done
tail -n +"$(($(cat "$OUT/bench-logs/.vts.start") + 1))" "$VERAISON_DEPLOYMENT/logs/vts.log" | grep -v DEBUG >"$OUT/bench-logs/veraison-vts.log" || true
tail -n +"$(($(cat "$OUT/bench-logs/.verification.start") + 1))" "$VERAISON_DEPLOYMENT/logs/verification.log" | grep -v DEBUG \
  >"$OUT/bench-logs/veraison-verification.log" || true
rm -f "$OUT"/bench-logs/.*.start
rc=0
python3 "$HERE/scripts/verdict.py" demo "$OUT" "${EXPECT[@]}" --out "$OUT/verdict.txt" || rc=$?
bench_seal "$OUT"
echo "== run directory: $OUT"
exit "$rc"
