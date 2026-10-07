#!/usr/bin/env bash
# The local TACRA test bench: Veraison (verification), step-ca (workload credentials), HashiCorp Vault (secrets),
# the Credential Authority and Secret Vault gateways (the RRPs), the EST server (the conduit) and an ordinary mTLS
# service (the RATS-unaware Relying Party). Keys, passwords and generated configuration live under BENCH_HOME
# (default ~/.attestation-bench; scripts/setup.sh creates it), outside git. Every listener is on 127.0.0.1.
#
#   e2e/scripts/bench.sh config    write the configuration of every service and the infrastructure's mutual TLS
#                                  (client certificates under the bench's TLS root, the verifiers' EAR keys as files,
#                                  Vault and Veraison requiring client certificates) from the bench's pack
#                                  (packs/tacra-bench) and the approved launches (trust/approved-launches.json), with
#                                  scripts/trustzone.py, the program the Demo Bank's trust zone uses too.
#                                  RATS_MODEL=background-check: the gateways ask the verifiers themselves;
#                                  OMIT_RRP_ID=1: the Credential Authorities bind no RRP identifier (#20)
#   e2e/scripts/bench.sh start|stop|status
set -euo pipefail
# BENCH_HOME (default ~/.attestation-bench) and VERAISON_DEPLOYMENT, the pinned tools on PATH: scripts/lib.sh
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"
B="$BENCH_HOME"
HERE="$BENCH_REPO"
EST="${EST_REPO:-$HERE/third_party/globalsign-est/src}"   # fetched by third_party/fetch.sh
BIN="$B/bin"
PACK="$HERE/packs/tacra-bench/pack.json"
export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT="$B/tls/root.crt"
# the operator's client certificate: Vault's listener requires one (N23)
export VAULT_CLIENT_CERT="$B/tls/clients/operator.crt" VAULT_CLIENT_KEY="$B/tls/clients/operator.key"

config() {
  mkdir -p "$B/config" "$BIN" "$B/tls/clients" "$B/gateways" "$B/secrets"
  [ -f "$B/epoch.hex" ] || (umask 077; openssl rand -hex 32 > "$B/epoch.hex")
  local flags=(--rats-model "${RATS_MODEL:-passport}")
  if [ "${OMIT_RRP_ID:-}" = 1 ]; then flags+=(--omit-rrp-id); fi
  python3 "$HERE/scripts/trustzone.py" --home "$B" --veraison "$VERAISON_DEPLOYMENT" --pack "$PACK" --simulated-tee "${flags[@]}"
  (cd "$HERE/rrp" && GOWORK=off go build -o "$BIN/ca-gateway" ./cmd/ca-gateway && GOWORK=off go build -o "$BIN/vault-gateway" ./cmd/vault-gateway \
    && GOWORK=off go build -o "$BIN/tdx-verifier" ./cmd/tdx-verifier && GOWORK=off go build -o "$BIN/sim-verifier" ./cmd/sim-verifier)
  (cd "$EST" && GOWORK=off go build -o "$BIN/estserver" ./cmd/estserver)
  (cd "$HERE/e2e" && GOWORK=off go build -o "$BIN/rup" ./cmd/rup)
  # the TDX verifier's EAR key, provisioned to the gateways as a file (its signing key is created if absent)
  "$BIN/tdx-verifier" -config "$B/config/tdx-verifier.json" -public-jwk >"$B/gateways/tdx-verifier.ear.jwk" 2>>"$B/tdx-verifier.log"
  "$BIN/sim-verifier" -config "$B/config/sim-verifier.json" -public-jwk >"$B/gateways/sim-verifier.ear.jwk" 2>>"$B/sim-verifier.log"
  echo "binaries in $BIN"
}

running() { [ -f "$B/$1.pid" ] && kill -0 "$(cat "$B/$1.pid")" 2>/dev/null; }

start_one() { # name command...
  local name="$1"; shift
  if running "$name"; then echo "$name already running ($(cat "$B/$name.pid"))"; return; fi
  # emptied, then appended to: the EST server also writes this file itself (log_file, O_APPEND); a plain ">" would
  # write its stderr from offset 0, over the start of its own log, and shift the e2e scripts' line-count windows
  : > "$B/$name.log"
  nohup "$@" >> "$B/$name.log" 2>&1 &
  echo $! > "$B/$name.pid"
  echo "$name started ($!)"
}

wait_port() { for _ in $(seq 1 120); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.25; done; echo "!! port $1 not up"; return 1; }

case "${1:-status}" in
  config) config ;;
  start)
    # every service stopped before: what they start with is recorded (make setup compares it later)
    none_running=yes
    for s in step-ca vault tdx-verifier sim-verifier ca-gateway ca-gateway-2 vault-gateway est-server rup; do
      if running "$s"; then none_running=; fi
    done
    "$HERE/e2e/scripts/veraison-local.sh" start
    start_one step-ca step-ca "$B/step/config/ca.json" --password-file "$B/secrets/step-ca-password"
    start_one vault vault server -config="$B/vault/config.hcl"
    wait_port 9000; wait_port 8200; wait_port 8443
    if { vault status 2>/dev/null || true; } | grep -q "Sealed *true"; then  # vault status exits 2 when sealed
      vault operator unseal "$(python3 -c "import json;print(json.load(open('$B/secrets/vault-init.json'))['unseal_keys_b64'][0])")" >/dev/null && echo "vault unsealed"
    fi
    start_one tdx-verifier "$BIN/tdx-verifier" -config "$B/config/tdx-verifier.json"
    start_one sim-verifier "$BIN/sim-verifier" -config "$B/config/sim-verifier.json"
    wait_port 8453; wait_port 8463
    start_one ca-gateway "$BIN/ca-gateway" -config "$B/config/ca-gateway.json"
    [ -f "$B/config/ca-gateway-2.json" ] && start_one ca-gateway-2 "$BIN/ca-gateway" -config "$B/config/ca-gateway-2.json"
    start_one vault-gateway "$BIN/vault-gateway" -config "$B/config/vault-gateway.json"
    wait_port 9101; wait_port 9102; [ -f "$B/config/ca-gateway-2.json" ] && wait_port 9103
    start_one est-server "$BIN/estserver" -config "$B/config/est-server.json"
    start_one rup "$BIN/rup" -listen 127.0.0.1:19443 -cert "$B/tls/rup.crt" -key "$B/tls/rup.key" \
      -client-ca "$B/workload-ca.pem" -allow payments.workload.tacra.example -api-key-file "$B/secrets/rup-api-key"
    wait_port 18443; wait_port 19443
    if [ -n "$none_running" ]; then bench_fingerprint >"$B/started.fingerprint"; fi ;;
  stop)
    for s in rup est-server vault-gateway ca-gateway-2 ca-gateway sim-verifier tdx-verifier vault step-ca; do
      if running "$s"; then pid="$(cat "$B/$s.pid")"; kill "$pid"; for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done; echo "$s stopped"; fi
      rm -f "$B/$s.pid"
    done
    rm -f "$B/started.fingerprint"
    "$HERE/e2e/scripts/veraison-local.sh" stop ;;
  status)
    "$HERE/e2e/scripts/veraison-local.sh" status
    for s in step-ca vault tdx-verifier sim-verifier ca-gateway ca-gateway-2 vault-gateway est-server rup; do
      if running "$s"; then echo "$s running ($(cat "$B/$s.pid"))"; else echo "$s stopped"; fi
    done ;;
  *) echo "usage: $0 config|start|stop|status" >&2; exit 2 ;;
esac
