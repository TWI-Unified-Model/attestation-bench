#!/usr/bin/env bash
# The local TACRA test bench: Veraison (verification), step-ca (workload credentials), HashiCorp Vault (secrets),
# the Credential Authority and Secret Vault gateways (the RRPs), the EST server (the conduit) and an ordinary mTLS
# service (the RATS-unaware Relying Party). Keys, passwords and
# generated configuration live under ~/tacra-bench, outside git. Every listener is on 127.0.0.1.
#
#   e2e/scripts/bench.sh config    write the gateway and EST server configuration (measurements from MEASUREMENTS)
#   e2e/scripts/bench.sh start|stop|status
#
# MEASUREMENTS: space-separated hex launch measurements the policy admits (GCP and AWS SEV-SNP launches by default).
set -euo pipefail
B="${TACRA_BENCH:-$HOME/tacra-bench}"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
EST="${EST_REPO:-$HOME/dev/globalsign-est}"
BIN="$B/bin"
MEASUREMENTS="${MEASUREMENTS:-ccdc5cf01ba25526bd65503d95931b787b4385a3277cfe4448addf9c3e894948ae8cf7b099620e3e22717de2fb5d26fa 7a89cceaaba0bbdddc4f775acca3ef15d1f9bf8abccdc6115cfad7fb8eae113df3ee0bb50efa34db9c53ae065b1dc766}"
# MRTDs of the GCP TDX launches the TDX verifier admits and the RRPs' policy names
TDX_MRTDS="${TDX_MRTDS:-c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5}"
export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT="$B/tls/root.crt"

config() {
  mkdir -p "$B/config" "$BIN"
  [ -f "$B/epoch.hex" ] || (umask 077; openssl rand -hex 32 > "$B/epoch.hex")
  B="$B" MEASUREMENTS="$MEASUREMENTS" TDX_MRTDS="$TDX_MRTDS" python3 - <<'PY'
import json, os
B = os.environ["B"]; tdx = os.environ["TDX_MRTDS"].split(); meas = os.environ["MEASUREMENTS"].split() + tdx
hint = "payments.workload.tacra.example"
kinds = {"nonce": "present-nonce", "epoch": "present-epoch", "lepoch": "absent-epoch", "time": "absent-timestamp", "none": "absent-none"}
def target(kind, extra):
    t = {"credential_types": ["x509", "api-key"], "freshness_kind": kind}
    if kind in ("present-nonce", "present-epoch"): t["expires_in"] = 300
    if kind == "absent-timestamp": t.update(max_age=120, clock_skew=5)
    t.update(extra); return t
veraison = {"url": "https://localhost:8443", "ca": os.path.expanduser("~/veraison-deployment/certs/rootCA.crt")}
tdxv = {"url": "https://localhost:8453", "ca": f"{B}/tls/root.crt"}
common = {"verifiers": [dict(veraison, submods=["SEVSNP"]), dict(tdxv, submods=["TDX"])],
          "ear": {"max_age": 120, "skew": 5}, "epoch_file": f"{B}/epoch.hex"}
ca = dict(common, rrp_id="https://ca1.tacra.example", listen="127.0.0.1:9101",
          tls_cert=f"{B}/tls/ca-gateway.crt", tls_key=f"{B}/tls/ca-gateway.key",
          targets={f"https://db-{k}.tacra.example": target(v, {"acceptable": ["ecdsa-p256-sha256"],
                   "identities": {hint: {"sans": [hint, "spiffe://tacra.example/payments"], "measurements": meas, "validity": "1h"}}})
                   for k, v in kinds.items()},
          step_ca={"url": "https://127.0.0.1:9000", "root": f"{B}/step/certs/root_ca.crt", "provisioner": "tacra-ca-gateway",
                   "provisioner_key": f"{B}/gateways/ca-provisioner.jwk"})
vault = dict(common, rrp_id="https://vault1.tacra.example", listen="127.0.0.1:9102",
             tls_cert=f"{B}/tls/vault-gateway.crt", tls_key=f"{B}/tls/vault-gateway.key",
             targets={f"https://ledger-{k}.tacra.example": target(v, {"acceptable": ["DHKEM(X25519,HKDF-SHA256)+HKDF-SHA256+AES-256-GCM",
                      "DHKEM(P-256,HKDF-SHA256)+HKDF-SHA256+AES-256-GCM"],
                      "groups": {hint: {"secret_path": "tacra/payments", "measurements": meas, "policy_version": "1"}}})
                      for k, v in kinds.items()},
             vault={"addr": "https://127.0.0.1:8200", "ca": f"{B}/tls/root.crt", "mount": "secret",
                    "token_file": f"{B}/gateways/vault-gateway.token"}, kem_keys=f"{B}/gateways/vault-kem.json")
targets = {f"https://db-{k}.tacra.example": "ca" for k in kinds}
targets.update({f"https://ledger-{k}.tacra.example": "vault" for k in kinds})
est = {"tls": {"listen_address": "127.0.0.1:18443", "certificates": f"{B}/tls/est-server.crt", "private_key": f"{B}/tls/est-server.key"},
       "healthcheck_password": os.urandom(16).hex(), "timeout": 60, "rate_limit": 0, "log_file": f"{B}/est-server.log",
       "tacra": {"veraison": veraison, "verifiers": {"tdx_guest": tdxv},
                 "acceptable_evidence": ["application/vnd.veraison.tsm-report+cbor"],
                 "ca_certs": f"{B}/step/certs/intermediate_ca.crt",
                 "rrps": {"ca": {"url": "https://127.0.0.1:9101", "ca": f"{B}/tls/root.crt", "rrp_id": ca["rrp_id"], "mode": "enroll"},
                          "vault": {"url": "https://127.0.0.1:9102", "ca": f"{B}/tls/root.crt", "rrp_id": vault["rrp_id"], "mode": "retrieve"}},
                 "targets": targets}}
tdxcfg = {"listen": "127.0.0.1:8453", "tls_cert": f"{B}/tls/tdx-verifier.crt", "tls_key": f"{B}/tls/tdx-verifier.key",
          "signing_key": f"{B}/secrets/tdx-verifier.jwk", "reference_mrtd": tdx}
for name, c in (("ca-gateway", ca), ("vault-gateway", vault), ("est-server", est), ("tdx-verifier", tdxcfg)):
    p = f"{B}/config/{name}.json"
    with open(p, "w") as f: json.dump(c, f, indent=1)
    os.chmod(p, 0o600)
print("configuration written to", f"{B}/config")
PY
  (cd "$HERE/rrp" && GOWORK=off go build -o "$BIN/ca-gateway" ./cmd/ca-gateway && GOWORK=off go build -o "$BIN/vault-gateway" ./cmd/vault-gateway \
    && GOWORK=off go build -o "$BIN/tdx-verifier" ./cmd/tdx-verifier)
  (cd "$EST" && GOWORK=off go build -o "$BIN/estserver" ./cmd/estserver)
  (cd "$HERE/e2e" && GOWORK=off go build -o "$BIN/rup" ./cmd/rup)
  echo "binaries in $BIN"
}

running() { [ -f "$B/$1.pid" ] && kill -0 "$(cat "$B/$1.pid")" 2>/dev/null; }

start_one() { # name command...
  local name="$1"; shift
  if running "$name"; then echo "$name already running ($(cat "$B/$name.pid"))"; return; fi
  nohup "$@" > "$B/$name.log" 2>&1 &
  echo $! > "$B/$name.pid"
  echo "$name started ($!)"
}

wait_port() { for _ in $(seq 1 120); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.25; done; echo "!! port $1 not up"; return 1; }

case "${1:-status}" in
  config) config ;;
  start)
    "$HERE/e2e/scripts/veraison-local.sh" start
    start_one step-ca "$HOME/go/bin/step-ca" "$B/step/config/ca.json" --password-file "$B/secrets/step-ca-password"
    start_one vault vault server -config="$B/vault/config.hcl"
    wait_port 9000; wait_port 8200; wait_port 8443
    if { vault status 2>/dev/null || true; } | grep -q "Sealed *true"; then  # vault status exits 2 when sealed
      vault operator unseal "$(python3 -c "import json;print(json.load(open('$B/secrets/vault-init.json'))['unseal_keys_b64'][0])")" >/dev/null && echo "vault unsealed"
    fi
    start_one tdx-verifier "$BIN/tdx-verifier" -config "$B/config/tdx-verifier.json"
    wait_port 8453
    start_one ca-gateway "$BIN/ca-gateway" -config "$B/config/ca-gateway.json"
    start_one vault-gateway "$BIN/vault-gateway" -config "$B/config/vault-gateway.json"
    wait_port 9101; wait_port 9102
    start_one est-server "$BIN/estserver" -config "$B/config/est-server.json"
    start_one rup "$BIN/rup" -listen 127.0.0.1:19443 -cert "$B/tls/rup.crt" -key "$B/tls/rup.key" \
      -client-ca "$B/workload-ca.pem" -allow payments.workload.tacra.example -api-key-file "$B/secrets/rup-api-key"
    wait_port 18443; wait_port 19443 ;;
  stop)
    for s in rup est-server vault-gateway ca-gateway tdx-verifier vault step-ca; do
      if running "$s"; then pid="$(cat "$B/$s.pid")"; kill "$pid"; for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done; echo "$s stopped"; fi
      rm -f "$B/$s.pid"
    done
    "$HERE/e2e/scripts/veraison-local.sh" stop ;;
  status)
    "$HERE/e2e/scripts/veraison-local.sh" status
    for s in step-ca vault tdx-verifier ca-gateway vault-gateway est-server rup; do
      if running "$s"; then echo "$s running ($(cat "$B/$s.pid"))"; else echo "$s stopped"; fi
    done ;;
  *) echo "usage: $0 config|start|stop|status" >&2; exit 2 ;;
esac
