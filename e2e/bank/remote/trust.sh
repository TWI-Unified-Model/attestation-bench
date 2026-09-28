#!/usr/bin/env bash
# Demo Bank's trust zone, run as root on its own VM: Veraison (built here from the SIG's fork with the DER and
# SIGNER_INFO fixes, keys generated here), step-ca (the bank's workload CA), HashiCorp Vault, the Credential Authority
# and Secret Vault gateways (the RRPs), the TDX verifier and the EST server, the one port workloads reach. Secrets are
# generated on this machine and stay here; /opt/demobank/public holds what may leave it. Demo Bank is fictional.
#
#   trust.sh install                        packages, Go, Vault, Veraison (sources in /opt/demobank/src)
#   trust.sh setup                          env: INTERNAL_IP EXTERNAL_IP SNP_MEASUREMENTS TDX_MRTDS
#   trust.sh start | stop | status | restart SERVICE...
set -euo pipefail
D=/opt/demobank
V=/root/veraison-deployment
export PATH="/usr/local/go/bin:/root/go/bin:$D/bin:$PATH" HOME=/root GOTOOLCHAIN=local
export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT="$D/tls/root.crt"
GO_VERSION=1.27.0
VAULT_VERSION=2.1.1
HINT=payments.workload.demobank.example
LEDGER=https://ledger-db.demobank.example
FRAUD=https://fraud-api.demobank.example

install() {
  mkdir -p "$D/logs"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq jq sqlite3 protobuf-compiler make gcc libc6-dev gettext-base \
    openssl git jose netcat-openbsd unzip python3 >/dev/null   # gcc: Veraison's sqlite stores use cgo
  if [ ! -x /usr/local/go/bin/go ]; then
    curl -sfL -o /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
  fi
  if [ ! -x "$D/bin/vault" ]; then
    (cd /tmp
     curl -sfLO "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip"
     curl -sfLO "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS"
     grep " vault_${VAULT_VERSION}_linux_amd64.zip$" "vault_${VAULT_VERSION}_SHA256SUMS" | sha256sum -c - > "$D/logs/vault-sha256.txt"
     unzip -o -q "vault_${VAULT_VERSION}_linux_amd64.zip" -d "$D/bin" vault && rm -f vault_*)
  fi
  # the tools the Veraison bootstrap installs, then its own build and deployment with freshly generated keys
  go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28 >/dev/null 2>&1
  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2 >/dev/null 2>&1
  go install github.com/mitchellh/protoc-gen-go-json@latest >/dev/null 2>&1
  go install github.com/veraison/corim-store/cmd/corim-store@latest >/dev/null 2>&1
  if [ ! -x "$V/bin/vts-service" ]; then
    (cd "$D/src/veraison-services/deployments/native" && GOWORK=off ./deployment.sh quick-init-all > "$D/logs/veraison-build.log" 2>&1) \
      || { tail -30 "$D/logs/veraison-build.log"; exit 1; }
  fi
  sed -i 's#listen-addr: 0.0.0.0:#listen-addr: 127.0.0.1:#' "$V/config/services/config.yaml"
  grep -q "listen-addr: 127.0.0.1:50051" "$V/config/services/config.yaml" || \
    sed -i 's#^  server-addr: localhost:50051$#  server-addr: localhost:50051\n  listen-addr: 127.0.0.1:50051#' "$V/config/services/config.yaml"
  echo "installed: $(go version | cut -d' ' -f3), $("$D/bin/vault" version | cut -d' ' -f1-2), veraison $(ls "$V/bin" | tr '\n' ' ')"
}

setup() {
  : "${INTERNAL_IP:?}" "${EXTERNAL_IP:?}" "${SNP_MEASUREMENTS:?}" "${TDX_MRTDS:?}"
  mkdir -p "$D"/{tls,secrets,step,vault/data,config,public,logs}
  chmod 700 "$D/secrets" "$D/tls" "$D/step" "$D/vault" "$D/config"
  umask 077
  # the bank's TLS root for its own services; the EST server is the only one reachable from outside this machine
  cd "$D/tls"
  if [ ! -f root.crt ]; then
    step certificate create "Demo Bank trust-zone TLS root" root.crt root.key --profile root-ca --no-password --insecure --not-after 720h >/dev/null
    step certificate create trust.demobank.internal est-server.crt est-server.key --profile leaf --ca root.crt --ca-key root.key \
      --san trust.demobank.internal --san "$INTERNAL_IP" --san "$EXTERNAL_IP" --no-password --insecure --not-after 240h >/dev/null
    for s in ca-gateway vault-gateway tdx-verifier vault; do
      step certificate create localhost $s.crt $s.key --profile leaf --ca root.crt --ca-key root.key --san localhost \
        --san 127.0.0.1 --no-password --insecure --not-after 240h >/dev/null
    done
  fi
  # step-ca: the bank's workload CA; its policy admits workload names only
  export STEPPATH="$D/step"
  if [ ! -f "$STEPPATH/config/ca.json" ]; then
    openssl rand -hex 32 > "$D/secrets/step-ca-password"; openssl rand -hex 32 > "$D/secrets/provisioner-password"
    step ca init --deployment-type standalone --name "Demo Bank workload CA" --dns localhost --dns 127.0.0.1 \
      --address 127.0.0.1:9000 --provisioner tacra-ca-gateway --password-file "$D/secrets/step-ca-password" \
      --provisioner-password-file "$D/secrets/provisioner-password" > "$D/logs/step-ca-init.log" 2>&1
    step ca provisioner update tacra-ca-gateway --x509-default-dur=1h --x509-max-dur=24h --x509-min-dur=5m >> "$D/logs/step-ca-init.log" 2>&1
    python3 - "$STEPPATH/config/ca.json" "$D/secrets/provisioner.jwe" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
c["authority"]["policy"] = {"x509": {"allow": {"dns": ["*.workload.demobank.example"], "uri": ["demobank.example"]}}}
json.dump(c, open(sys.argv[1], "w"), indent=1)
p = [x for x in c["authority"]["provisioners"] if x["name"] == "tacra-ca-gateway"][0]
open(sys.argv[2], "w").write(p["encryptedKey"])
PY
    step crypto jwe decrypt --password-file "$D/secrets/provisioner-password" < "$D/secrets/provisioner.jwe" > "$D/secrets/ca-provisioner.jwk"
    rm "$D/secrets/provisioner.jwe"
  fi
  [ -f "$D/secrets/epoch.hex" ] || openssl rand -hex 32 > "$D/secrets/epoch.hex"
  cat > "$D/vault/config.hcl" <<EOF
storage "file" { path = "$D/vault/data" }
listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_cert_file = "$D/tls/vault.crt"
  tls_key_file  = "$D/tls/vault.key"
}
api_addr      = "https://127.0.0.1:8200"
disable_mlock = true
ui            = false
EOF
  D="$D" HINT="$HINT" LEDGER="$LEDGER" FRAUD="$FRAUD" V="$V" python3 - <<'PY'
import json, os
D, V, hint, ledger, fraud = (os.environ[k] for k in ("D", "V", "HINT", "LEDGER", "FRAUD"))
snp, tdx = os.environ["SNP_MEASUREMENTS"].split(), os.environ["TDX_MRTDS"].split()
veraison = {"url": "https://localhost:8443", "ca": f"{V}/certs/rootCA.crt"}
tdxv = {"url": "https://localhost:8453", "ca": f"{D}/tls/root.crt"}
common = {"verifiers": [dict(veraison, submods=["SEVSNP"]), dict(tdxv, submods=["TDX"])], "ear": {"max_age": 120, "skew": 5},
          "epoch_file": f"{D}/secrets/epoch.hex"}
ca = dict(common, rrp_id="https://ca.demobank.example", listen="127.0.0.1:9101",
          tls_cert=f"{D}/tls/ca-gateway.crt", tls_key=f"{D}/tls/ca-gateway.key",
          targets={ledger: {"credential_types": ["x509"], "freshness_kind": "present-nonce", "expires_in": 300,
                            "acceptable": ["ecdsa-p256-sha256"],
                            "identities": {hint: {"sans": [hint, "spiffe://demobank.example/payments"],
                                                  "measurements": snp + tdx, "validity": "1h"}}}},
          step_ca={"url": "https://127.0.0.1:9000", "root": f"{D}/step/certs/root_ca.crt", "provisioner": "tacra-ca-gateway",
                   "provisioner_key": f"{D}/secrets/ca-provisioner.jwk"})
vault = dict(common, rrp_id="https://vault.demobank.example", listen="127.0.0.1:9102",
             tls_cert=f"{D}/tls/vault-gateway.crt", tls_key=f"{D}/tls/vault-gateway.key",
             targets={fraud: {"credential_types": ["api-key"], "freshness_kind": "present-nonce", "expires_in": 300,
                              "acceptable": ["DHKEM(X25519,HKDF-SHA256)+HKDF-SHA256+AES-256-GCM",
                                             "DHKEM(P-256,HKDF-SHA256)+HKDF-SHA256+AES-256-GCM"],
                              "groups": {hint: {"secret_path": "demobank/fraud-api", "measurements": snp + tdx, "policy_version": "1"}}}},
             vault={"addr": "https://127.0.0.1:8200", "ca": f"{D}/tls/root.crt", "mount": "secret",
                    "token_file": f"{D}/secrets/vault-gateway.token"}, kem_keys=f"{D}/secrets/vault-kem.json")
est = {"tls": {"listen_address": "0.0.0.0:18443", "certificates": f"{D}/tls/est-server.crt", "private_key": f"{D}/tls/est-server.key"},
       "healthcheck_password": os.urandom(16).hex(), "timeout": 60, "rate_limit": 0, "log_file": f"{D}/logs/est.log",
       "tacra": {"veraison": veraison, "verifiers": {"tdx_guest": tdxv}, "acceptable_evidence": ["application/vnd.veraison.tsm-report+cbor"],
                 "ca_certs": f"{D}/step/certs/intermediate_ca.crt",
                 "rrps": {"ca": {"url": "https://127.0.0.1:9101", "ca": f"{D}/tls/root.crt", "rrp_id": ca["rrp_id"], "mode": "enroll"},
                          "vault": {"url": "https://127.0.0.1:9102", "ca": f"{D}/tls/root.crt", "rrp_id": vault["rrp_id"], "mode": "retrieve"}},
                 "targets": {ledger: "ca", fraud: "vault"}}}
tdxcfg = {"listen": "127.0.0.1:8453", "tls_cert": f"{D}/tls/tdx-verifier.crt", "tls_key": f"{D}/tls/tdx-verifier.key",
          "signing_key": f"{D}/secrets/tdx-verifier.jwk", "reference_mrtd": tdx}
for name, c in (("ca-gateway", ca), ("vault-gateway", vault), ("est-server", est), ("tdx-verifier", tdxcfg)):
    p = f"{D}/config/{name}.json"
    json.dump(c, open(p, "w"), indent=1); os.chmod(p, 0o600)
PY
  publish
  echo "setup done"
}

# what may leave this machine: trust anchors, the epoch marker (broadcast by design), the policy (no secrets)
publish() {
  umask 022
  mkdir -p "$D/public"
  cat "$D/step/certs/root_ca.crt" "$D/step/certs/intermediate_ca.crt" > "$D/public/workload-ca.pem"
  cp "$D/tls/root.crt" "$D/public/trust-tls-root.crt"
  cp "$D/secrets/epoch.hex" "$D/public/epoch.hex"
  python3 - "$D" <<'PY' > "$D/public/policy.json"
import json, sys
D = sys.argv[1]
out = {}
for n in ("ca-gateway", "vault-gateway"):
    c = json.load(open(f"{D}/config/{n}.json"))
    out[n] = {"rrp_id": c["rrp_id"], "targets": c["targets"], "ear": c["ear"], "verifiers": c["verifiers"]}
out["tdx-verifier"] = {"reference_mrtd": json.load(open(f"{D}/config/tdx-verifier.json"))["reference_mrtd"]}
print(json.dumps(out, indent=1))
PY
  chmod -R a+rX "$D/public"; chmod 755 "$D"
}

running() { [ -f "$D/logs/$1.pid" ] && kill -0 "$(cat "$D/logs/$1.pid")" 2>/dev/null; }
start_one() {
  local name="$1"; shift
  running "$name" && return 0
  nohup "$@" >> "$D/logs/$name.log" 2>&1 &
  echo $! > "$D/logs/$name.pid"
}
wait_port() { for _ in $(seq 1 240); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.25; done; echo "!! port $1 not up"; return 1; }

vault_init() {
  if ! { "$D/bin/vault" status -format=json 2>/dev/null || true; } | python3 -c 'import sys,json; sys.exit(0 if json.load(sys.stdin)["initialized"] else 1)'; then
    (umask 077; "$D/bin/vault" operator init -key-shares=1 -key-threshold=1 -format=json > "$D/secrets/vault-init.json")
  fi
  if { "$D/bin/vault" status 2>/dev/null || true; } | grep -q "Sealed *true"; then
    "$D/bin/vault" operator unseal "$(python3 -c "import json;print(json.load(open('$D/secrets/vault-init.json'))['unseal_keys_b64'][0])")" >/dev/null
  fi
  VAULT_TOKEN="$(python3 -c "import json;print(json.load(open('$D/secrets/vault-init.json'))['root_token'])")"
  export VAULT_TOKEN
  "$D/bin/vault" secrets list -format=json | grep -q '"secret/"' || "$D/bin/vault" secrets enable -path=secret kv-v2 >/dev/null
  if [ -f "$D/secrets/fraud-api-key" ]; then   # the partner's key, handed to the bank's administrator once
    "$D/bin/vault" kv put -mount=secret demobank/fraud-api type=api-key format=text value="$(tr -d '\n' < "$D/secrets/fraud-api-key")" >/dev/null
    rm -f "$D/secrets/fraud-api-key"
  fi
  printf 'path "secret/data/demobank/*" {\n  capabilities = ["read"]\n}\n' | "$D/bin/vault" policy write tacra-vault-gateway - >/dev/null
  [ -s "$D/secrets/vault-gateway.token" ] || (umask 077; "$D/bin/vault" token create -policy=tacra-vault-gateway -ttl=240h -field=token > "$D/secrets/vault-gateway.token")
  unset VAULT_TOKEN
}

start() {
  cd "$V"
  for s in vts provisioning verification management; do
    start_one "veraison-$s" "$V/bin/$s-service" --config="$V/config/services/config.yaml"
    [ "$s" = vts ] && sleep 2
  done
  wait_port 9443; wait_port 8443
  # AMD's ARK and the approved launches, as on the bench; the media type is the one VTS lists at start for sevsnp
  if ! grep -q success "$D/logs/corim-submit.json" 2>/dev/null; then
    curl -sS --cacert "$V/certs/rootCA.crt" -X POST \
      -H 'Content-Type: application/rim+cbor; profile="tag:amd.com,2024:snp-corim-profile"' \
      --data-binary @"$D/src/corim-milan.cbor" https://localhost:9443/endorsement-provisioning/v1/submit > "$D/logs/corim-submit.json"
    grep -q success "$D/logs/corim-submit.json" || { echo "!! CoRIM not accepted: $(cat "$D/logs/corim-submit.json")"; exit 1; }
  fi
  export STEPPATH="$D/step"
  start_one step-ca "$D/bin/step-ca" "$D/step/config/ca.json" --password-file "$D/secrets/step-ca-password"
  start_one vault "$D/bin/vault" server -config="$D/vault/config.hcl"
  wait_port 9000; wait_port 8200
  vault_init
  start_one tdx-verifier "$D/bin/tdx-verifier" -config "$D/config/tdx-verifier.json"; wait_port 8453
  start_one ca-gateway "$D/bin/ca-gateway" -config "$D/config/ca-gateway.json"
  start_one vault-gateway "$D/bin/vault-gateway" -config "$D/config/vault-gateway.json"
  wait_port 9101; wait_port 9102
  curl -sf --cacert "$D/tls/root.crt" https://127.0.0.1:9102/tacra/v1/origin-keys > "$D/public/origin-keys.json"
  chmod 644 "$D/public/origin-keys.json"
  start_one est-server "$D/bin/estserver" -config "$D/config/est-server.json"; wait_port 18443
  status
}

restart() {   # the named services read their configuration again
  local s
  for s in "$@"; do
    if running "$s"; then
      kill "$(cat "$D/logs/$s.pid")"
      for _ in $(seq 1 40); do running "$s" || break; sleep 0.25; done
    fi
    rm -f "$D/logs/$s.pid"
  done
  start
}

stop() {
  for s in est-server vault-gateway ca-gateway tdx-verifier vault step-ca veraison-management veraison-verification veraison-provisioning veraison-vts; do
    if running "$s"; then kill "$(cat "$D/logs/$s.pid")"; fi
    rm -f "$D/logs/$s.pid"
  done
}

status() {
  for s in veraison-vts veraison-provisioning veraison-verification veraison-management step-ca vault tdx-verifier ca-gateway vault-gateway est-server; do
    if running "$s"; then echo "$s running"; else echo "$s STOPPED"; fi
  done
  ss -ltnp | awk 'NR>1 {print $4}' | sort -u | tr '\n' ' '; echo
}

"$@"
