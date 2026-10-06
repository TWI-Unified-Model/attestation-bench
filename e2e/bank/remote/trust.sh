#!/usr/bin/env bash
# Demo Bank's trust zone, run as root on its own VM: Veraison (built here from the bench's pinned sources with our
# patches, keys generated here), step-ca (the bank's workload CA), HashiCorp Vault, the Credential Authority and Secret
# Vault gateways (the RRPs), the TDX verifier and the EST server, the one port workloads reach. Its configuration is
# written by the bench's own program (scripts/trustzone.py, with packs/demo-bank and trust/), so mutual TLS between
# the components (N23), the verifiers' EAR keys as files (N24) and the signed container are as on the bench, in the
# same layout under /opt/demobank. Secrets are generated on this machine and stay here; /opt/demobank/public holds
# what may leave it. Demo Bank is fictional.
#
#   trust.sh install        packages, Go, Vault, the Python packages, Veraison (versions: versions.env)
#   trust.sh setup          env: INTERNAL_IP EXTERNAL_IP [RATS_MODEL]: TLS, the workload CA, the configuration
#   trust.sh config         the configuration again, e.g. after approve [RATS_MODEL]
#   trust.sh start | stop | status | restart SERVICE...
set -euo pipefail
D=/opt/demobank
V=/root/veraison-deployment
# shellcheck source=SCRIPTDIR/../../../scripts/versions.env
. "$D/versions.env"
export PATH="/usr/local/go/bin:/root/go/bin:$D/bin:$PATH" HOME=/root GOTOOLCHAIN=local GOWORK=off
# the operator's client certificate: Vault's listener requires one (N23)
export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT="$D/tls/root.crt" \
  VAULT_CLIENT_CERT="$D/tls/clients/operator.crt" VAULT_CLIENT_KEY="$D/tls/clients/operator.key"

install() {
  mkdir -p "$D/logs"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq jq sqlite3 protobuf-compiler make gcc libc6-dev gettext-base \
    openssl git jose netcat-openbsd unzip python3 python3-venv >/dev/null   # gcc: Veraison's sqlite stores use cgo
  if [ "$(/usr/local/go/bin/go env GOVERSION 2>/dev/null || true)" != "go$GO_VM_VERSION" ]; then
    curl -sfL -o /tmp/go.tgz "https://go.dev/dl/go${GO_VM_VERSION}.linux-amd64.tar.gz"
    echo "$GO_VM_SHA256_linux_amd64  /tmp/go.tgz" | sha256sum -c - >/dev/null
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
  fi
  if [ ! -x "$D/bin/vault" ]; then
    curl -sfL -o /tmp/vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip"
    echo "$VAULT_SHA256_linux_amd64  /tmp/vault.zip" | sha256sum -c - > "$D/logs/vault-sha256.txt"
    unzip -o -q /tmp/vault.zip -d "$D/bin" vault && rm /tmp/vault.zip
  fi
  # the bench's Python packages (requirements.txt), for scripts/trustzone.py
  [ -x "$D/venv/bin/python3" ] || python3 -m venv "$D/venv"
  "$D/venv/bin/pip" install -q --disable-pip-version-check -r "$D/requirements.txt"
  # the protoc plug-ins Veraison's build runs, at the bench's pins; then its build and deployment with fresh keys, in
  # the steps of its quick-init-all, each skipped when done: a deployment that stopped half-way is finished
  go install "$PROTOC_GEN_GO" && go install "$PROTOC_GEN_GO_GRPC" && go install "$PROTOC_GEN_GO_JSON"
  [ -x "$V/bin/vts-service" ] || { veraison_step build; veraison_step deploy; }
  [ -s "$V/certs/rootCA.crt" ] || veraison_step init-certs localhost
  [ -s "$V/signing/skey.jwk" ] || veraison_step init-signing-keys   # jose
  [ -x "$V/bin/corim-store" ] || veraison_step init-clients
  [ -s "$V/stores/po-store.sql" ] || veraison_step init-stores
  sed -i 's#listen-addr: 0.0.0.0:#listen-addr: 127.0.0.1:#' "$V/config/services/config.yaml"
  grep -q "listen-addr: 127.0.0.1:50051" "$V/config/services/config.yaml" || \
    sed -i 's#^  server-addr: localhost:50051$#  server-addr: localhost:50051\n  listen-addr: 127.0.0.1:50051#' "$V/config/services/config.yaml"
  echo "installed: $(go version | cut -d' ' -f3), $("$D/bin/vault" version | cut -d' ' -f1-2)," \
    "$("$D/venv/bin/python3" -c 'from importlib.metadata import version as v; print("cryptography", v("cryptography"), "cbor2", v("cbor2"))')," \
    "veraison $(ls "$V/bin" | tr '\n' ' ')"
}

veraison_step() { # one step of Veraison's native deployment, logged
  (cd "$D/src/veraison-services/deployments/native" && ./deployment.sh "$@" >> "$D/logs/veraison-build.log" 2>&1) \
    || { tail -30 "$D/logs/veraison-build.log"; exit 1; }
}

setup() {
  : "${INTERNAL_IP:?}" "${EXTERNAL_IP:?}"
  mkdir -p "$D"/{tls/clients,secrets,gateways,step,vault/data,config,public,logs}
  chmod 700 "$D/secrets" "$D/gateways" "$D/tls" "$D/step" "$D/vault" "$D/config"
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
  # step-ca: the bank's workload CA; its policy admits the workload names of packs/demo-bank only
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
    step crypto jwe decrypt --password-file "$D/secrets/provisioner-password" < "$D/secrets/provisioner.jwe" > "$D/gateways/ca-provisioner.jwk"
    rm "$D/secrets/provisioner.jwe"
  fi
  [ -f "$D/epoch.hex" ] || openssl rand -hex 32 > "$D/epoch.hex"
  config
  echo "setup done"
}

# The configuration of every service, written as on the bench (scripts/trustzone.py: packs/demo-bank and the approved
# launches), then the TDX verifier's EAR key as a file for the gateways (N24; its signing key is made if absent).
config() {
  "$D/venv/bin/python3" "$D/scripts/trustzone.py" --home "$D" --veraison "$V" --pack "$D/packs/demo-bank/pack.json" \
    --approved "$D/trust/approved-launches.json" --corim "$D/trust/veraison-corim-milan.cbor" --logs "$D/logs" \
    --est-listen 0.0.0.0:18443 --rats-model "${RATS_MODEL:-passport}"
  "$D/bin/tdx-verifier" -config "$D/config/tdx-verifier.json" -public-jwk > "$D/gateways/tdx-verifier.ear.jwk"
  publish
}

# what may leave this machine: trust anchors, the epoch marker (broadcast by design), the policy (no secrets)
publish() {
  umask 022
  mkdir -p "$D/public"
  cat "$D/step/certs/root_ca.crt" "$D/step/certs/intermediate_ca.crt" > "$D/public/workload-ca.pem"
  cp "$D/step/certs/intermediate_ca.crt" "$D/public/workload-ca-intermediate.crt"
  cp "$D/tls/root.crt" "$D/public/trust-tls-root.crt"
  cp "$D/epoch.hex" "$D/public/epoch.hex"
  python3 - "$D" <<'PY' > "$D/public/policy.json"
import json, sys
D = sys.argv[1]
out = {}
for n in ("ca-gateway", "vault-gateway"):
    c = json.load(open(f"{D}/config/{n}.json"))
    out[n] = {k: c[k] for k in ("rrp_id", "rats_model", "targets", "ear", "verifiers", "client_ca", "clients")}
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

# the secret the Vault releases: the path of packs/demo-bank's one Secret Vault Target
secret_path() {
  python3 -c 'import json,sys; print([t["secret"]["path"] for t in json.load(open(sys.argv[1]))["targets"] if "secret" in t][0])' \
    "$D/packs/demo-bank/pack.json"
}

vault_init() {
  if ! { "$D/bin/vault" status -format=json 2>/dev/null || true; } | python3 -c 'import sys,json; sys.exit(0 if json.load(sys.stdin)["initialized"] else 1)'; then
    (umask 077; "$D/bin/vault" operator init -key-shares=1 -key-threshold=1 -format=json > "$D/secrets/vault-init.json")
  fi
  if { "$D/bin/vault" status 2>/dev/null || true; } | grep -q "Sealed *true"; then
    "$D/bin/vault" operator unseal "$(python3 -c "import json;print(json.load(open('$D/secrets/vault-init.json'))['unseal_keys_b64'][0])")" >/dev/null
  fi
  VAULT_TOKEN="$(python3 -c "import json;print(json.load(open('$D/secrets/vault-init.json'))['root_token'])")"
  export VAULT_TOKEN
  local path; path="$(secret_path)"
  "$D/bin/vault" secrets list -format=json | grep -q '"secret/"' || "$D/bin/vault" secrets enable -path=secret kv-v2 >/dev/null
  if [ -f "$D/secrets/fraud-api-key" ]; then   # the partner's key, handed to the bank's administrator once
    "$D/bin/vault" kv put -mount=secret "$path" type=api-key format=text value="$(tr -d '\n' < "$D/secrets/fraud-api-key")" >/dev/null
    rm -f "$D/secrets/fraud-api-key"
  fi
  # the gateway's token reads that one secret
  printf 'path "secret/data/%s" {\n  capabilities = ["read"]\n}\n' "$path" | "$D/bin/vault" policy write tacra-vault-gateway - >/dev/null
  [ -s "$D/gateways/vault-gateway.token" ] || (umask 077; "$D/bin/vault" token create -policy=tacra-vault-gateway -ttl=240h -field=token > "$D/gateways/vault-gateway.token")
  unset VAULT_TOKEN
}

start() {
  cd "$V"
  local s
  for s in vts provisioning verification management; do
    start_one "veraison-$s" "$V/bin/$s-service" --config="$V/config/services/config.yaml"
    if [ "$s" = vts ]; then wait_port 50051; fi
  done
  wait_port 9443; wait_port 8443
  # AMD's ARK and the approved SEV-SNP launches (trust/veraison-corim-milan.cbor), as on the bench; the media type is
  # the one VTS lists at start for sevsnp; retried while the provisioning service's connection to VTS comes up
  if ! grep -q success "$D/logs/corim-submit.json" 2>/dev/null; then
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      curl -sS --cacert "$V/certs/rootCA.crt" -X POST \
        -H 'Content-Type: application/rim+cbor; profile="tag:amd.com,2024:snp-corim-profile"' \
        --data-binary @"$D/trust/veraison-corim-milan.cbor" https://localhost:9443/endorsement-provisioning/v1/submit \
        > "$D/logs/corim-submit.json" || true
      grep -q success "$D/logs/corim-submit.json" && break
      grep -q Unavailable "$D/logs/corim-submit.json" || break
      sleep 3
    done
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
  # the Vault's public keys: its KEM keys and the signed container's signature key
  curl -sf --cacert "$D/tls/root.crt" --cert "$D/tls/clients/operator.crt" --key "$D/tls/clients/operator.key" \
    https://127.0.0.1:9102/tacra/v1/origin-keys > "$D/public/origin-keys.json"
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
  local s
  for s in est-server vault-gateway ca-gateway tdx-verifier vault step-ca veraison-management veraison-verification veraison-provisioning veraison-vts; do
    if running "$s"; then kill "$(cat "$D/logs/$s.pid")"; fi
    rm -f "$D/logs/$s.pid"
  done
}

status() {
  local s
  for s in veraison-vts veraison-provisioning veraison-verification veraison-management step-ca vault tdx-verifier ca-gateway vault-gateway est-server; do
    if running "$s"; then echo "$s running"; else echo "$s STOPPED"; fi
  done
  ss -ltnp | awk 'NR>1 {print $4}' | sort -u | tr '\n' ' '; echo
}

"$@"
