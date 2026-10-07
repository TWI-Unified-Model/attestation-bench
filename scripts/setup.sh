#!/usr/bin/env bash
# Sets the bench up from zero in BENCH_HOME (default ~/.attestation-bench) and starts it. It can run again at any time:
# each step keeps what already exists and does only what is missing, so a second run after a failure, an update or a
# reboot completes the bench rather than replacing it.
#
#   scripts/setup.sh        (make setup)
#
# Steps:
#  1. directories, Python environment (scripts/requirements.txt);
#  2. pinned tools: step, step-ca, Vault, protoc plug-ins (scripts/versions.env);
#  3. the third-party sources (third_party/fetch.sh);
#  4. the bench's TLS root and service certificates;
#  5. step-ca, the workload CA;
#  6. Veraison, the SEV-SNP Verifier, with fresh keys;
#  7. the bench's configuration and programs (e2e/scripts/bench.sh config);
#  8. HashiCorp Vault, initialised, with the ledger's API key;
#  9. Veraison started and provisioned with AMD's Milan trust anchor and the approved launches;
# 10. everything started (e2e/scripts/bench.sh start).
#
# Network: proxy.golang.org, pypi.org, github.com and releases.hashicorp.com. Every key and password is generated on
# this machine and stays in BENCH_HOME.
set -euo pipefail
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
B="$BENCH_HOME"
V="$VERAISON_DEPLOYMENT"
LOG="$B/logs/setup.log"
BENCH="$BENCH_REPO/e2e/scripts/bench.sh"

fail() { echo "error: $*; the details are in $LOG" >&2; tail -20 "$LOG" >&2 || true; exit 1; }
quiet() { "$@" >>"$LOG" 2>&1; }

dirs_and_python() {
  bench_say "1/10 directories and the Python environment in $B"
  mkdir -p "$B/bin" "$B/tools/bin" "$B/logs" "$B/config" "$B/gateways" "$B/secrets" "$B/tls/clients" "$B/step" "$B/vault/data"
  chmod 700 "$B/secrets" "$B/tls" "$B/step" "$B/vault" "$B/config" "$B/gateways"
  echo "# setup $(date -u +%FT%TZ)" >>"$LOG"
  if [ ! -x "$B/venv/bin/python3" ]; then quiet python3 -m venv "$B/venv" || fail "python3 -m venv"; fi
  quiet "$B/venv/bin/python3" -m pip install --disable-pip-version-check -r "$BENCH_REPO/scripts/requirements.txt" \
    || fail "pip install -r scripts/requirements.txt"
  echo "  venv: $("$B/venv/bin/python3" -c 'import cryptography, cbor2, sys; print("python %d.%d" % sys.version_info[:2])'), cryptography and cbor2 installed"
}

tools() {
  bench_say "2/10 pinned tools in $B/bin and $B/tools/bin"
  bench_go_tool step "$STEP_CLI_MODULE@$STEP_VERSION" "$B/bin" 2>>"$LOG" || fail "go install step"
  bench_go_tool step-ca "$STEP_CA_MODULE@$STEP_VERSION" "$B/bin" 2>>"$LOG" || fail "go install step-ca"
  bench_go_tool protoc-gen-go "$PROTOC_GEN_GO" "$B/tools/bin" 2>>"$LOG" || fail "go install protoc-gen-go"
  bench_go_tool protoc-gen-go-grpc "$PROTOC_GEN_GO_GRPC" "$B/tools/bin" 2>>"$LOG" || fail "go install protoc-gen-go-grpc"
  bench_go_tool protoc-gen-go-json "$PROTOC_GEN_GO_JSON" "$B/tools/bin" 2>>"$LOG" || fail "go install protoc-gen-go-json"
  if [ -x "$B/bin/vault" ] && "$B/bin/vault" version | grep -q "^Vault v$VAULT_VERSION "; then
    echo "  vault $VAULT_VERSION: present"
  else
    local key="VAULT_SHA256_${BENCH_OS}_${BENCH_ARCH}" zip="vault_${VAULT_VERSION}_${BENCH_OS}_${BENCH_ARCH}.zip" tmp
    local want="${!key:-}"
    [ -n "$want" ] || fail "no pinned Vault $VAULT_VERSION for $BENCH_OS/$BENCH_ARCH in scripts/versions.env"
    tmp="$(mktemp -d)"
    curl -sfL -o "$tmp/$zip" "https://releases.hashicorp.com/vault/$VAULT_VERSION/$zip" || fail "download $zip"
    [ "$(bench_sha256 "$tmp/$zip")" = "$want" ] || fail "$zip does not match its pinned SHA-256"
    unzip -o -q "$tmp/$zip" vault -d "$B/bin"
    rm -rf "${tmp:?}"
    echo "  vault $VAULT_VERSION: installed (SHA-256 matches the pin)"
  fi
}

sources() {
  bench_say "3/10 third-party sources (pinned upstream + our patches)"
  "$BENCH_REPO/third_party/fetch.sh" || fail "third_party/fetch.sh"
}

tls() {
  bench_say "4/10 the bench's TLS root and service certificates ($B/tls)"
  (
    cd "$B/tls"
    umask 077
    if [ ! -f root.crt ]; then
      quiet step certificate create "TACRA bench TLS root" root.crt root.key --profile root-ca --no-password --insecure \
        --not-after 8760h || fail "TLS root"
      echo "  root created (1 year)"
    fi
    openssl x509 -checkend 2592000 -noout -in root.crt >/dev/null \
      || echo "  warning: the TLS root expires within 30 days; remove $B to start over"
    local s renewed=""
    for s in ca-gateway vault-gateway est-server tdx-verifier sim-verifier vault rup; do
      if [ -f "$s.crt" ] && openssl x509 -checkend 1209600 -noout -in "$s.crt" >/dev/null; then continue; fi
      quiet step certificate create localhost "$s.crt" "$s.key" --profile leaf --ca root.crt --ca-key root.key \
        --san localhost --san 127.0.0.1 --no-password --insecure --not-after 2160h --force || fail "certificate $s"
      renewed="$renewed $s"
    done
    echo "  service certificates (90 days, renewed within 14 days of expiry):${renewed:- all current}"
  )
}

step_ca() {
  bench_say "5/10 step-ca, the workload CA ($B/step, 127.0.0.1:9000)"
  export STEPPATH="$B/step"
  if [ ! -f "$STEPPATH/config/ca.json" ]; then
    (umask 077; openssl rand -hex 32 >"$B/secrets/step-ca-password"; openssl rand -hex 32 >"$B/secrets/provisioner-password")
    quiet step ca init --deployment-type standalone --name "TACRA bench CA" --dns localhost --dns 127.0.0.1 \
      --address 127.0.0.1:9000 --provisioner tacra-ca-gateway --password-file "$B/secrets/step-ca-password" \
      --provisioner-password-file "$B/secrets/provisioner-password" || fail "step ca init"
    quiet step ca provisioner update tacra-ca-gateway --x509-default-dur=1h --x509-max-dur=24h --x509-min-dur=5m \
      || fail "step ca provisioner update"
    # the CA issues only workload names, and keeps the provisioner's key for the CA gateway
    python3 - "$STEPPATH/config/ca.json" "$B/secrets/provisioner.jwe" <<'PY' || fail "step-ca policy"
import json, os, sys
c = json.load(open(sys.argv[1]))
c["authority"]["policy"] = {"x509": {"allow": {"dns": ["*.workload.tacra.example"], "uri": ["tacra.example"]}}}
json.dump(c, open(sys.argv[1], "w"), indent=1)
p = [x for x in c["authority"]["provisioners"] if x["name"] == "tacra-ca-gateway"][0]
os.umask(0o077)
open(sys.argv[2], "w").write(p["encryptedKey"])
PY
    (umask 077; step crypto jwe decrypt --password-file "$B/secrets/provisioner-password" <"$B/secrets/provisioner.jwe" \
      >"$B/gateways/ca-provisioner.jwk") || fail "provisioner key"
    rm -f "$B/secrets/provisioner.jwe"
    echo "  initialised: TACRA bench CA, provisioner tacra-ca-gateway (5 min to 24 h, default 1 h)"
  else
    echo "  present"
  fi
  cat "$STEPPATH/certs/root_ca.crt" "$STEPPATH/certs/intermediate_ca.crt" >"$B/workload-ca.pem"
}

# one command of Veraison's own deployment script (deployments/native) for the deployment in $V, logged
vdeploy() {
  (cd "$BENCH_REPO/third_party/veraison-services/src/deployments/native" && VERAISON_ROOT="$V" ./deployment.sh "$@") \
    >>"$LOG" 2>&1
}

veraison() {
  bench_say "6/10 Veraison ($V)"
  # The trees of the sources it is built from, each the pinned upstream with our patches (third_party/fetch.sh checks
  # them): Veraison's and go-gen-ref's, which Veraison's SEV-SNP scheme builds in. The deployment records them: when a
  # patch changes either, the programs and plugins are built again.
  local vtree gtree tree built="$V/built-from-tree"
  vtree="$(git -C "$BENCH_REPO/third_party/veraison-services/src" write-tree)" || fail "Veraison sources"
  gtree="$(git -C "$BENCH_REPO/third_party/go-gen-ref/src" write-tree)" || fail "go-gen-ref sources"
  tree="veraison-services $vtree go-gen-ref $gtree"
  if [ ! -x "$V/bin/vts-service" ]; then
    echo "  building and deploying (a few minutes; log: $LOG)"
    { vdeploy build && vdeploy deploy && vdeploy init-certs localhost && vdeploy init-clients && vdeploy init-stores; } \
      || fail "Veraison deployment"
    echo "$tree" >"$built"
  elif [ "$(cat "$built" 2>/dev/null)" != "$tree" ]; then
    # deploy replaces the programs, the plugins and the services' configuration (edited again below); the
    # certificates, keys, clients and stores stay. Veraison is stopped first and started again at step 9.
    echo "  built from other sources: building again (Veraison ${vtree:0:12}, go-gen-ref ${gtree:0:12}; a few minutes);" \
      "keys and stores kept"
    "$BENCH_REPO/e2e/scripts/veraison-local.sh" stop >>"$LOG" 2>&1 || true
    { vdeploy build && vdeploy deploy; } || fail "Veraison build"
    echo "$tree" >"$built"
  else
    echo "  deployment present, built from Veraison ${vtree:0:12} and go-gen-ref ${gtree:0:12}"
  fi
  # the EAR signing key (and CoSERV's), generated here in the shape Veraison's own tool writes
  mkdir -p "$V/signing"
  python3 - "$V/signing" <<'PY' || fail "Veraison signing keys"
import base64, json, os, sys
from cryptography.hazmat.primitives.asymmetric import ec
def b64(n): return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()
os.umask(0o077)
for name in ("skey.jwk", "coserv-signer.jwk"):
    p = os.path.join(sys.argv[1], name)
    if os.path.exists(p):
        continue
    k = ec.generate_private_key(ec.SECP256R1())
    n = k.private_numbers()
    json.dump({"kty": "EC", "crv": "P-256", "x": b64(n.public_numbers.x), "y": b64(n.public_numbers.y),
               "d": b64(n.private_value)}, open(p, "w"))
    print("  signing key", name, "generated")
PY
  # every listener on 127.0.0.1 only
  python3 - "$V/config/services/config.yaml" <<'PY' || fail "Veraison listen addresses"
import re, sys
p = sys.argv[1]
y = open(p).read()
y2 = y.replace("listen-addr: 0.0.0.0:", "listen-addr: 127.0.0.1:")
if not re.search(r"^  listen-addr: 127\.0\.0\.1:50051$", y2, re.M):
    y2 = re.sub(r"^(  server-addr: localhost:50051)$", r"\1\n  listen-addr: 127.0.0.1:50051", y2, flags=re.M)
if y2 != y:
    open(p, "w").write(y2)
    print("  services bound to 127.0.0.1")
PY
}

bench_config() {
  bench_say "7/10 the bench's configuration and programs ($B/config, $B/bin)"
  "$BENCH" config || fail "e2e/scripts/bench.sh config"
}

vault_setup() {
  bench_say "8/10 HashiCorp Vault (127.0.0.1:8200, mutual TLS)"
  export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT="$B/tls/root.crt" \
    VAULT_CLIENT_CERT="$B/tls/clients/operator.crt" VAULT_CLIENT_KEY="$B/tls/clients/operator.key"
  if ! { [ -f "$B/vault.pid" ] && kill -0 "$(cat "$B/vault.pid")" 2>/dev/null; }; then
    : >"$B/vault.log"
    nohup vault server -config="$B/vault/config.hcl" >>"$B/vault.log" 2>&1 &
    echo $! >"$B/vault.pid"
  fi
  bench_wait_port 8200 || fail "Vault did not start (see $B/vault.log)"
  local status
  status="$(vault status -format=json 2>/dev/null || true)"
  if ! python3 -c 'import json,sys; sys.exit(0 if json.loads(sys.argv[1])["initialized"] else 1)' "$status"; then
    (umask 077; vault operator init -key-shares=1 -key-threshold=1 -format=json >"$B/secrets/vault-init.json") || fail "vault operator init"
    echo "  initialised (1 key share, kept in $B/secrets)"
    status="$(vault status -format=json 2>/dev/null || true)"
  fi
  if python3 -c 'import json,sys; sys.exit(0 if json.loads(sys.argv[1])["sealed"] else 1)' "$status"; then
    quiet vault operator unseal "$(python3 -c "import json;print(json.load(open('$B/secrets/vault-init.json'))['unseal_keys_b64'][0])")" \
      || fail "vault operator unseal"
    echo "  unsealed"
  fi
  VAULT_TOKEN="$(python3 -c "import json;print(json.load(open('$B/secrets/vault-init.json'))['root_token'])")"
  export VAULT_TOKEN
  vault secrets list -format=json | grep -q '"secret/"' || quiet vault secrets enable -path=secret kv-v2 || fail "kv-v2"
  # the gateway's token: read access to the ledger's secret only, valid one year on this local bench
  quiet vault write sys/auth/token/tune max_lease_ttl=8760h || fail "token max TTL"
  printf 'path "secret/data/tacra/*" {\n  capabilities = ["read"]\n}\n' | quiet vault policy write tacra-vault-gateway - \
    || fail "vault policy"
  local ttl=0
  if [ -s "$B/gateways/vault-gateway.token" ]; then
    ttl="$(VAULT_TOKEN="$(cat "$B/gateways/vault-gateway.token")" vault token lookup -format=json 2>/dev/null \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["ttl"])' 2>/dev/null || echo 0)"
  fi
  if [ "$ttl" -lt 2592000 ]; then
    (umask 077; vault token create -policy=tacra-vault-gateway -ttl=8760h -field=token >"$B/gateways/vault-gateway.token") \
      || fail "gateway token"
    echo "  gateway token issued (1 year, policy tacra-vault-gateway)"
  fi
  # the ledger's API key: the Vault releases it to an attested workload; the ledger (rup) admits it
  [ -s "$B/secrets/rup-api-key" ] || (umask 077; openssl rand -hex 32 >"$B/secrets/rup-api-key")
  if ! quiet vault kv get -mount=secret tacra/payments; then
    quiet vault kv put -mount=secret tacra/payments type=api-key format=text value="$(tr -d '\n' <"$B/secrets/rup-api-key")" \
      || fail "vault kv put"
    echo "  ledger API key stored at secret/tacra/payments"
  fi
  unset VAULT_TOKEN
}

veraison_provision() {
  bench_say "9/10 Veraison started and provisioned (AMD Milan ARK, approved SEV-SNP launches)"
  "$BENCH_REPO/e2e/scripts/veraison-local.sh" start
  if ! { bench_wait_port 50051 && bench_wait_port 9443 && bench_wait_port 8443; }; then fail "Veraison did not start (see $V/logs)"; fi
  # trust/veraison-corim-milan.cbor; submitted again when it changes (its SHA-256 is kept next to the answer)
  local corim="$BENCH_REPO/trust/veraison-corim-milan.cbor" mark="$V/logs/corim-submit.json" sum
  sum="$(bench_sha256 "$corim")"
  if grep -q success "$mark" 2>/dev/null; then
    [ -f "$mark.sha256" ] || echo "$sum" >"$mark.sha256"   # provisioned before the SHA-256 was kept: this CoRIM
    if [ "$(cat "$mark.sha256")" = "$sum" ]; then echo "  already provisioned"; return; fi
  fi
  # retried while the provisioning service's connection to VTS is still coming up (gRPC Unavailable)
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -sS --cacert "$V/certs/rootCA.crt" -X POST \
      -H 'Content-Type: application/rim+cbor; profile="tag:amd.com,2024:snp-corim-profile"' \
      --data-binary @"$corim" https://localhost:9443/endorsement-provisioning/v1/submit >"$mark" || fail "CoRIM submission"
    grep -q success "$mark" && break
    grep -q Unavailable "$mark" || break
    sleep 3
  done
  grep -q success "$mark" || fail "Veraison did not accept the CoRIM: $(cat "$mark")"
  echo "$sum" >"$mark.sha256"
  echo "  CoRIM accepted"
}

start_all() {
  bench_say "10/10 starting the bench"
  "$BENCH" start || fail "e2e/scripts/bench.sh start"
  "$BENCH" status
}

preflight() {
  "$BENCH_REPO/scripts/doctor.sh" >/dev/null || { "$BENCH_REPO/scripts/doctor.sh"; exit 1; }
  # the ports must be free, or held by this bench: a rerun while some of its services run (after a partial setup too)
  local f ours=""
  for f in "$B"/*.pid "$V"/logs/*.pid; do
    [ -f "$f" ] && kill -0 "$(cat "$f")" 2>/dev/null && ours=yes
  done
  if [ -z "$ours" ]; then
    local p busy=""
    for p in $BENCH_PORTS; do nc -z 127.0.0.1 "$p" 2>/dev/null && busy="$busy $p"; done
    [ -z "$busy" ] || bench_die "ports in use by another program:$busy. Stop it first (lsof -nP -iTCP:<port> -sTCP:LISTEN shows which)."
  fi
}

preflight
dirs_and_python
tools
sources
tls
step_ca
veraison
bench_config
vault_setup
veraison_provision
start_all
echo
echo "The bench is up in $B. Next: make status, make check-mtls."
