#!/usr/bin/env bash
# The local TACRA test bench: Veraison (verification), step-ca (workload credentials), HashiCorp Vault (secrets),
# the Credential Authority and Secret Vault gateways (the RRPs), the EST server (the conduit) and an ordinary mTLS
# service (the RATS-unaware Relying Party). Keys, passwords and
# generated configuration live under ~/tacra-bench, outside git. Every listener is on 127.0.0.1.
#
#   e2e/scripts/bench.sh config    write the gateway and EST server configuration (measurements from MEASUREMENTS;
#                                  RATS_MODEL=background-check makes the gateways ask the verifiers themselves)
#                                  and the infrastructure's mutual TLS: client certificates under the bench's TLS root,
#                                  the verifiers' EAR keys as files, Vault and Veraison requiring client certificates
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
# the operator's client certificate: Vault's listener requires one (N23)
export VAULT_CLIENT_CERT="$B/tls/clients/operator.crt" VAULT_CLIENT_KEY="$B/tls/clients/operator.key"

config() {
  mkdir -p "$B/config" "$BIN" "$B/tls/clients"
  [ -f "$B/epoch.hex" ] || (umask 077; openssl rand -hex 32 > "$B/epoch.hex")
  # The bench's infrastructure identities (mutual TLS, tacra-est N23): a client certificate under the bench's TLS root
  # for the EST server, each gateway and the operator, named <name>.bench.tacra.example; issued when absent or within
  # 14 days of its end.
  B="$B" python3 - <<'PY'
import datetime, os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
B = os.environ["B"]
root = x509.load_pem_x509_certificate(open(f"{B}/tls/root.crt", "rb").read())
root_key = serialization.load_pem_private_key(open(f"{B}/tls/root.key", "rb").read(), None)
now = datetime.datetime.now(datetime.timezone.utc)
for name in ("est-server", "ca-gateway", "vault-gateway", "operator"):
    cp, kp, dns = f"{B}/tls/clients/{name}.crt", f"{B}/tls/clients/{name}.key", f"{name}.bench.tacra.example"
    if os.path.exists(cp) and x509.load_pem_x509_certificate(open(cp, "rb").read()).not_valid_after_utc > now + datetime.timedelta(days=14):
        continue
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)]))
            .issuer_name(root.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(root_key, hashes.SHA256()))
    old = os.umask(0o077)
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.umask(old)
    print("client certificate", dns, "until", cert.not_valid_after_utc.date())
PY
  B="$B" MEASUREMENTS="$MEASUREMENTS" TDX_MRTDS="$TDX_MRTDS" python3 - <<'PY'
import json, os, re
B = os.environ["B"]; tdx = os.environ["TDX_MRTDS"].split(); meas = os.environ["MEASUREMENTS"].split() + tdx
hint = "payments.workload.tacra.example"
kinds = {"nonce": "present-nonce", "epoch": "present-epoch", "lepoch": "absent-epoch", "time": "absent-timestamp", "none": "absent-none"}
def target(kind, extra):
    t = {"credential_types": ["x509", "api-key"], "freshness_kind": kind}
    if kind in ("present-nonce", "present-epoch"): t["expires_in"] = 300
    if kind == "absent-timestamp": t.update(max_age=120, clock_skew=5)
    t.update(extra); return t
root = f"{B}/tls/root.crt"
infra = {n: f"{n}.bench.tacra.example" for n in ("est-server", "ca-gateway", "vault-gateway", "operator")}
def ident(name):   # a component's client certificate on its calls (N23)
    return {"client_cert": f"{B}/tls/clients/{name}.crt", "client_key": f"{B}/tls/clients/{name}.key"}
veraison = {"url": "https://localhost:8443", "ca": os.path.expanduser("~/veraison-deployment/certs/rootCA.crt")}
tdxv = {"url": "https://localhost:8453", "ca": root}
# the verifiers the RRPs may take, by name, with their EAR keys as provisioned files (N24: never fetched from them)
verifiers = [dict(veraison, name="veraison", ear_key=f"{B}/gateways/veraison.ear.jwk", submods=["SEVSNP"], provider="sev_guest"),
             dict(tdxv, name="tdx", ear_key=f"{B}/gateways/tdx-verifier.ear.jwk", submods=["TDX"], provider="tdx_guest")]
both = ["veraison", "tdx"]
model = os.environ.get("RATS_MODEL", "passport")   # who asks the verifiers: the EST server, or the gateways
common = {"verifiers": verifiers, "ear": {"max_age": 120, "skew": 5}, "epoch_file": f"{B}/epoch.hex", "rats_model": model,
          "client_ca": root, "clients": [infra["est-server"]]}
identity = {hint: {"sans": [hint, "spiffe://tacra.example/payments"], "measurements": meas, "validity": "1h"}}
catargets = {f"https://db-{k}.tacra.example": target(v, {"verifiers": both, "acceptable": ["ecdsa-p256-sha256"], "identities": identity})
             for k, v in kinds.items()}
# N24: Targets whose policy takes one platform's verifier; Evidence of the other platform is refused there
catargets["https://db-snp-only.tacra.example"] = target("present-nonce", {"verifiers": ["veraison"], "acceptable": ["ecdsa-p256-sha256"],
                                                                          "identities": identity})
catargets["https://db-tdx-only.tacra.example"] = target("present-nonce", {"verifiers": ["tdx"], "acceptable": ["ecdsa-p256-sha256"],
                                                                          "identities": identity})
ca = dict(common, **ident("ca-gateway"), rrp_id="https://ca1.tacra.example", listen="127.0.0.1:9101",
          tls_cert=f"{B}/tls/ca-gateway.crt", tls_key=f"{B}/tls/ca-gateway.key", targets=catargets,
          step_ca={"url": "https://127.0.0.1:9000", "root": f"{B}/step/certs/root_ca.crt", "provisioner": "tacra-ca-gateway",
                   "provisioner_key": f"{B}/gateways/ca-provisioner.jwk"})
# A second Credential Authority, "another bank", for the #19/#20 redirection experiment: a different rrp_id, the same
# step-ca and verifiers, the same Targets and TLS server certificate (SAN localhost/127.0.0.1). The honest EST server
# never routes to it; only the experiment driver posts to it directly, to see whether one Evidence is accepted at two
# RRPs. OMIT_RRP_ID=1 makes both CAs bind no RRP identifier (the variant #20 is about).
ca2 = dict(ca, rrp_id="https://ca2.tacra.example", listen="127.0.0.1:9103")
if os.environ.get("OMIT_RRP_ID") == "1":
    ca["omit_rrp_id_in_binding"] = True
    ca2["omit_rrp_id_in_binding"] = True
vault = dict(common, **ident("vault-gateway"), rrp_id="https://vault1.tacra.example", listen="127.0.0.1:9102",
             tls_cert=f"{B}/tls/vault-gateway.crt", tls_key=f"{B}/tls/vault-gateway.key",
             # the hpke-base-signed container only (tacra-est decision 4): an MLKEM768-P256 CEK, the Vault's signature
             targets={f"https://ledger-{k}.tacra.example": target(v, {"verifiers": both, "acceptable": ["MLKEM768-P256+HKDF-SHA256+AES-256-GCM"],
                      # key-block attributes the CAI requires of a signed container's items: the API key authenticates,
                      # an opaque bearer value; 3600 s, the bank profile's longest
                      "groups": {hint: {"secret_path": "tacra/payments", "measurements": meas, "policy_version": "1",
                                        "purpose": ["authenticate"], "algorithm": "opaque-bearer", "validity_seconds": 3600}}})
                      for k, v in kinds.items()},
             vault={"addr": "https://127.0.0.1:8200", "ca": root, "mount": "secret",
                    "token_file": f"{B}/gateways/vault-gateway.token"}, kem_keys=f"{B}/gateways/vault-kem.json",
             sign_key=f"{B}/gateways/vault-sign.key")
targets = {t: "ca" for t in catargets}
targets.update({f"https://ledger-{k}.tacra.example": "vault" for k in kinds})
est = {"tls": {"listen_address": "127.0.0.1:18443", "certificates": f"{B}/tls/est-server.crt", "private_key": f"{B}/tls/est-server.key"},
       "healthcheck_password": os.urandom(16).hex(), "timeout": 60, "rate_limit": 0, "log_file": f"{B}/est-server.log",
       "tacra": dict(ident("est-server"),
                     verifiers={"veraison": dict(veraison, provider="sev_guest"), "tdx": dict(tdxv, provider="tdx_guest")},
                     acceptable_evidence=["application/vnd.veraison.tsm-report+cbor"],
                     ca_certs=f"{B}/step/certs/intermediate_ca.crt",
                     rrps={"ca": {"url": "https://127.0.0.1:9101", "ca": root, "rrp_id": ca["rrp_id"], "mode": "enroll",
                                  "rats_model": model, "verifiers": both},
                           "vault": {"url": "https://127.0.0.1:9102", "ca": root, "rrp_id": vault["rrp_id"], "mode": "retrieve",
                                     "rats_model": model, "verifiers": both}},
                     targets=targets)}
tdxcfg = {"listen": "127.0.0.1:8453", "tls_cert": f"{B}/tls/tdx-verifier.crt", "tls_key": f"{B}/tls/tdx-verifier.key",
          "client_ca": root, "clients": [infra["est-server"], infra["ca-gateway"], infra["vault-gateway"]],
          "signing_key": f"{B}/secrets/tdx-verifier.jwk", "reference_mrtd": tdx}
for name, c in (("ca-gateway", ca), ("ca-gateway-2", ca2), ("vault-gateway", vault), ("est-server", est), ("tdx-verifier", tdxcfg)):
    p = f"{B}/config/{name}.json"
    with open(p, "w") as f: json.dump(c, f, indent=1)
    os.chmod(p, 0o600)
# Veraison's EAR key, provisioned to the gateways as a file: the public half of the deployment's signing key
sk = json.load(open(os.path.expanduser("~/veraison-deployment/signing/skey.jwk")))
with open(f"{B}/gateways/veraison.ear.jwk", "w") as f:
    json.dump({k: v for k, v in sk.items() if k in ("kty", "crv", "x", "y", "alg", "kid")}, f)
# Veraison's verification API takes only callers with a certificate of the bench's root (its client-ca option)
vy = os.path.expanduser("~/veraison-deployment/config/services/config.yaml")
y = open(vy).read()
blk = re.search(r"^verification:\n((?:  .*\n)+)", y, re.M)
if blk and "client-ca:" not in blk.group(1):
    open(vy, "w").write(y[:blk.end()] + "  client-ca: " + root + "\n" + y[blk.end():])
# HashiCorp Vault: TLS 1.3, a client certificate of the bench's root required
hcl = ['storage "file" {', '  path = "%s/vault/data"' % B, '}', 'listener "tcp" {',
       '  address                            = "127.0.0.1:8200"',
       '  tls_cert_file                      = "%s/tls/vault.crt"' % B,
       '  tls_key_file                       = "%s/tls/vault.key"' % B,
       '  tls_min_version                    = "tls13"',
       '  tls_require_and_verify_client_cert = "true"',
       '  tls_client_ca_file                 = "%s"' % root, '}',
       'api_addr      = "https://127.0.0.1:8200"', 'disable_mlock = true', 'ui            = false']
with open(f"{B}/vault/config.hcl", "w") as f: f.write("\n".join(hcl) + "\n")
# step-ca: TLS 1.3; the CA gateway authenticates to it with its provisioner's one-time token and presents its certificate
sc = f"{B}/step/config/ca.json"
c = json.load(open(sc))
if c.get("tls", {}).get("minVersion") != 1.3:
    c.setdefault("tls", {})["minVersion"] = 1.3
    with open(sc, "w") as f: json.dump(c, f, indent=1)
print("configuration written to", f"{B}/config", "(RATS model: %s)" % model)
PY
  (cd "$HERE/rrp" && GOWORK=off go build -o "$BIN/ca-gateway" ./cmd/ca-gateway && GOWORK=off go build -o "$BIN/vault-gateway" ./cmd/vault-gateway \
    && GOWORK=off go build -o "$BIN/tdx-verifier" ./cmd/tdx-verifier)
  (cd "$EST" && GOWORK=off go build -o "$BIN/estserver" ./cmd/estserver)
  (cd "$HERE/e2e" && GOWORK=off go build -o "$BIN/rup" ./cmd/rup)
  # the TDX verifier's EAR key, provisioned to the gateways as a file (its signing key is created if absent)
  "$BIN/tdx-verifier" -config "$B/config/tdx-verifier.json" -public-jwk > "$B/gateways/tdx-verifier.ear.jwk"
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
    [ -f "$B/config/ca-gateway-2.json" ] && start_one ca-gateway-2 "$BIN/ca-gateway" -config "$B/config/ca-gateway-2.json"
    start_one vault-gateway "$BIN/vault-gateway" -config "$B/config/vault-gateway.json"
    wait_port 9101; wait_port 9102; [ -f "$B/config/ca-gateway-2.json" ] && wait_port 9103
    start_one est-server "$BIN/estserver" -config "$B/config/est-server.json"
    start_one rup "$BIN/rup" -listen 127.0.0.1:19443 -cert "$B/tls/rup.crt" -key "$B/tls/rup.key" \
      -client-ca "$B/workload-ca.pem" -allow payments.workload.tacra.example -api-key-file "$B/secrets/rup-api-key"
    wait_port 18443; wait_port 19443 ;;
  stop)
    for s in rup est-server vault-gateway ca-gateway-2 ca-gateway tdx-verifier vault step-ca; do
      if running "$s"; then pid="$(cat "$B/$s.pid")"; kill "$pid"; for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done; echo "$s stopped"; fi
      rm -f "$B/$s.pid"
    done
    "$HERE/e2e/scripts/veraison-local.sh" stop ;;
  status)
    "$HERE/e2e/scripts/veraison-local.sh" status
    for s in step-ca vault tdx-verifier ca-gateway ca-gateway-2 vault-gateway est-server rup; do
      if running "$s"; then echo "$s running ($(cat "$B/$s.pid"))"; else echo "$s stopped"; fi
    done ;;
  *) echo "usage: $0 config|start|stop|status" >&2; exit 2 ;;
esac
