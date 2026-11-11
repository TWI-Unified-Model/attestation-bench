#!/usr/bin/env bash
# End-to-end run of the SPIRE proof of concept of TACRA with a confidential VM in Google Cloud: AMD SEV-SNP, or Intel
# TDX with TEE=tdx.
#
# On the computer that runs the bench: SPIRE Server built from the fork, the Server of the Credential Acquisition
# System, and the services of the bench that the Server calls: the Verifier (Veraison for SEV-SNP, the TDX Verifier of
# the bench for TDX) and the Secret Vault. The run writes the configuration of the Server from the configuration of the
# bench: the Verifier and the key that signs its Attestation Results, the approved launch measurements, the platform
# rule. The Server calls the Verifier with the client certificate of the Credential Authority gateway of the bench, and
# the Secret Vault with the client certificate of the EST Server of the bench.
# In the VM: SPIRE Agent, which joins with a join token and reaches the Server through an SSH reverse tunnel on
# 127.0.0.1:8081, and the attested Workload (support/attested-workload of the fork), the Attester. The Workload enrolls
# an X509-SVID for a key that it generates, and retrieves a credential from the Secret Vault, through the attested
# credential acquisition calls of the Workload API.
#
#   SPIRE_REPO=<checkout of the fork> e2e/scripts/spire-gcp-snp-e2e.sh            built from HEAD of the checkout
#   SPIRE_REPO=<checkout of the fork> TEE=tdx e2e/scripts/spire-gcp-snp-e2e.sh
#
# SPIRE_REPO has no default (scripts/lib.sh, bench_spire_repo); docs/spire.md says what to clone and what a run keeps.
#
# The run directory (RUNS_DIR, default BENCH_HOME/runs) keeps the record of the Workload (result.json, the X509-SVID,
# the bundle, the Evidence), the logs of the Server and of the Agent, the logs of the Verifier and of the Secret Vault
# during the run, the configurations without secrets, and the verdict (docs/spire.md, "The verdict").
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"
[ $# -eq 0 ] || bench_die "no arguments: the project and zone come from GCP_PROJECT and GCP_ZONE (scripts/lib.sh)"
bench_spire_repo
bench_gcp
PROJECT="$GCP_PROJECT" ZONE="$GCP_ZONE"
TEE="${TEE:-sev-snp}"
TRUST_DOMAIN="${TRUST_DOMAIN:-example.org}"
TARGET="spiffe://$TRUST_DOMAIN"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-spire-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
B="$BENCH_HOME"
RUNS_DIR="${RUNS_DIR:-$B/runs}"
OUT="$RUNS_DIR/${STAMP}-spire-gcp-${TEE}-e2e"
BIN="$(mktemp -d)"
S="$B/spire"   # the directory of the Server for this run: configuration, data, socket, log (outside git)
mkdir -p "$OUT/bench-logs" "$OUT/config"
case "$TEE" in sev-snp | tdx) ;; *) bench_die "TEE=$TEE: sev-snp or tdx" ;; esac
nc -z 127.0.0.1 8443 || bench_die "Veraison is not up on 127.0.0.1:8443 (make start)"
! nc -z 127.0.0.1 8081 2>/dev/null || bench_die "port 8081 is in use on this computer"

echo "== the checkout of the fork"
bench_spire_source > "$OUT/spire-source.txt"
cat "$OUT/spire-source.txt"

echo "== build: spire-server for this computer, spire-agent and attested-workload for linux/amd64"
(cd "$SPIRE_REPO" && go build -trimpath -o "$BIN/spire-server" ./cmd/spire-server \
  && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/spire-agent" ./cmd/spire-agent \
  && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/attested-workload" ./support/attested-workload)
shasum -a 256 "$BIN/spire-server" "$BIN/spire-agent" "$BIN/attested-workload" | sed "s#$BIN/##" > "$OUT/binaries.sha256"

echo "== the configuration of the Server: the Verifier of the bench and the approved launch measurements"
rm -rf "$S"; mkdir -p "$S/data"
python3 - "$B" "$S" "$TRUST_DOMAIN" "$TEE" > "$S/server.conf" <<'PY'
import json, sys
B, S, td, tee = sys.argv[1:5]
ca = json.load(open(f"{B}/config/ca-gateway.json"))
verifiers = {v["name"]: v for v in ca["verifiers"]}
name = "veraison" if tee == "sev-snp" else "tdx"
v = verifiers[name]
measurements = sorted({m for t in ca["targets"].values() for i in t.get("identities", {}).values() for m in i.get("measurements", [])})
est = json.load(open(f"{B}/config/est-server.json"))["tacra"]   # the client certificate that the Secret Vault admits
vault = json.load(open(f"{B}/config/vault-gateway.json"))          # the RATS model of the Secret Vault for a Retrieval
q = lambda s: json.dumps(s)
json.dump(ca["platform"], open(f"{S}/platform-rule.json", "w"), indent=1)
print(f'''server {{
    bind_address = "127.0.0.1"
    bind_port = "8081"
    socket_path = {q(S + "/server.sock")}
    trust_domain = {q(td)}
    data_dir = {q(S + "/data")}
    log_level = "DEBUG"
    log_file = {q(S + "/server.log")}
    default_x509_svid_ttl = "1h"
    audit_log_enabled = true
    experimental {{
        credential_acquisition {{
            acceptable_evidence = ["application/vnd.veraison.tsm-report+cbor"]
            ear_max_age = "{ca["ear"]["max_age"]}s"
            ear_skew = "{ca["ear"]["skew"]}s"
            client_cert_path = {q(ca["client_cert"])}
            client_key_path = {q(ca["client_key"])}
            verifier {q(name)} {{
                url = {q(v["url"])}
                ca_path = {q(v["ca"])}
                ear_key_path = {q(v["ear_key"])}
                provider = {q(v["provider"])}
                submods = {json.dumps(v["submods"])}
            }}
            target {q("spiffe://" + td)} {{
                mode = "enroll"
                credential_types = ["x509"]
                freshness_kind = "present-nonce"
                expires_in = "5m"
                verifiers = [{q(name)}]
                acceptable_csk = ["ecdsa-p256-sha256"]
                measurements = {json.dumps(measurements)}
            }}
            target "https://ledger-nonce.tacra.example" {{
                mode = "retrieve"
                credential_types = ["api-key", "x509"]
                rats_model = {q(vault.get("rats_model") or "passport")}
                verifiers = [{q(name)}]
            }}
            secret_vault {{
                url = "https://127.0.0.1:9102"
                ca_path = {q(B + "/tls/root.crt")}
                client_cert_path = {q(est["client_cert"])}
                client_key_path = {q(est["client_key"])}
            }}
            platform_rule_path = {q(S + "/platform-rule.json")}
        }}
    }}
}}
plugins {{
    DataStore "sql" {{
        plugin_data {{
            database_type = "sqlite3"
            connection_string = {q(S + "/data/datastore.sqlite3")}
        }}
    }}
    NodeAttestor "join_token" {{
        plugin_data {{}}
    }}
    KeyManager "memory" {{
        plugin_data = {{}}
    }}
}}
''')
PY
cp "$S/server.conf" "$OUT/config/server.conf"
cp "$S/platform-rule.json" "$OUT/config/platform-rule.json"
# Origin authentication: when the Secret Vault signs the containers that it releases for the Target, the Workload
# gets the public signature key of the Secret Vault, from its origin-keys resource, and requires the signature.
# config/vault-mode.txt of the run records whether the Secret Vault signs.
ORIGIN_AUTH="$(python3 -c "import json,sys; v=json.load(open(sys.argv[1])); print('off' if v['targets']['https://ledger-nonce.tacra.example'].get('sign') is False else 'on')" "$B/config/vault-gateway.json")"
VAULT_MODEL="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('rats_model') or 'passport')" "$B/config/vault-gateway.json")"
echo "vault rats_model=$VAULT_MODEL origin_auth=$ORIGIN_AUTH" | tee "$OUT/config/vault-mode.txt"
if [ "$ORIGIN_AUTH" = on ]; then
  curl -sf --cacert "$B/tls/root.crt" --cert "$B/tls/clients/operator.crt" --key "$B/tls/clients/operator.key" https://127.0.0.1:9102/tacra/v1/origin-keys \
    | python3 -c "import json,sys,base64; k=json.load(sys.stdin)['ECDSA-P256-SHA256']; der=base64.urlsafe_b64decode(k+'='*(-len(k)%4)); b=base64.b64encode(der).decode(); print('-----BEGIN PUBLIC KEY-----'); print('\\n'.join(b[i:i+64] for i in range(0,len(b),64))); print('-----END PUBLIC KEY-----')" > "$BIN/vault-origin.pem"
  cp "$BIN/vault-origin.pem" "$OUT/config/vault-origin.pem"
else
  : > "$BIN/vault-origin.pem"
fi
wc -l < "$B/vault-gateway.log" > "$OUT/bench-logs/.vault-gateway.start"
python3 -c "import json,sys; ca=json.load(open(sys.argv[1])); print(json.dumps(sorted({m for t in ca['targets'].values() for i in t.get('identities',{}).values() for m in i.get('measurements',[])}), indent=1))" "$B/config/ca-gateway.json" > "$OUT/approved-measurements.json"

wc -l < "$VERAISON_DEPLOYMENT/logs/vts.log" > "$OUT/bench-logs/.vts.start"
wc -l < "$VERAISON_DEPLOYMENT/logs/verification.log" > "$OUT/bench-logs/.verification.start"

echo "== start the Server"
SERVER_PID=""
TUNNEL=""
cleanup() {
  set +e
  [ -n "$TUNNEL" ] && kill "$TUNNEL" 2>/dev/null
  echo "== delete $NAME"
  gcloud compute instances delete "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1
  left="$(gcloud compute instances list --project="$PROJECT" --filter="name=$NAME" --format='value(name)' 2>/dev/null)"
  if [ -n "$left" ]; then echo "!! $NAME still exists"; else echo "== $NAME is gone at $(bench_now)" | tee "$OUT/vm-deleted.txt"; fi
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  rm -rf "$BIN"
}
trap cleanup EXIT
"$BIN/spire-server" run -config "$S/server.conf" > "$S/server.stdout" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 30); do "$BIN/spire-server" healthcheck -socketPath "$S/server.sock" >/dev/null 2>&1 && break; sleep 1; done
"$BIN/spire-server" healthcheck -socketPath "$S/server.sock" >/dev/null || { cat "$S/server.stdout"; bench_die "SPIRE Server did not come up"; }
AGENT_ID="spiffe://$TRUST_DOMAIN/agent/gcp-$TEE"   # the join token names the Agent; SPIRE reserves /spire/agent/
TOKEN="$("$BIN/spire-server" token generate -socketPath "$S/server.sock" -spiffeID "$AGENT_ID" -ttl 1800 | awk '/Token:/{print $2}')"
[ -n "$TOKEN" ] || bench_die "no join token"
"$BIN/spire-server" bundle show -socketPath "$S/server.sock" -format pem > "$BIN/bundle.pem"
"$BIN/spire-server" entry create -socketPath "$S/server.sock" -parentID "$AGENT_ID" -spiffeID "spiffe://$TRUST_DOMAIN/workload" \
  -selector unix:uid:0 -hint internal -x509SVIDTTL 3600 > "$OUT/entry.txt"
cat "$OUT/entry.txt"

echo "== the configuration of the Agent (the join token goes on the command line, not into the record)"
cat > "$BIN/agent.conf" <<CONF
agent {
    data_dir = "/root/spire-agent/data"
    log_level = "DEBUG"
    log_file = "/root/spire-agent/agent.log"
    server_address = "127.0.0.1"
    server_port = "8081"
    socket_path = "/tmp/spire-agent/public/api.sock"
    trust_bundle_path = "/root/spire-agent/bundle.pem"
    trust_domain = "$TRUST_DOMAIN"
}
plugins {
    NodeAttestor "join_token" {
        plugin_data {}
    }
    KeyManager "disk" {
        plugin_data {
            directory = "/root/spire-agent/data"
        }
    }
    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
CONF
cp "$BIN/agent.conf" "$OUT/config/agent.conf"

if [ "$TEE" = tdx ]; then
  MACHINE=(--machine-type=c3-standard-4 --confidential-compute-type=TDX)
else
  MACHINE=(--machine-type=n2d-standard-2 --min-cpu-platform="AMD Milan" --confidential-compute-type=SEV_SNP)
fi
echo "== create $NAME ($ZONE, $TEE)"
gcloud compute instances create "$NAME" --project="$PROJECT" --zone="$ZONE" "${MACHINE[@]}" \
  --maintenance-policy=TERMINATE --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB --labels=purpose=tacra-spire,stamp="$(echo "$STAMP" | tr -d 'TZ')" "${GCP_GUEST_METADATA[@]}" >/dev/null
SSH=(gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE")

echo "== wait for ssh"
for _ in $(seq 1 30); do "${SSH[@]}" --command=true >/dev/null 2>&1 && break; sleep 10; done
"${SSH[@]}" --command='
set -e
sudo modprobe sev-guest 2>/dev/null || sudo modprobe tdx_guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /sys/kernel/config/tsm/report; uname -r' 2>>"$OUT/ssh.stderr" | tee "$OUT/provision.txt"

echo "== copy the Agent, the Workload and the public configuration"
bench_retry "$OUT/ssh.stderr" gcloud compute scp "$BIN/spire-agent" "$BIN/attested-workload" "$BIN/agent.conf" "$BIN/bundle.pem" "$BIN/vault-origin.pem" \
  "$HERE/hwcheck/scripts/guest-clock.sh" "$NAME:~/" --project="$PROJECT" --zone="$ZONE" >/dev/null

echo "== reverse tunnel to the Server (8081)"
UP=""
for try in 1 2 3; do
  "${SSH[@]}" -- -N -o ExitOnForwardFailure=yes -R 8081:127.0.0.1:8081 2>>"$OUT/ssh.stderr" &
  TUNNEL=$!
  for _ in $(seq 1 20); do
    kill -0 "$TUNNEL" 2>/dev/null || break
    "${SSH[@]}" --command='nc -z 127.0.0.1 8081' >/dev/null 2>&1 && { UP=1; break; }
    sleep 3
  done
  [ -z "$UP" ] || break
  kill "$TUNNEL" 2>/dev/null || true
  echo "$(bench_now) the reverse tunnel is not up, try $try of 3" >>"$OUT/ssh.stderr"
done
[ -n "$UP" ] || bench_die "the reverse tunnel to the Server did not come up ($OUT/ssh.stderr)"

echo "== run in the VM: the Agent joins, the Workload enrolls and retrieves"
NB="$(date -u +%s)"
GUEST_RC=0
# shellcheck disable=SC2016
bench_guest_run "$OUT/ssh.stderr" '
set -eo pipefail
H="$HOME"
sudo mkdir -p /root/spire-agent/data /tmp/spire-agent/public
sudo cp "$H/agent.conf" "$H/bundle.pem" /root/spire-agent/
sudo chmod +x "$H/spire-agent" "$H/attested-workload"
# the Agent runs as root: the socket of the Workload API, the unix attestor for a Workload of root, the data directory
sudo bash -c "nohup $H/spire-agent run -config /root/spire-agent/agent.conf -joinToken '"$TOKEN"' > /root/spire-agent/agent.stdout 2>&1 &"
for _ in $(seq 1 60); do sudo test -S /tmp/spire-agent/public/api.sock && break; sleep 1; done
rc=0
sudo "$H/spire-agent" healthcheck -socketPath /tmp/spire-agent/public/api.sock || rc=$?
mkdir -p "$H/out" "$H/out-retrieve"
if [ "$rc" = 0 ]; then
  sleep 3
  sudo "$H/attested-workload" -target '"$TARGET"' -tee '"$TEE"' -hint internal -out "$H/out" 2>&1 | tee "$H/out/stdout.txt" || rc=$?
  ORIGIN=""; [ -s "$H/vault-origin.pem" ] && ORIGIN="-vaultOriginKey $H/vault-origin.pem"
  sudo "$H/attested-workload" -target https://ledger-nonce.tacra.example -credentialType api-key -tee '"$TEE"' -hint payments.workload.tacra.example $ORIGIN -out "$H/out-retrieve" 2>&1 | tee "$H/out-retrieve/stdout.txt" || rc=$?
fi
sudo chown -R "$(id -u):$(id -g)" "$H/out" "$H/out-retrieve"
sudo rm -f "$H/out/svid.key" "$H/out-retrieve/credential.secret"
uname -a > "$H/kernel.txt"
sudo bash "$H/guest-clock.sh" "$H" && sudo chown "$(id -u):$(id -g)" "$H/clock.txt"
(curl -s -H Metadata-Flavor:Google http://metadata.google.internal/computeMetadata/v1/instance/machine-type > "$H/machine-type.txt" || true)
sudo pkill -f "spire-agent run" || true
sleep 1
for f in agent.log agent.stdout; do sudo cp "/root/spire-agent/$f" "$H/$f" 2>/dev/null && sudo chown "$(id -u):$(id -g)" "$H/$f" || : > "$H/$f"; done
tar czf "$H/out.tgz" -C "$H" out out-retrieve agent.log agent.stdout kernel.txt machine-type.txt clock.txt
exit "$rc"' "${SSH[@]}" --command | tee "$OUT/guest-stdout.txt" || GUEST_RC=$?
NA="$(date -u +%s)"
echo "$NB $NA" > "$OUT/run-window.txt"
echo "exit status of the script in the VM: $GUEST_RC" | tee "$OUT/guest-rc.txt"
bench_clock_offset "$OUT/clock-offset.txt" "${SSH[@]}" --command || true
bench_retry "$OUT/ssh.stderr" gcloud compute scp "$NAME:~/out.tgz" "$OUT/" --project="$PROJECT" --zone="$ZONE" >/dev/null || true
if [ -f "$OUT/out.tgz" ]; then tar xzf "$OUT/out.tgz" -C "$OUT" && rm -f "$OUT/out.tgz" && mv "$OUT/out" "$OUT/workload" && mv "$OUT/out-retrieve" "$OUT/workload-retrieve"; fi
cleanup
trap 'rm -rf "$BIN"' EXIT

echo "== the logs of the Server, of the Verifier and of the Secret Vault during the run"
cp "$S/server.log" "$OUT/server.log"
tail -n +"$(( $(cat "$OUT/bench-logs/.vault-gateway.start") + 1 ))" "$B/vault-gateway.log" | grep -v "TLS handshake error" > "$OUT/bench-logs/vault-gateway.log" || true
tail -n +"$(( $(cat "$OUT/bench-logs/.vts.start") + 1 ))" "$VERAISON_DEPLOYMENT/logs/vts.log" | grep -v DEBUG > "$OUT/bench-logs/veraison-vts.log" || true
tail -n +"$(( $(cat "$OUT/bench-logs/.verification.start") + 1 ))" "$VERAISON_DEPLOYMENT/logs/verification.log" | grep -v DEBUG > "$OUT/bench-logs/veraison-verification.log" || true
rm -f "$OUT"/bench-logs/.*.start

echo "== verdict"
rc=0
python3 - "$OUT" "$TRUST_DOMAIN" > "$OUT/verdict.txt" <<'PY' || rc=$?
import json, os, sys
out, td = sys.argv[1:3]
try:
    r = json.load(open(f"{out}/workload/result.json"))
except FileNotFoundError:
    print("REFUSED   no result.json: the Workload did not run (guest-stdout.txt, agent.stdout)")
    sys.exit(1)
approved = set(json.load(open(f"{out}/approved-measurements.json")))
server = open(f"{out}/server.log", errors="replace").read()
try:
    rr = json.load(open(f"{out}/workload-retrieve/result.json"))
except FileNotFoundError:
    rr = {}
vault = open(f"{out}/bench-logs/vault-gateway.log", errors="replace").read() if os.path.exists(f"{out}/bench-logs/vault-gateway.log") else ""
audit = [l for l in server.splitlines() if "API accessed" in l and "method=EnrollCredential" in l]
audit_r = [l for l in server.splitlines() if "API accessed" in l and "method=RetrieveCredential" in l]
enrolled = [l for l in server.splitlines() if "Enrolled an attested X509-SVID" in l]
m = r.get("report_measurement_hex")
checks = {
    "Enrollment: the Workload completed without an error": r.get("ok") is True,
    "Enrollment: the chain of the X509-SVID verifies against the bundle": r.get("chain_verified") is True,
    "Enrollment: the X509-SVID certifies the key that the Workload generated": r.get("key_matches") is True,
    "Enrollment: the X509-SVID names the SPIFFE ID of the registration entry": r.get("spiffe_id") == f"spiffe://{td}/workload",
    "Enrollment: the launch measurement is approved": m in approved,
    "Enrollment: SPIRE Server enrolled with the launch measurement of the Evidence": any(f"measurement={m}" in l for l in enrolled),
    "Enrollment: SPIRE Server audited the call as a success with that launch measurement": any("status=success" in l and f"measurement={m}" in l for l in audit),
    "Retrieval: the Workload completed without an error": rr.get("ok") is True,
    "Retrieval: the Workload opened the credential with its Credential Encryption Key": bool(rr.get("secret_sha256")) and rr.get("secret_bytes", 0) > 0,
    "Retrieval: the Evidence has the launch measurement of the Enrollment": rr.get("report_measurement_hex") == m,
    "Retrieval: SPIRE Server audited the call as a success": any("status=success" in l for l in audit_r),
    "Retrieval: the Secret Vault released the credential for the Target": "released: target=https://ledger-nonce.tacra.example" in vault,
}
mode = open(f"{out}/config/vault-mode.txt").read().strip() if os.path.exists(f"{out}/config/vault-mode.txt") else ""
if "origin_auth=on" in mode:
    checks["Retrieval: the Workload verified the origin signature of the container under the key of the Secret Vault"] = rr.get("origin_verified") is True
for k, v in checks.items():
    print(("ADMITTED  " if v else "REFUSED   ") + k)
print()
print(f"enroll: spiffe_id={r.get('spiffe_id')} serial={r.get('cert_serial')} not_after={r.get('not_after')}")
print(f"enroll: measurement={m} report_version={r.get('report_version')} signer={r.get('report_signer')}")
print(f"enroll: initiate_ms={r.get('initiate_ms')} enroll_ms={r.get('enroll_ms')} evidence_bytes={r.get('evidence_bytes')}")
print(f"retrieve: item={rr.get('item_type')}/{rr.get('item_kid')} suite={rr.get('suite')} secret_bytes={rr.get('secret_bytes')} secret_sha256={rr.get('secret_sha256')} group={str(rr.get('group_id'))[:16]}…")
print(f"retrieve: initiate_ms={rr.get('initiate_ms')} retrieve_ms={rr.get('retrieve_ms')} cek_pub_bytes={rr.get('cek_pub_bytes')} origin_verified={rr.get('origin_verified')} vault: {mode}")
for name, x in (("enroll", r), ("retrieve", rr)):
    if x.get("error"): print(f"{name} error:", x["error"])
sys.exit(0 if all(checks.values()) else 1)
PY
cat "$OUT/verdict.txt"
bench_seal "$OUT"
echo "== run directory: $OUT"
exit "$rc"
