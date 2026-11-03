#!/usr/bin/env bash
# End-to-end run of the SPIRE proof of concept of TACRA on an AWS EC2 AMD SEV-SNP guest (c6a.large, AmdSevSnp enabled).
# On the test bench (this machine): SPIRE Server from the TWI-Unified-Model fork, the Credential Acquisition System
# Server of TACRA, configured with the bench's Veraison as its verifier (the Credential Authority gateway's client
# certificate and EAR key, the approved launch measurements of trust/approved-launches.json as the gateways hold them),
# and Veraison itself (e2e/scripts/bench.sh start). In the guest: SPIRE Agent (join token node attestation, the server
# reached through the SSH reverse tunnel on 127.0.0.1:8081) and the attested workload (support/attested-workload of the
# fork: the Attester with the SEV-SNP or TDX plug-in), which enrolls an X509-SVID for a key of its own through the
# attested credential acquisition calls of the Workload API.
#
#   e2e/scripts/spire-aws-snp-e2e.sh            SPIRE_REPO=~/dev/spire (the fork's checkout, built from its HEAD)
#   AWS_REGION, AWS_AZ: where the instance goes (scripts/lib.sh); TYPE: the instance type (default c6a.large)
#
# The run directory (RUNS_DIR, default BENCH_HOME/runs) keeps the workload's record (result.json, the SVID and the
# bundle, the Evidence), the server's and the agent's logs, Veraison's logs of the run, the configurations without
# secrets, and the verdict: admitted when the workload's chain verifies, carries its key, and the server's audit
# record names a launch measurement the bench approves.
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"
[ $# -eq 0 ] || bench_die "no arguments: the region and zone come from AWS_REGION and AWS_AZ (scripts/lib.sh)"
bench_aws
REGION="$AWS_REGION" AZ="$AWS_AZ"
TYPE="${TYPE:-c6a.large}"
AMI_PARAM="${AMI_PARAM:-/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id}"
TEE="sev-snp"
SPIRE_REPO="${SPIRE_REPO:-$HOME/dev/spire}"
TRUST_DOMAIN="${TRUST_DOMAIN:-example.org}"
TARGET="spiffe://$TRUST_DOMAIN"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-spire-aws-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
B="$BENCH_HOME"
RUNS_DIR="${RUNS_DIR:-$B/runs}"
OUT="$RUNS_DIR/${STAMP}-spire-aws-${TEE}-e2e"
BIN="$(mktemp -d)"
S="$B/spire"   # the server's directory for this run: configuration, data, socket, log (outside git)
mkdir -p "$OUT/bench-logs" "$OUT/config"
[ -d "$SPIRE_REPO/.git" ] || bench_die "SPIRE_REPO=$SPIRE_REPO is not a checkout"
make -s status >/dev/null 2>&1 || true
nc -z 127.0.0.1 8443 || bench_die "Veraison is not up on 127.0.0.1:8443 (make start)"
! nc -z 127.0.0.1 8081 2>/dev/null || bench_die "port 8081 is taken on this machine"

echo "== the fork's state"
{ echo "spire built from $SPIRE_REPO"; git -C "$SPIRE_REPO" log -1 --format="  commit %H %s"; git -C "$SPIRE_REPO" status --porcelain | sed 's/^/  modified: /';
  grep -E '^replace' "$SPIRE_REPO/go.mod" | sed 's/^/  /'; for r in go-spiffe spire-api-sdk; do git -C "$HOME/dev/$r" log -1 --format="$r: %H %s"; done; } > "$OUT/spire-source.txt"
cat "$OUT/spire-source.txt"

echo "== build: spire-server (this machine), spire-agent and attested-workload (linux/amd64)"
(cd "$SPIRE_REPO" && go build -trimpath -o "$BIN/spire-server" ./cmd/spire-server \
  && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/spire-agent" ./cmd/spire-agent \
  && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/attested-workload" ./support/attested-workload)
shasum -a 256 "$BIN/spire-server" "$BIN/spire-agent" "$BIN/attested-workload" | sed "s#$BIN/##" > "$OUT/binaries.sha256"

echo "== the server's configuration: the bench's verifier and approved launches"
rm -rf "$S"; mkdir -p "$S/data"
python3 - "$B" "$S" "$TRUST_DOMAIN" "$TEE" > "$S/server.conf" <<'PY'
import json, sys
B, S, td, tee = sys.argv[1:5]
ca = json.load(open(f"{B}/config/ca-gateway.json"))
verifiers = {v["name"]: v for v in ca["verifiers"]}
name = "veraison" if tee == "sev-snp" else "tdx"
v = verifiers[name]
measurements = sorted({m for t in ca["targets"].values() for i in t.get("identities", {}).values() for m in i.get("measurements", [])})
est = json.load(open(f"{B}/config/est-server.json"))["tacra"]   # the conduit's client certificate: the Vault takes it
vault = json.load(open(f"{B}/config/vault-gateway.json"))          # its RATS model: who asks the verifier for a Retrieval
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
# the vault's origin authentication: when its Targets sign their containers, the guest holds the vault's signature
# key (public, from the vault's origin-keys resource) and requires the signature; the record keeps which
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

echo "== start the server"
SERVER_PID=""
TUNNEL=""
ID="" SG="" KEY="$NAME"
cleanup() {
  set +e
  [ -n "$TUNNEL" ] && kill "$TUNNEL" 2>/dev/null
  if [ -n "$ID" ]; then
    echo "== terminate $ID"
    aws ec2 terminate-instances --region "$REGION" --instance-ids "$ID" >/dev/null
    aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$ID"
    echo "instance $ID: $(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].State.Name' --output text) at $(bench_now)" | tee "$OUT/vm-deleted.txt"
    ID=""
  fi
  if [ -n "$SG" ]; then aws ec2 delete-security-group --region "$REGION" --group-id "$SG" && echo "security group $SG deleted" | tee -a "$OUT/vm-deleted.txt"; SG=""; fi
  if [ -n "$KEY" ] && aws ec2 describe-key-pairs --region "$REGION" --key-names "$KEY" >/dev/null 2>&1; then
    aws ec2 delete-key-pair --region "$REGION" --key-name "$KEY" && echo "key pair $KEY deleted" | tee -a "$OUT/vm-deleted.txt"
  fi
  KEY=""
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  rm -rf "$BIN"
}
trap cleanup EXIT
"$BIN/spire-server" run -config "$S/server.conf" > "$S/server.stdout" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 30); do "$BIN/spire-server" healthcheck -socketPath "$S/server.sock" >/dev/null 2>&1 && break; sleep 1; done
"$BIN/spire-server" healthcheck -socketPath "$S/server.sock" >/dev/null || { cat "$S/server.stdout"; bench_die "the server did not come up"; }
AGENT_ID="spiffe://$TRUST_DOMAIN/agent/gcp-$TEE"   # the join token names the agent; /spire/agent/ is the reserved namespace
TOKEN="$("$BIN/spire-server" token generate -socketPath "$S/server.sock" -spiffeID "$AGENT_ID" -ttl 1800 | awk '/Token:/{print $2}')"
[ -n "$TOKEN" ] || bench_die "no join token"
"$BIN/spire-server" bundle show -socketPath "$S/server.sock" -format pem > "$BIN/bundle.pem"
"$BIN/spire-server" entry create -socketPath "$S/server.sock" -parentID "$AGENT_ID" -spiffeID "spiffe://$TRUST_DOMAIN/workload" \
  -selector unix:uid:0 -hint internal -x509SVIDTTL 3600 > "$OUT/entry.txt"
cat "$OUT/entry.txt"

echo "== the agent's configuration (the join token goes with the command line, not into the record)"
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

echo "== key pair, security group (SSH from this address only)"
aws ec2 create-key-pair --region "$REGION" --key-name "$KEY" --key-type ed25519 --query KeyMaterial --output text > "$BIN/key"
chmod 600 "$BIN/key"
VPC="$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
SG="$(aws ec2 create-security-group --region "$REGION" --group-name "$NAME" --description "tacra spire $STAMP" --vpc-id "$VPC" --query GroupId --output text)"
MYIP="$(curl -sf -m 10 https://checkip.amazonaws.com | tr -d '[:space:]')"
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null

echo "== launch $TYPE in $AZ with AmdSevSnp=enabled"
AMI="$(aws ssm get-parameter --region "$REGION" --name "$AMI_PARAM" --query Parameter.Value --output text)"
SUB="$(aws ec2 describe-subnets --region "$REGION" --filters Name=availability-zone,Values="$AZ" Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)"
ID="$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type "$TYPE" --subnet-id "$SUB" \
  --cpu-options AmdSevSnp=enabled --key-name "$KEY" --security-group-ids "$SG" \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=purpose,Value=tacra-spire}]" \
  --query 'Instances[0].InstanceId' --output text)"
echo "$REGION $AZ $ID $AMI $TYPE" > "$OUT/instance.txt"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$ID"
IP="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
SSHO=(-i "$BIN/key" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BIN/known_hosts" -o ConnectTimeout=10)
SSH=(ssh "${SSHO[@]}" "ubuntu@$IP")

echo "== wait for ssh"
for _ in $(seq 1 40); do "${SSH[@]}" true >/dev/null 2>&1 && break; sleep 10; done
"${SSH[@]}" '
set -e
sudo modprobe sev-guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /sys/kernel/config/tsm/report; uname -r' 2>>"$OUT/ssh.stderr" | tee "$OUT/provision.txt"

echo "== copy the agent, the workload and the public configuration"
bench_retry "$OUT/ssh.stderr" scp "${SSHO[@]}" "$BIN/spire-agent" "$BIN/attested-workload" "$BIN/agent.conf" "$BIN/bundle.pem" "$BIN/vault-origin.pem" \
  "$HERE/hwcheck/scripts/guest-clock.sh" "ubuntu@$IP:~/" >/dev/null

echo "== reverse tunnel to the server (8081)"
UP=""
for try in 1 2 3; do
  ssh "${SSHO[@]}" -N -o ExitOnForwardFailure=yes -R 8081:127.0.0.1:8081 "ubuntu@$IP" 2>>"$OUT/ssh.stderr" &
  TUNNEL=$!
  for _ in $(seq 1 20); do
    kill -0 "$TUNNEL" 2>/dev/null || break
    "${SSH[@]}" 'nc -z 127.0.0.1 8081' >/dev/null 2>&1 && { UP=1; break; }
    sleep 3
  done
  [ -z "$UP" ] || break
  kill "$TUNNEL" 2>/dev/null || true
  echo "$(bench_now) the reverse tunnel is not up, try $try of 3" >>"$OUT/ssh.stderr"
done
[ -n "$UP" ] || bench_die "the reverse tunnel to the server never came up ($OUT/ssh.stderr)"

echo "== run in the guest: the agent attests the node, the workload enrolls"
NB="$(date -u +%s)"
GUEST_RC=0
# shellcheck disable=SC2016
bench_guest_run "$OUT/ssh.stderr" '
set -eo pipefail
H="$HOME"
sudo mkdir -p /root/spire-agent/data /tmp/spire-agent/public
sudo cp "$H/agent.conf" "$H/bundle.pem" /root/spire-agent/
sudo chmod +x "$H/spire-agent" "$H/attested-workload"
# the agent runs as root: the Workload API socket, the unix attestor of a root workload, the data directory
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
(TOK="$(curl -s -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token)"; curl -s -H "X-aws-ec2-metadata-token: $TOK" http://169.254.169.254/latest/meta-data/instance-type > "$H/machine-type.txt" || true)
sudo pkill -f "spire-agent run" || true
sleep 1
for f in agent.log agent.stdout; do sudo cp "/root/spire-agent/$f" "$H/$f" 2>/dev/null && sudo chown "$(id -u):$(id -g)" "$H/$f" || : > "$H/$f"; done
tar czf "$H/out.tgz" -C "$H" out out-retrieve agent.log agent.stdout kernel.txt machine-type.txt clock.txt
exit "$rc"' "${SSH[@]}" | tee "$OUT/guest-stdout.txt" || GUEST_RC=$?
NA="$(date -u +%s)"
echo "$NB $NA" > "$OUT/run-window.txt"
echo "guest script exit status: $GUEST_RC" | tee "$OUT/guest-rc.txt"
bench_clock_offset "$OUT/clock-offset.txt" "${SSH[@]}" || true
bench_retry "$OUT/ssh.stderr" scp "${SSHO[@]}" "ubuntu@$IP:~/out.tgz" "$OUT/" >/dev/null || true
if [ -f "$OUT/out.tgz" ]; then tar xzf "$OUT/out.tgz" -C "$OUT" && rm -f "$OUT/out.tgz" && mv "$OUT/out" "$OUT/workload" && mv "$OUT/out-retrieve" "$OUT/workload-retrieve"; fi
cleanup
trap 'rm -rf "$BIN"' EXIT

echo "== the server's and Veraison's logs of the run"
cp "$S/server.log" "$OUT/server.log"
tail -n +"$(( $(cat "$OUT/bench-logs/.vault-gateway.start") + 1 ))" "$B/vault-gateway.log" | grep -v "TLS handshake error" > "$OUT/bench-logs/vault-gateway.log" || true
tail -n +"$(( $(cat "$OUT/bench-logs/.vts.start") + 1 ))" "$VERAISON_DEPLOYMENT/logs/vts.log" | grep -v DEBUG > "$OUT/bench-logs/veraison-vts.log" || true
tail -n +"$(( $(cat "$OUT/bench-logs/.verification.start") + 1 ))" "$VERAISON_DEPLOYMENT/logs/verification.log" | grep -v DEBUG > "$OUT/bench-logs/veraison-verification.log" || true
rm -f "$OUT"/bench-logs/.*.start

echo "== verdict"
rc=0
python3 - "$OUT" "$TRUST_DOMAIN" > "$OUT/verdict.txt" <<'PY' || rc=$?
import json, os, re, sys
out, td = sys.argv[1:3]
try:
    r = json.load(open(f"{out}/workload/result.json"))
except FileNotFoundError:
    print("REFUSED   no result.json: the workload did not run (see guest-stdout.txt, agent.stdout)")
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
    "enroll: workload ok": r.get("ok") is True,
    "enroll: chain verified against the bundle": r.get("chain_verified") is True,
    "enroll: the SVID carries the workload's key": r.get("key_matches") is True,
    "enroll: SPIFFE ID of the entry": r.get("spiffe_id") == f"spiffe://{td}/workload",
    "enroll: launch measurement approved": m in approved,
    "enroll: server enrolled with the report's measurement": any(f"measurement={m}" in l for l in enrolled),
    "enroll: server audited the enrollment": any("status=success" in l and f"measurement={m}" in l for l in audit),
    "retrieve: workload ok": rr.get("ok") is True,
    "retrieve: a credential came back, opened by the workload's CEK": bool(rr.get("secret_sha256")) and rr.get("secret_bytes", 0) > 0,
    "retrieve: the same launch measurement": rr.get("report_measurement_hex") == m,
    "retrieve: server audited the retrieval": any("status=success" in l for l in audit_r),
    "retrieve: the Secret Vault released for the Target": "released: target=https://ledger-nonce.tacra.example" in vault,
}
mode = open(f"{out}/config/vault-mode.txt").read().strip() if os.path.exists(f"{out}/config/vault-mode.txt") else ""
if "origin_auth=on" in mode:
    checks["retrieve: the container's origin signature verified under the vault's key"] = rr.get("origin_verified") is True
for k, v in checks.items():
    print(("ADMITTED  " if v else "REFUSED   ") + k)
print()
print(f"enroll: spiffe_id={r.get('spiffe_id')} serial={r.get('cert_serial')} not_after={r.get('not_after')}")
print(f"enroll: measurement={m} report_version={r.get('report_version')} signer={r.get('report_signer')} waived={r.get('waived','')}")
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
