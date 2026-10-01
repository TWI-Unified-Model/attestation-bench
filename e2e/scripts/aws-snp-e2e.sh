#!/usr/bin/env bash
# End-to-end run on an AWS EC2 AMD SEV-SNP guest (shared tenancy: VLEK-signed reports). In the guest: the workload
# (e2e-attester: the SIG's CAI with the SEV-SNP plug-in) and the CAS Client (caapi-est). On the test bench (this
# machine): the EST server, Veraison, the CA and Vault gateways over step-ca and HashiCorp Vault, and the mTLS
# service. The guest reaches the bench through an SSH reverse tunnel; TLS runs end to end over it. A throwaway key
# pair and a security group admitting SSH from this address only are deleted with the instance.
#
#   e2e/scripts/aws-snp-e2e.sh [REGION] [AZ]
set -euo pipefail
REGION="${1:-us-east-2}"
AZ="${2:-us-east-2a}"
TYPE="${TYPE:-c6a.large}"
AMI_PARAM="${AMI_PARAM:-/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id}"
TEE=sev-snp
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-e2e-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
B="${TACRA_BENCH:-$HOME/tacra-bench}"
OUT="$HERE/e2e/evidence/${STAMP}-aws-${TEE}-e2e"
BIN="$(mktemp -d)"
export AWS_PAGER="" GOWORK=off
mkdir -p "$OUT/bench-logs"
ID="" SG="" KEY="$NAME"
echo "== bench"
"$HERE/e2e/scripts/bench.sh" status | tee "$OUT/bench-status.txt"
if grep -q stopped "$OUT/bench-status.txt"; then echo "!! start the bench first: e2e/scripts/bench.sh start"; exit 1; fi
{ echo "twi-tacra $(git -C "$HERE" rev-parse --short=12 HEAD)$(git -C "$HERE" diff --quiet HEAD -- platform cai bundle rrp e2e/cmd || echo -dirty)"
  echo "globalsign-est $(git -C "$HOME/dev/globalsign-est" rev-parse --short=12 HEAD)"
  echo "veraison-services $(git -C "$HOME/dev/veraison-services-der" rev-parse --short=12 HEAD)"; } > "$OUT/code-revs.txt"
for f in est-server ca-gateway vault-gateway rup tdx-verifier; do wc -l < "$B/$f.log" > "$OUT/bench-logs/.$f.start"; done
wc -l < "$HOME/veraison-deployment/logs/vts.log" > "$OUT/bench-logs/.vts.start"
wc -l < "$HOME/veraison-deployment/logs/verification.log" > "$OUT/bench-logs/.verification.start"

echo "== build (linux/amd64)"
(cd "$HERE/e2e" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/e2e-attester" ./cmd/e2e-attester \
  && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/caapi-est" ./cmd/caapi-est)
shasum -a 256 "$BIN/e2e-attester" "$BIN/caapi-est" | sed "s#$BIN/##" > "$OUT/binaries.sha256"

echo "== guest configuration (public material only)"
# the Vault gateway takes callers with a certificate of the bench (mutual TLS): the operator's
curl -sf --cacert "$B/tls/root.crt" --cert "$B/tls/clients/operator.crt" --key "$B/tls/clients/operator.key" https://127.0.0.1:9102/tacra/v1/origin-keys > "$BIN/origin-keys.json"
cp "$B/tls/root.crt" "$BIN/bench-tls-root.crt"
TEE="$TEE" B="$B" BIN="$BIN" python3 - <<'PY'
import json, os
B, BIN = os.environ["B"], os.environ["BIN"]
kinds = ["nonce", "epoch", "lepoch", "time", "none"]
targets = [{"target": f"https://db-{k}.tacra.example", "type": "x509"} for k in kinds] + \
          [{"target": f"https://ledger-{k}.tacra.example", "type": "api-key"} for k in kinds]
rp = {t["target"]: ({"enroll": "https://ca1.tacra.example"} if "/db-" in t["target"] else {"retrieve": "https://vault1.tacra.example"}) for t in targets}
cfg = {"tee": os.environ["TEE"], "caapi": "127.0.0.1:50061", "hint": "payments.workload.tacra.example",
       "targets": targets, "relying_parties": rp,
       "vault_origins": {"https://vault1.tacra.example": json.load(open(f"{BIN}/origin-keys.json"))},
       "local_epoch_hex": open(f"{B}/epoch.hex").read().strip(),
       "rup": {"url": "https://localhost:19443", "anchor_pem": open(f"{B}/tls/root.crt").read()}}
json.dump(cfg, open(f"{BIN}/e2e-attester.json", "w"), indent=1)
PY
cp "$BIN/e2e-attester.json" "$OUT/e2e-attester.json"

cleanup() {
  set +e
  [ -n "${TUNNEL:-}" ] && kill "$TUNNEL" 2>/dev/null
  if [ -n "$ID" ]; then
    echo "== terminate $ID"
    aws ec2 terminate-instances --region "$REGION" --instance-ids "$ID" >/dev/null
    aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$ID"
    echo "instance $ID: $(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].State.Name' --output text)" | tee "$OUT/vm-deleted.txt"
    ID=""
  fi
  if [ -n "$SG" ]; then aws ec2 delete-security-group --region "$REGION" --group-id "$SG" && echo "security group $SG deleted" | tee -a "$OUT/vm-deleted.txt"; SG=""; fi
  if [ -n "$KEY" ] && aws ec2 describe-key-pairs --region "$REGION" --key-names "$KEY" >/dev/null 2>&1; then
    aws ec2 delete-key-pair --region "$REGION" --key-name "$KEY" && echo "key pair $KEY deleted" | tee -a "$OUT/vm-deleted.txt"
  fi
  KEY=""
}
trap 'cleanup; rm -rf "$BIN"' EXIT

echo "== key pair, security group (SSH from this address only)"
aws ec2 create-key-pair --region "$REGION" --key-name "$KEY" --key-type ed25519 --query KeyMaterial --output text > "$BIN/key"
chmod 600 "$BIN/key"
VPC="$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
SG="$(aws ec2 create-security-group --region "$REGION" --group-name "$NAME" --description "tacra e2e $STAMP" --vpc-id "$VPC" --query GroupId --output text)"
MYIP="$(curl -sf -m 10 https://checkip.amazonaws.com | tr -d '[:space:]')"
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null

echo "== launch $TYPE in $AZ with AmdSevSnp=enabled"
AMI="$(aws ssm get-parameter --region "$REGION" --name "$AMI_PARAM" --query Parameter.Value --output text)"
SUB="$(aws ec2 describe-subnets --region "$REGION" --filters Name=availability-zone,Values="$AZ" Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)"
ID="$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type "$TYPE" --subnet-id "$SUB" \
  --cpu-options AmdSevSnp=enabled --key-name "$KEY" --security-group-ids "$SG" \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=purpose,Value=tacra-e2e}]" \
  --query 'Instances[0].InstanceId' --output text)"
echo "$REGION $AZ $ID $AMI $TYPE" > "$OUT/instance.txt"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$ID"
IP="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
SSHO=(-i "$BIN/key" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BIN/known_hosts" -o ConnectTimeout=10)
SSH=(ssh "${SSHO[@]}" "ubuntu@$IP")

echo "== wait for ssh"
for i in $(seq 1 40); do "${SSH[@]}" true >/dev/null 2>&1 && break; sleep 10; done
"${SSH[@]}" '
set -e
sudo modprobe sev-guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /sys/kernel/config/tsm/report; uname -r' 2>>"$OUT/ssh.stderr" | tee "$OUT/provision.txt"

echo "== copy the workload, the CAS Client and the public configuration"
scp "${SSHO[@]}" "$BIN/e2e-attester" "$BIN/caapi-est" "$BIN/e2e-attester.json" "$BIN/bench-tls-root.crt" "ubuntu@$IP:~/" >/dev/null 2>>"$OUT/ssh.stderr"

echo "== reverse tunnel to the bench (EST server 18443, mTLS service 19443)"
ssh "${SSHO[@]}" -N -o ExitOnForwardFailure=yes -R 18443:127.0.0.1:18443 -R 19443:127.0.0.1:19443 "ubuntu@$IP" 2>>"$OUT/ssh.stderr" &
TUNNEL=$!
for i in $(seq 1 20); do "${SSH[@]}" 'nc -z 127.0.0.1 18443 && nc -z 127.0.0.1 19443' >/dev/null 2>&1 && break; sleep 3; done

echo "== run in the guest"
NB="$(date -u +%s)"
"${SSH[@]}" '
set -e
nohup ~/caapi-est -listen 127.0.0.1:50061 -est localhost:18443 -anchor ~/bench-tls-root.crt > ~/caapi-est.log 2>&1 &
echo $! > ~/caapi-est.pid
sleep 1
sudo ~/e2e-attester -config ~/e2e-attester.json -out ~/results.json 2>&1
sudo chown $(id -u):$(id -g) ~/results.json; uname -a > ~/kernel.txt
kill "$(cat ~/caapi-est.pid)" || true' 2>>"$OUT/ssh.stderr" | tee "$OUT/e2e-attester-stdout.txt"
NA="$(date -u +%s)"
echo "$NB $NA" > "$OUT/run-window.txt"
scp "${SSHO[@]}" "ubuntu@$IP:~/results.json" "ubuntu@$IP:~/caapi-est.log" "ubuntu@$IP:~/kernel.txt" "$OUT/" >/dev/null 2>>"$OUT/ssh.stderr"
trap 'rm -rf "$BIN"' EXIT
cleanup

echo "== bench logs for the run"
for f in est-server ca-gateway vault-gateway rup tdx-verifier; do tail -n +"$(( $(cat "$OUT/bench-logs/.$f.start") + 1 ))" "$B/$f.log" | grep -v "TLS handshake error" > "$OUT/bench-logs/$f.log" || true; done
tail -n +"$(( $(cat "$OUT/bench-logs/.vts.start") + 1 ))" "$HOME/veraison-deployment/logs/vts.log" | grep -v DEBUG > "$OUT/bench-logs/veraison-vts.log" || true
# Veraison's verification API: who asked for each session (client-ca)
tail -n +"$(( $(cat "$OUT/bench-logs/.verification.start") + 1 ))" "$HOME/veraison-deployment/logs/verification.log" | grep -v DEBUG \
  > "$OUT/bench-logs/veraison-verification.log" || true
rm -f "$OUT"/bench-logs/.*.start
python3 - "$OUT/results.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
ok = sum(1 for x in r if x["ok"])
print(f"{ok} of {len(r)} Targets: credential acquired and admitted by the relying party")
for x in r:
    print(("ok " if x["ok"] else "BAD"), x["target"].ljust(38), x["type"].ljust(8), f'{x["acquire_ms"]:8.1f} ms', x["rup_status"], x.get("error", "")[:120])
PY
(cd "$OUT" && find . -type f ! -name sha256sums.txt | sort | xargs shasum -a 256 > sha256sums.txt)
echo "== evidence in $OUT"
