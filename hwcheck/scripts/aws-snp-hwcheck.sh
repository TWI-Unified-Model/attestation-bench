#!/usr/bin/env bash
# Runs hwrun in a live AMD SEV-SNP guest on AWS EC2 (shared tenancy: reports are VLEK-signed) and verifies what it
# wrote with rrpverify against the veraison-services fork as it is, with the DER and signer-info fixes, and with
# those fixes on go-sev-guest v0.15.0 with AMD's roots for VCEK and VLEK (third_party/veraison-services). Creates
# a throwaway key pair and a security group that admits SSH from this machine's address only, launches one
# instance with AmdSevSnp=enabled, runs hwrun as root (configfs-tsm), copies the output back, terminates the
# instance, deletes the key pair and the group, and checks that all three are gone.
#
#   hwcheck/scripts/aws-snp-hwcheck.sh [REGION] [AZ]
#
# Env: TYPE (default c6a.large), AMI_PARAM (SSM parameter of the image; default Ubuntu 24.04), SSH_USER.
# Cost: one c6a.large for ~10 minutes.
set -euo pipefail
REGION="${1:-us-east-2}"
AZ="${2:-us-east-2a}"
TYPE="${TYPE:-c6a.large}"
AMI_PARAM="${AMI_PARAM:-/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id}"
SSH_USER="${SSH_USER:-ubuntu}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-hwcheck-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
HW="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HW/.." && pwd)"
CODE_REV="$(git -C "$REPO" rev-parse --short=12 HEAD)$(git -C "$REPO" diff --quiet HEAD -- platform cai hwcheck/cmd || echo -dirty)"
OUT="$HW/evidence/${STAMP}-aws-sev-snp"
BIN="$(mktemp -d)"
export AWS_PAGER="" GOWORK=off
mkdir -p "$OUT"
echo "$CODE_REV" > "$OUT/code-rev.txt"
ID="" SG="" KEY="$NAME"

echo "== build hwrun (linux/amd64) and rrpverify (three Veraison builds)"
(cd "$HW" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/hwrun" ./cmd/hwrun)
(cd "$HW" && go build -o "$BIN/rrpverify-fork" ./cmd/rrpverify && go build -modfile=go.patched.mod -o "$BIN/rrpverify-fixed" ./cmd/rrpverify \
  && go build -modfile=go.v015.mod -o "$BIN/rrpverify-v015" ./cmd/rrpverify)
shasum -a 256 "$BIN/hwrun" | awk '{print $1"  hwrun (linux/amd64)"}' > "$OUT/binaries.sha256"
{ # in-process builds: fork = src-fork, fixed = src-der, v015 = src (third_party/veraison-services/UPSTREAM)
  "$REPO/third_party/describe.sh" veraison-services go-gen-ref
  "$REPO/e2e/scripts/veraison-build-info.sh"; } > "$OUT/veraison-revs.txt"

echo "== RRP mints the Freshness Handles; AMD KDS chain for VLEK (ASVK, ARK)"
"$BIN/rrpverify-fork" mint -out "$OUT/handles.json"
curl -sf -m 30 -o "$OUT/amd-kds-milan-vlek-cert_chain.pem" https://kdsintf.amd.com/vlek/v1/Milan/cert_chain

cleanup() {
  set +e
  if [ -n "$ID" ]; then
    echo "== terminate $ID"
    aws ec2 terminate-instances --region "$REGION" --instance-ids "$ID" >/dev/null
    aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$ID"
    st="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].State.Name' --output text)"
    echo "instance $ID: $st" | tee "$OUT/vm-deleted.txt"
    ID=""
  fi
  if [ -n "$SG" ]; then
    aws ec2 delete-security-group --region "$REGION" --group-id "$SG" && echo "security group $SG deleted" | tee -a "$OUT/vm-deleted.txt"
    SG=""
  fi
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
SG="$(aws ec2 create-security-group --region "$REGION" --group-name "$NAME" --description "tacra hwcheck $STAMP" --vpc-id "$VPC" --query GroupId --output text)"
MYIP="$(curl -sf -m 10 https://checkip.amazonaws.com | tr -d '[:space:]')"
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null

echo "== launch $TYPE in $AZ with AmdSevSnp=enabled"
AMI="$(aws ssm get-parameter --region "$REGION" --name "$AMI_PARAM" --query Parameter.Value --output text)"
SUB="$(aws ec2 describe-subnets --region "$REGION" --filters Name=availability-zone,Values="$AZ" Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)"
ID="$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type "$TYPE" --subnet-id "$SUB" \
  --cpu-options AmdSevSnp=enabled --key-name "$KEY" --security-group-ids "$SG" \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=purpose,Value=tacra-hwcheck}]" \
  --query 'Instances[0].InstanceId' --output text)"
echo "$REGION $AZ $ID $AMI $TYPE" | tee "$OUT/instance.txt"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$ID"
IP="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
SSH=(ssh -i "$BIN/key" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BIN/known_hosts" -o ConnectTimeout=10 "$SSH_USER@$IP")
SCP=(scp -i "$BIN/key" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BIN/known_hosts" -o ConnectTimeout=10)

echo "== wait for ssh ($IP)"
for i in $(seq 1 40); do
  if "${SSH[@]}" true >/dev/null 2>&1; then break; fi
  st="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].State.Name' --output text)"
  if [ "$st" != "running" ]; then
    echo "!! instance is $st: $(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].StateReason.Message' --output text)" | tee "$OUT/boot-failure.txt"
    exit 1
  fi
  sleep 10
done

echo "== provision: sev-guest module, configfs-tsm"
"${SSH[@]}" '
set -e
sudo modprobe sev-guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /dev/sev-guest /sys/kernel/config/tsm/report
uname -r
' | tee "$OUT/provision.txt"

echo "== copy hwrun and the handles"
"${SCP[@]}" "$BIN/hwrun" "$OUT/handles.json" "$SSH_USER@$IP:~/" >/dev/null

echo "== run hwrun as root"
NB="$(date -u +%s)"
"${SSH[@]}" "
set -e
sudo ~/hwrun -handles ~/handles.json -out /root/hwrun-out -burst 100 2>&1
sudo sh -c 'cd /root/hwrun-out && uname -a > kernel.txt && (dmesg 2>/dev/null | grep -i -E \"sev|snp|tsm\" > dmesg-sev.txt || true) && date -u +%s > guest-clock.txt'
rm -rf ~/hwrun-out; sudo cp -r /root/hwrun-out ~/hwrun-out; sudo chown -R \$(id -u):\$(id -g) ~/hwrun-out
" | tee "$OUT/hwrun-stdout.txt"
NA="$(date -u +%s)"
echo "$NB $NA" > "$OUT/rrp-clock-window.txt"

echo "== copy the output back"
"${SCP[@]}" -r "$SSH_USER@$IP:~/hwrun-out/*" "$OUT/" >/dev/null
trap 'rm -rf "$BIN"' EXIT
cleanup

echo "== RRP verification: Veraison fork as it is, with the DER and signer-info fixes, and on v0.15.0 with AMD roots"
for v in fork fixed v015; do
  "$BIN/rrpverify-$v" verify -in "$OUT" -handles "$OUT/handles.json" -ark "$OUT/amd-kds-milan-vlek-cert_chain.pem" \
    -not-before "$NB" -not-after "$NA" -out "$OUT/rrpverify-veraison-$v.json" | tee "$OUT/rrpverify-veraison-$v.txt"
done
if curl -sf --cacert "$HOME/veraison-deployment/certs/rootCA.crt" --cert "${TACRA_BENCH:-$HOME/tacra-bench}/tls/clients/ca-gateway.crt" \
  --key "${TACRA_BENCH:-$HOME/tacra-bench}/tls/clients/ca-gateway.key" https://localhost:8443/.well-known/veraison/verification >/dev/null 2>&1; then
  echo "== RRP verification through the deployed Veraison service (https://localhost:8443)"
  "$BIN/rrpverify-fixed" service -in "$OUT" -handles "$OUT/handles.json" -not-before "$NB" -not-after "$NA" \
    -out "$OUT/rrpverify-service.json" | tee "$OUT/rrpverify-service.txt"
fi
(cd "$OUT" && find . -type f ! -name sha256sums.txt | sort | xargs shasum -a 256 > sha256sums.txt)
echo "== evidence in $OUT"
