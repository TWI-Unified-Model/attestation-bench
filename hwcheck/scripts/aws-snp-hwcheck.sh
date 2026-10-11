#!/usr/bin/env bash
# Runs hwrun in a live AMD SEV-SNP guest on AWS EC2 (shared tenancy: reports are VLEK-signed) and verifies what it
# wrote with rrpverify against the veraison-services fork as it is, with the DER and signer-info fixes, and with those
# fixes on go-sev-guest v0.15.0 with AMD's roots for VCEK and VLEK (third_party/veraison-services). Creates a
# throwaway key pair and a security group that admits SSH from this machine's address only, launches one instance with
# AmdSevSnp=enabled, runs hwrun as root (configfs-tsm), records what the guest's clock rests on and its offset from
# this machine's, makes Evidence with the guest's clock moved (the pre-play check: ahead, every Freshness Kind, the
# Handles minted by the live RRPs; behind, absent-timestamp), copies the output back, terminates the instance, deletes
# the key pair and the group, and checks that all three are gone. Then the RRP's checks, through the bench's live
# Veraison too, and, beside them, the pre-play Evidence presented to the live RRPs (hwcheck/scripts/preplay.py).
#
#   hwcheck/scripts/aws-snp-hwcheck.sh        (make attacks PLATFORM=aws-snp)
#
# AWS_REGION, AWS_AZ: where the instance goes (scripts/lib.sh). RUNS_DIR: where the run directory goes (default
# BENCH_HOME/runs). Env: TYPE (default c6a.large), AMI_PARAM (SSM parameter of the image; default Ubuntu 24.04),
# SSH_USER. Needs the running bench (make setup). Cost: one c6a.large for ~15 minutes.
# The run ends with its verdict (scripts/verdict.py) and exits 1 unless every check came out as expected.
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"   # BENCH_HOME, VERAISON_DEPLOYMENT, pinned tools
[ $# -eq 0 ] || bench_die "no arguments: the region and zone come from AWS_REGION and AWS_AZ (scripts/lib.sh)"
bench_aws
bench_require_up # the checks through the live Veraison, and the pre-play, need the trust zone
REGION="$AWS_REGION" AZ="$AWS_AZ"
AHEAD=300 # how far ahead the guest's clock is set for the pre-play, in seconds
TYPE="${TYPE:-c6a.large}"
AMI_PARAM="${AMI_PARAM:-/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id}"
SSH_USER="${SSH_USER:-ubuntu}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-hwcheck-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
HW="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HW/.." && pwd)"
CODE_REV="$(git -C "$REPO" rev-parse --short=12 HEAD)$(git -C "$REPO" diff --quiet HEAD -- platform cai hwcheck/cmd || echo -dirty)"
RUNS_DIR="${RUNS_DIR:-$BENCH_HOME/runs}"
OUT="$RUNS_DIR/${STAMP}-aws-sev-snp${BIND_RRP_ID:+-bind-rrp-id}"
# The guest binds no RRP identifier and rrpverify expects none: the group's decision of 6 October 2026 (rats-tacra#20), the
# default since 11 October. BIND_RRP_ID=1: the measured variant, the identifiers bound (the bench's RRPs must bind them too,
# BIND_RRP_ID=1 e2e/scripts/bench.sh config, and so must the EST server, which the group's code no longer does).
RRP_FLAGS="-rrp-ca '' -rrp-vault ''"; RRPV=(-rrp-ca "" -rrp-vault ""); PREPLAY_BIND=""
if [ -n "${BIND_RRP_ID:-}" ]; then RRP_FLAGS="-rrp-ca https://ca1.tacra.example -rrp-vault https://vault1.tacra.example"; RRPV=(-rrp-ca https://ca1.tacra.example -rrp-vault https://vault1.tacra.example); PREPLAY_BIND=with-rrp-id; fi
BIN="$(mktemp -d)"
mkdir -p "$OUT"
echo "$CODE_REV" > "$OUT/code-rev.txt"
ID="" SG="" KEY="$NAME"

echo "== build hwrun (linux/amd64) and rrpverify (three Veraison builds)"
(cd "$HW" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/hwrun" ./cmd/hwrun)
(cd "$REPO/rrp" && GOWORK=off go build -o "$BIN/platform-check" ./cmd/platform-check)
(cd "$HW" && go build -o "$BIN/rrpverify-fork" ./cmd/rrpverify && go build -modfile=go.patched.mod -o "$BIN/rrpverify-fixed" ./cmd/rrpverify \
  && go build -modfile=go.v015.mod -o "$BIN/rrpverify-v015" ./cmd/rrpverify)
shasum -a 256 "$BIN/hwrun" | awk '{print $1"  hwrun (linux/amd64)"}' > "$OUT/binaries.sha256"
{ # in-process builds: fork = src-fork, fixed = src-der, v015 = src (third_party/veraison-services/UPSTREAM)
  "$REPO/third_party/describe.sh" veraison-services go-gen-ref
  cat "$BENCH_HOME/est-source.txt" 2>/dev/null
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
    echo "instance $ID: $st at $(bench_now)" | tee "$OUT/vm-deleted.txt"
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
for _ in $(seq 1 40); do
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

echo "== copy hwrun, the handles and the guest's scripts"
bench_retry "$OUT/run-ssh.stderr" "${SCP[@]}" "$BIN/hwrun" "$OUT/handles.json" "$HW/scripts/guest-clock.sh" \
  "$HW/scripts/preplay-guest.sh" "$SSH_USER@$IP:~/" >/dev/null

echo "== run hwrun as root"
NB="$(date -u +%s)"
# detached from the SSH session: one that breaks costs a call, not the run (scripts/lib.sh)
bench_guest_run "$OUT/run-ssh.stderr" "
set -e
sudo ~/hwrun -handles ~/handles.json -out /root/hwrun-out -burst 100 $RRP_FLAGS 2>&1
sudo sh -c 'cd /root/hwrun-out && uname -a > kernel.txt && (dmesg 2>/dev/null | grep -i -E \"sev|snp|tsm\" > dmesg-sev.txt || true) && date -u +%s > guest-clock.txt'
sudo bash ~/guest-clock.sh /root/hwrun-out
rm -rf ~/hwrun-out; sudo cp -r /root/hwrun-out ~/hwrun-out; sudo chown -R \$(id -u):\$(id -g) ~/hwrun-out
" "${SSH[@]}" | tee "$OUT/hwrun-stdout.txt"
NA="$(date -u +%s)"
echo "$NB $NA" > "$OUT/rrp-clock-window.txt"
bench_clock_offset "$OUT/clock-offset.txt" "${SSH[@]}"
cat "$OUT/clock-offset.txt"

echo "== pre-play: Evidence made with the guest's clock $AHEAD s ahead (every kind) and $AHEAD s behind (absent-timestamp)"
python3 "$HW/scripts/preplay.py" prepare "$OUT" # the Handles the live RRPs mint for it: they live expires_in seconds
for f in handles ca-targets vault-targets; do cp "$OUT/preplay/$f.json" "$BIN/preplay-$f.json"; done
bench_retry "$OUT/run-ssh.stderr" "${SCP[@]}" "$BIN"/preplay-*.json "$SSH_USER@$IP:~/" >/dev/null
PB="$(date -u +%s)"
bench_guest_run "$OUT/run-ssh.stderr" "
set -e
sudo bash ~/preplay-guest.sh $AHEAD /root/preplay/ahead sev-snp all $PREPLAY_BIND 2>&1
sudo bash ~/preplay-guest.sh -$AHEAD /root/preplay/behind sev-snp absent-timestamp $PREPLAY_BIND 2>&1
rm -rf ~/preplay; sudo cp -r /root/preplay ~/preplay; sudo chown -R \$(id -u):\$(id -g) ~/preplay
" "${SSH[@]}" | tee "$OUT/preplay-stdout.txt"
PA="$(date -u +%s)"

echo "== copy the output back"
bench_retry "$OUT/run-ssh.stderr" "${SCP[@]}" -r "$SSH_USER@$IP:~/hwrun-out/*" "$OUT/" >/dev/null
mkdir -p "$OUT/preplay"
bench_retry "$OUT/run-ssh.stderr" "${SCP[@]}" -r "$SSH_USER@$IP:~/preplay/*" "$OUT/preplay/" >/dev/null
echo "$PB $PA" > "$OUT/preplay/rrp-clock-window.txt"
echo "== pre-play: its Evidence offered to the live RRPs now, then at the absent-timestamp window's edges"
python3 "$HW/scripts/preplay.py" present "$OUT" >"$OUT/preplay.txt" 2>&1 &
PREPLAY=$!
trap 'rm -rf "$BIN"' EXIT
cleanup

echo "== RRP verification: Veraison fork as it is, with the DER and signer-info fixes, and on v0.15.0 with AMD roots"
for v in fork fixed v015; do
  # its log (standard error) holds Veraison's own lines, the revocation check of each appraisal among them
  "$BIN/rrpverify-$v" verify -in "$OUT" -handles "$OUT/handles.json" -ark "$OUT/amd-kds-milan-vlek-cert_chain.pem" ${RRPV[@]+"${RRPV[@]}"} \
    -not-before "$NB" -not-after "$NA" -out "$OUT/rrpverify-veraison-$v.json" 2>"$OUT/rrpverify-veraison-$v.stderr.log" \
    | tee "$OUT/rrpverify-veraison-$v.txt"
done
echo "== RRP verification through the deployed Veraison service (https://localhost:8443)"
"$BIN/rrpverify-fixed" service -in "$OUT" -handles "$OUT/handles.json" -not-before "$NB" -not-after "$NA" ${RRPV[@]+"${RRPV[@]}"} \
  -out "$OUT/rrpverify-service.json" -save-ears "$OUT/ears" | tee "$OUT/rrpverify-service.txt"
echo "== the RRPs' platform rule on the honest Attestation Results: the bench's, a bank's, one step stricter"
# the platform rule the RRPs apply (trust/platform-policy.json, as scripts/trustzone.py gave it to them)
python3 -c "import json,sys; json.dump(json.load(open(sys.argv[1])).get('platform'), sys.stdout, indent=1)" \
  "$BENCH_HOME/config/vault-gateway.json" > "$OUT/platform-rule.json"
"$BIN/platform-check" -ears "$OUT/ears" -rule "$OUT/platform-rule.json" -submod SEVSNP \
  -out "$OUT/rrpverify-platform.json" | tee "$OUT/rrpverify-platform.txt"
echo "== pre-play: its last answers (an absent-timestamp window closes max_age seconds after its timestamp)"
wait "$PREPLAY" || true # verdict.py judges what it wrote
cat "$OUT/preplay.txt"
rc=0
python3 "$BENCH_REPO/scripts/verdict.py" attacks "$OUT" --out "$OUT/verdict.txt" || rc=$?
bench_seal "$OUT"
echo "== run directory: $OUT"
exit "$rc"
