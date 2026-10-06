#!/usr/bin/env bash
# The #19/#20 redirection experiment on real hardware, through the deployed gateways. In a confidential guest, the
# Attester produces one Evidence for a Target that the honest EST server routes to ca1. The conduit (rrp-issue) then
# offers that same Evidence to ca1 and to a second Credential Authority, ca2, and we record which issues. Two passes:
# with the RRP identifier in the binding (both CAs bind their own), and without it (OMIT_RRP_ID=1, both bind none).
# This measures, per Freshness Kind, what the RRP identifier prevents.
#
#   hwcheck/scripts/redirect.sh gcp-snp|gcp-tdx|aws-snp
#
# The guest only runs hwrun (offline); all gateway interaction is on this machine, where the bench runs. The bench is
# reconfigured between passes (OMIT_RRP_ID) and left in background-check mode, no omit, at the end.
set -euo pipefail
CLOUD="${1:?usage: redirect.sh gcp-snp|gcp-tdx|aws-snp}"
HW="$(cd "$(dirname "$0")/.." && pwd)"; REPO="$(cd "$HW/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-redir-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
OUT="$HW/evidence/${STAMP}-${CLOUD}-redirect"; BIN="$(mktemp -d)"
CA1=https://127.0.0.1:9101; CA2=https://127.0.0.1:9103
CA1_ID=https://ca1.tacra.example; CA2_ID=https://ca2.tacra.example
B="${TACRA_BENCH:-$HOME/tacra-bench}"; CERT="$B/tls/clients/est-server.crt"; KEY_C="$B/tls/clients/est-server.key"; ROOT="$B/tls/root.crt"
export CLOUDSDK_CORE_DISABLE_PROMPTS=1 GOWORK=off
mkdir -p "$OUT"
git -C "$REPO" rev-parse --short=12 HEAD > "$OUT/code-rev.txt"
"$REPO/e2e/scripts/veraison-build-info.sh" > "$OUT/veraison-build.txt"  # the Verifier the gateways ask (SEV-SNP)
ORDER=(nonce epoch lepoch time none)  # short name of each Target; fresh_of maps it to the Freshness Kind (bash 3.2: no associative arrays)
fresh_of() { case "$1" in nonce) echo present-nonce;; epoch) echo present-epoch;; lepoch) echo absent-epoch;; time) echo absent-timestamp;; none) echo absent-none;; esac; }

case "$CLOUD" in
  gcp-snp) TEE=sev-snp; ZONE=us-central1-c; MACHINE=(--machine-type=n2d-standard-2 --min-cpu-platform="AMD Milan" --confidential-compute-type=SEV_SNP);;
  gcp-tdx) TEE=tdx;     ZONE=us-central1-a; MACHINE=(--machine-type=c3-standard-4 --confidential-compute-type=TDX);;
  aws-snp) TEE=sev-snp; REGION=us-east-2; AZ=us-east-2a; TYPE=c6a.large;;
  *) echo "unknown cloud $CLOUD" >&2; exit 2;;
esac

echo "== build hwrun (linux/amd64) and rrp-issue"
(cd "$HW" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/hwrun" ./cmd/hwrun)
(cd "$HW" && go build -o "$BIN/rrp-issue" ./cmd/rrp-issue)
shasum -a 256 "$BIN/hwrun" | awk '{print $1"  hwrun (linux/amd64)"}' > "$OUT/binaries.sha256"

# --- cloud glue: GUEST_SSH "<cmd>", GUEST_SCP_IN <files...> dst, GUEST_SCP_OUT src dst, vm_create, vm_delete ---
if [ "${CLOUD#gcp}" != "$CLOUD" ]; then
  GSSH=(gcloud compute ssh "$NAME" --project=rats-probe --zone="$ZONE" --command)
  vm_create() {
    echo "== create $NAME ($ZONE, $TEE)"
    gcloud compute instances create "$NAME" --project=rats-probe --zone="$ZONE" "${MACHINE[@]}" \
      --maintenance-policy=TERMINATE --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
      --boot-disk-size=20GB --labels=purpose=tacra-redir --metadata=enable-oslogin=TRUE >/dev/null
  }
  vm_delete() {
    gcloud compute instances delete "$NAME" --project=rats-probe --zone="$ZONE" --quiet >/dev/null 2>&1 || true
    left="$(gcloud compute instances list --project=rats-probe --filter="name=$NAME" --format='value(name)' 2>/dev/null)"
    [ -z "$left" ] && echo "$NAME is gone" | tee "$OUT/vm-deleted.txt" || echo "!! $NAME still exists"
  }
  guest_ssh() { "${GSSH[@]}" "$1" ; }
  guest_in()  { gcloud compute scp "$@" "$NAME:~/" --project=rats-probe --zone="$ZONE" >/dev/null ; }
  guest_out() { gcloud compute scp --recurse "$NAME:~/$1" "$2" --project=rats-probe --zone="$ZONE" >/dev/null ; }
  wait_ssh()  { for i in $(seq 1 30); do guest_ssh true >/dev/null 2>&1 && return 0; sleep 10; done; return 1; }
else
  vm_create() {
    echo "== launch $NAME ($REGION/$AZ, $TYPE, SEV-SNP)"
    aws ec2 create-key-pair --region "$REGION" --key-name "$NAME" --key-type ed25519 --query KeyMaterial --output text > "$BIN/key"
    chmod 600 "$BIN/key"
    VPC="$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
    SG="$(aws ec2 create-security-group --region "$REGION" --group-name "$NAME" --description "tacra redir" --vpc-id "$VPC" --query GroupId --output text)"
    MYIP="$(curl -sf -m 10 https://checkip.amazonaws.com | tr -d '[:space:]')"
    aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null
    AMI="$(aws ssm get-parameter --region "$REGION" --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)"
    SUB="$(aws ec2 describe-subnets --region "$REGION" --filters Name=availability-zone,Values="$AZ" Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)"
    ID="$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type "$TYPE" --subnet-id "$SUB" \
      --key-name "$NAME" --security-group-ids "$SG" --cpu-options AmdSevSnp=enabled \
      --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=20}' \
      --tag-specifications 'ResourceType=instance,Tags=[{Key=purpose,Value=tacra-redir}]' --query 'Instances[0].InstanceId' --output text)"
    echo "$REGION $AZ $ID $AMI $TYPE" > "$OUT/instance.txt"
    aws ec2 wait instance-running --region "$REGION" --instance-ids "$ID"
    IP="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
    SSHC=(ssh -i "$BIN/key" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BIN/known_hosts" -o ConnectTimeout=10 "ubuntu@$IP")
    SCPC=(scp -i "$BIN/key" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$BIN/known_hosts" -o ConnectTimeout=10)
  }
  vm_delete() {
    [ -n "${ID:-}" ] && { aws ec2 terminate-instances --region "$REGION" --instance-ids "$ID" >/dev/null; aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$ID"; \
      echo "instance $ID terminated" | tee "$OUT/vm-deleted.txt"; }
    [ -n "${SG:-}" ] && aws ec2 delete-security-group --region "$REGION" --group-id "$SG" >/dev/null 2>&1 && echo "security group deleted" | tee -a "$OUT/vm-deleted.txt" && SG=""
    aws ec2 delete-key-pair --region "$REGION" --key-name "$NAME" >/dev/null 2>&1 && echo "key pair deleted" | tee -a "$OUT/vm-deleted.txt"
  }
  guest_ssh() { "${SSHC[@]}" "$1" ; }
  guest_in()  { "${SCPC[@]}" "$@" "ubuntu@$IP:~/" >/dev/null ; }
  guest_out() { "${SCPC[@]}" -r "ubuntu@$IP:~/$1" "$2" >/dev/null ; }
  wait_ssh()  { for i in $(seq 1 40); do guest_ssh true >/dev/null 2>&1 && return 0; sleep 10; done; return 1; }
fi
trap 'vm_delete; rm -rf "$BIN"' EXIT

PROVISION='set -e
if [ "'"$TEE"'" = tdx ]; then :; else sudo modprobe sev-guest 2>/dev/null || true; if [ ! -e /dev/sev-guest ]; then sudo apt-get update -qq >/dev/null; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-modules-extra-$(uname -r) >/dev/null; sudo modprobe sev-guest || true; fi; fi
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /sys/kernel/config/tsm/report; uname -r'

# mint a present-nonce Handle from ca1 for db-nonce; print it (base64url, as ca1 returned it)
mint_nonce() {
  curl -s --cacert "$ROOT" --cert "$CERT" --key "$KEY_C" -H 'Content-Type: application/json' \
    -d '{"target":"https://db-nonce.tacra.example","credential_type":"x509"}' "$CA1/tacra/v1/initiate" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['handle'])"
}

# run_pass PASS RRPCA : mint, make Evidence in the guest bound to RRPCA, then offer each case to ca1 and ca2
run_pass() {
  local PASS="$1" RRPCA="$2" d="$OUT/$1"; mkdir -p "$d"
  local nonce epoch; nonce="$(mint_nonce)"; epoch="$(tr -d '[:space:]' < "$B/epoch.hex")"
  python3 - "$nonce" "$epoch" "$d" <<'PY'
import sys, json, base64, os, secrets
nonce_url, epoch_hex, d = sys.argv[1], sys.argv[2], sys.argv[3]
std = lambda b: base64.b64encode(b).decode()
nonce = base64.urlsafe_b64decode(nonce_url + "=" * (-len(nonce_url) % 4))
json.dump({"nonce_enroll": std(nonce), "nonce_retrieve": std(secrets.token_bytes(32)),
           "epoch": std(bytes.fromhex(epoch_hex))}, open(os.path.join(d, "handles.json"), "w"))
json.dump({"present-nonce": "https://db-nonce.tacra.example", "present-epoch": "https://db-epoch.tacra.example",
           "absent-epoch": "https://db-lepoch.tacra.example", "absent-timestamp": "https://db-time.tacra.example",
           "absent-none": "https://db-none.tacra.example"}, open(os.path.join(d, "targets.json"), "w"))
PY
  guest_in "$BIN/hwrun" "$d/handles.json" "$d/targets.json"
  guest_ssh "set -e
sudo ~/hwrun -tee $TEE -targets ~/targets.json -handles ~/handles.json -rrp-ca '$RRPCA' -csr-cn payments.workload.tacra.example -out /root/redir 2>&1
sudo chmod -R a+rX /root/redir; rm -rf ~/redir; sudo cp -r /root/redir ~/redir; sudo chown -R \$(id -u):\$(id -g) ~/redir" \
    2>>"$OUT/run-ssh.stderr" | tee -a "$OUT/hwrun-stdout.txt"
  guest_out redir "$d/"
  local k fresh tgt ev subj handle res
  : > "$d/results.jsonl"
  for k in "${ORDER[@]}"; do
    fresh="$(fresh_of "$k")"; tgt="https://db-${k}.tacra.example"
    ev="$d/redir/enroll-${fresh}/evidence.tsm.cbor"; subj="$d/redir/enroll-${fresh}/subject.der"
    handle="$(python3 -c "import json;print(json.load(open('$d/redir/enroll-${fresh}/meta.json')).get('freshness_element_b64',''))")"
    for rrp in ca1 ca2; do
      url="$CA1"; [ "$rrp" = ca2 ] && url="$CA2"
      res="$("$BIN/rrp-issue" enroll -url "$url" -target "$tgt" -ctype x509 -kind "$fresh" \
        ${handle:+-handle "$handle"} -evidence "$ev" -csr "$subj" -ca "$ROOT" -cert "$CERT" -key "$KEY_C")"
      echo "{\"pass\":\"$PASS\",\"kind\":\"$fresh\",\"rrp\":\"$rrp\",\"result\":$res}" >> "$d/results.jsonl"
      echo "  $PASS $fresh -> $rrp : $(echo "$res" | python3 -c "import sys,json;d=json.load(sys.stdin);print('ISSUED' if d['issued'] else 'refused', d.get('reason',d.get('cert_serial','')))")"
    done
  done
}

reconfigure() { # $1 = "omit" or "normal"
  local omit=""; [ "$1" = omit ] && omit=1
  bash "$REPO/e2e/scripts/bench.sh" stop >/dev/null 2>&1 || true
  RATS_MODEL=background-check OMIT_RRP_ID="$omit" bash "$REPO/e2e/scripts/bench.sh" config >/dev/null 2>&1
  bash "$REPO/e2e/scripts/bench.sh" start >/dev/null 2>&1
}

echo "== bench: background-check, RRP identifier IN the binding"
reconfigure normal
vm_create
wait_ssh || { echo "ssh never came up" >&2; exit 1; }
guest_ssh "$PROVISION" 2>>"$OUT/run-ssh.stderr"
run_pass with-rrp-id "$CA1_ID"

echo "== bench: background-check, NO RRP identifier in the binding"
reconfigure omit
run_pass no-rrp-id ""

vm_delete; trap 'rm -rf "$BIN"' EXIT
echo "== bench: back to background-check, no omit"
reconfigure normal

cat "$OUT"/*/results.jsonl > "$OUT/results.jsonl"
(cd "$OUT" && find . -type f ! -name sha256sums.txt | sort | xargs shasum -a 256 > sha256sums.txt)
echo "== evidence in $OUT"
python3 - "$OUT/results.jsonl" <<'PY'
import sys, json
rows = [json.loads(l) for l in open(sys.argv[1])]
print(f"{'pass':12} {'kind':18} {'ca1':8} {'ca2':8}")
by = {}
for r in rows: by[(r['pass'], r['kind'], r['rrp'])] = r['result']['issued']
seen = []
for (p, k, _) in by:
    if (p, k) in seen: continue
    seen.append((p, k))
    print(f"{p:12} {k:18} {'ISSUED' if by[(p,k,'ca1')] else 'refused':8} {'ISSUED' if by[(p,k,'ca2')] else 'refused':8}")
PY
