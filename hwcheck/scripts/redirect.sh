#!/usr/bin/env bash
# The #19/#20 redirection experiment on real hardware, through the deployed gateways. In a confidential guest, the
# Attester produces one Evidence for a Target that the honest EST server routes to ca1. The conduit (rrp-issue) then
# offers that same Evidence to ca1 and to a second Credential Authority, ca2, and we record which issues. Two passes:
# with the RRP identifier in the binding (both CAs bind their own), and without it (OMIT_RRP_ID=1, both bind none).
# This measures, per Freshness Kind, what the RRP identifier prevents.
#
#   hwcheck/scripts/redirect.sh gcp-snp|gcp-tdx|aws-snp|local      (make redirect PLATFORM=...)
#
# The guest only runs hwrun (offline); all gateway interaction is on this machine, where the bench runs. "local" runs
# hwrun here with the bench's software stand-in TEE (no VM, no cost, no security). The bench runs both passes in
# Background Check, reconfigured between them (OMIT_RRP_ID), and is put back as it was however the run ends: its RATS
# model, the RRP identifier in the binding.
#
# GCP_PROJECT, GCP_ZONE, AWS_REGION, AWS_AZ: where the VM goes (scripts/lib.sh). RUNS_DIR: where the run directory
# goes (default BENCH_HOME/runs). The run ends with its verdict (scripts/verdict.py) and exits 1 unless every outcome
# is the one the experiment expects.
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"   # BENCH_HOME, VERAISON_DEPLOYMENT, pinned tools
CLOUD="${1:?usage: redirect.sh gcp-snp|gcp-tdx|aws-snp|local}"
case "$CLOUD" in
  gcp-snp) TEE=sev-snp; MACHINE=(--machine-type=n2d-standard-2 --min-cpu-platform="AMD Milan" --confidential-compute-type=SEV_SNP);;
  gcp-tdx) TEE=tdx;     MACHINE=(--machine-type=c3-standard-4 --confidential-compute-type=TDX);;
  aws-snp) TEE=sev-snp; TYPE=c6a.large;;
  local)   TEE=sim;;
  *) echo "unknown cloud $CLOUD" >&2; exit 2;;
esac
case "$CLOUD" in
  gcp-*) bench_gcp; ZONE="$GCP_ZONE";;
  aws-*) bench_aws; REGION="$AWS_REGION"; AZ="$AWS_AZ";;
esac
HW="$(cd "$(dirname "$0")/.." && pwd)"; REPO="$(cd "$HW/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-redir-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
RUNS_DIR="${RUNS_DIR:-$BENCH_HOME/runs}"
OUT="$RUNS_DIR/${STAMP}-${CLOUD}-redirect"; BIN="$(mktemp -d)"
CA1=https://127.0.0.1:9101; CA2=https://127.0.0.1:9103
CA1_ID=https://ca1.tacra.example   # the RRP identifier the honest EST server's Credential Authority binds
B="$BENCH_HOME"; CERT="$B/tls/clients/est-server.crt"; KEY_C="$B/tls/clients/est-server.key"; ROOT="$B/tls/root.crt"
mkdir -p "$OUT"
git -C "$REPO" rev-parse --short=12 HEAD > "$OUT/code-rev.txt"
MODEL_BEFORE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("rats_model") or "passport")' \
  "$B/config/vault-gateway.json")"
RECONFIGURED=""
restore_bench() { # the bench as it was before the experiment; nothing to do until reconfigure has run
  [ -n "$RECONFIGURED" ] || return 0
  bash "$REPO/e2e/scripts/bench.sh" stop >/dev/null 2>&1 || true
  RATS_MODEL="$MODEL_BEFORE" OMIT_RRP_ID="" bash "$REPO/e2e/scripts/bench.sh" config >/dev/null 2>&1
  bash "$REPO/e2e/scripts/bench.sh" start >/dev/null 2>&1
  RECONFIGURED=""
}
"$REPO/e2e/scripts/veraison-build-info.sh" > "$OUT/veraison-build.txt"  # the Verifier the gateways ask (SEV-SNP)
ORDER=(nonce epoch lepoch time none)  # short name of each Target; fresh_of maps it to the Freshness Kind (bash 3.2: no associative arrays)
fresh_of() { case "$1" in nonce) echo present-nonce;; epoch) echo present-epoch;; lepoch) echo absent-epoch;; time) echo absent-timestamp;; none) echo absent-none;; esac; }

echo "== build hwrun and rrp-issue"
if [ "$CLOUD" = local ]; then
  (cd "$HW" && go build -trimpath -o "$BIN/hwrun" ./cmd/hwrun)
  shasum -a 256 "$BIN/hwrun" | awk '{print $1"  hwrun (this machine; -tee sim)"}' > "$OUT/binaries.sha256"
  echo "software stand-in TEE (platform.SimTEE): no hardware, no isolation, no security" > "$OUT/platform.txt"
else
  (cd "$HW" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/hwrun" ./cmd/hwrun)
  shasum -a 256 "$BIN/hwrun" | awk '{print $1"  hwrun (linux/amd64)"}' > "$OUT/binaries.sha256"
fi
(cd "$HW" && go build -o "$BIN/rrp-issue" ./cmd/rrp-issue)

# --- cloud glue: GUEST_SSH "<cmd>", GUEST_SCP_IN <files...> dst, GUEST_SCP_OUT src dst, vm_create, vm_delete ---
if [ "$CLOUD" = local ]; then
  vm_create() { echo "== local: the software stand-in TEE on this machine, no VM"; }
  vm_delete() { :; }
  wait_ssh()  { return 0; }
elif [ "${CLOUD#gcp}" != "$CLOUD" ]; then
  GSSH=(gcloud compute ssh "$NAME" --project="$GCP_PROJECT" --zone="$ZONE" --command)
  vm_create() {
    echo "== create $NAME ($ZONE, $TEE)"
    gcloud compute instances create "$NAME" --project="$GCP_PROJECT" --zone="$ZONE" "${MACHINE[@]}" \
      --maintenance-policy=TERMINATE --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
      --boot-disk-size=20GB --labels=purpose=tacra-redir --metadata=enable-oslogin=TRUE >/dev/null
  }
  vm_delete() {
    gcloud compute instances delete "$NAME" --project="$GCP_PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1 || true
    left="$(gcloud compute instances list --project="$GCP_PROJECT" --filter="name=$NAME" --format='value(name)' 2>/dev/null)"
    [ -z "$left" ] && echo "$NAME is gone at $(bench_now)" | tee "$OUT/vm-deleted.txt" || echo "!! $NAME still exists"
  }
  guest_ssh() { "${GSSH[@]}" "$1" ; }
  guest_in()  { bench_retry "$OUT/run-ssh.stderr" gcloud compute scp "$@" "$NAME:~/" --project="$GCP_PROJECT" --zone="$ZONE" >/dev/null ; }
  guest_out() { bench_retry "$OUT/run-ssh.stderr" gcloud compute scp --recurse "$NAME:~/$1" "$2" --project="$GCP_PROJECT" --zone="$ZONE" >/dev/null ; }
  wait_ssh()  { for _ in $(seq 1 30); do guest_ssh true >/dev/null 2>&1 && return 0; sleep 10; done; return 1; }
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
      echo "instance $ID terminated at $(bench_now)" | tee "$OUT/vm-deleted.txt"; }
    [ -n "${SG:-}" ] && aws ec2 delete-security-group --region "$REGION" --group-id "$SG" >/dev/null 2>&1 && echo "security group deleted" | tee -a "$OUT/vm-deleted.txt" && SG=""
    aws ec2 delete-key-pair --region "$REGION" --key-name "$NAME" >/dev/null 2>&1 && echo "key pair deleted" | tee -a "$OUT/vm-deleted.txt"
  }
  guest_ssh() { "${SSHC[@]}" "$1" ; }
  guest_in()  { bench_retry "$OUT/run-ssh.stderr" "${SCPC[@]}" "$@" "ubuntu@$IP:~/" >/dev/null ; }
  guest_out() { bench_retry "$OUT/run-ssh.stderr" "${SCPC[@]}" -r "ubuntu@$IP:~/$1" "$2" >/dev/null ; }
  wait_ssh()  { for _ in $(seq 1 40); do guest_ssh true >/dev/null 2>&1 && return 0; sleep 10; done; return 1; }
fi
trap 'vm_delete; restore_bench; rm -rf "$BIN"' EXIT

# shellcheck disable=SC2016  # the $ in the single-quoted script expands in the guest, not here
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
  if [ "$CLOUD" = local ]; then
    "$BIN/hwrun" -tee sim -sim-key "$B/secrets/sim-tee-ak.jwk" -sim-measurement "$(tr -d '[:space:]' < "$B/sim-measurement.hex")" \
      -targets "$d/targets.json" -handles "$d/handles.json" -rrp-ca "$RRPCA" -csr-cn payments.workload.tacra.example \
      -out "$d/redir" 2>&1 | tee -a "$OUT/hwrun-stdout.txt"
  else
  guest_in "$BIN/hwrun" "$d/handles.json" "$d/targets.json"
  guest_ssh "set -e
sudo ~/hwrun -tee $TEE -targets ~/targets.json -handles ~/handles.json -rrp-ca '$RRPCA' -csr-cn payments.workload.tacra.example -out /root/redir 2>&1
sudo chmod -R a+rX /root/redir; rm -rf ~/redir; sudo cp -r /root/redir ~/redir; sudo chown -R \$(id -u):\$(id -g) ~/redir" \
    2>>"$OUT/run-ssh.stderr" | tee -a "$OUT/hwrun-stdout.txt"
  guest_out redir "$d/"
  fi
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
  RECONFIGURED=1
  bash "$REPO/e2e/scripts/bench.sh" stop >/dev/null 2>&1 || true
  RATS_MODEL=background-check OMIT_RRP_ID="$omit" bash "$REPO/e2e/scripts/bench.sh" config >/dev/null 2>&1
  bash "$REPO/e2e/scripts/bench.sh" start >/dev/null 2>&1
}

echo "== bench: background-check, RRP identifier IN the binding"
reconfigure normal
vm_create
wait_ssh || { echo "ssh never came up" >&2; exit 1; }
[ "$CLOUD" = local ] || guest_ssh "$PROVISION" 2>>"$OUT/run-ssh.stderr"
run_pass with-rrp-id "$CA1_ID"

echo "== bench: background-check, NO RRP identifier in the binding"
reconfigure omit
run_pass no-rrp-id ""

vm_delete; trap 'restore_bench; rm -rf "$BIN"' EXIT
echo "== bench: back as it was ($MODEL_BEFORE, the RRP identifier in the binding)"
restore_bench

cat "$OUT"/*/results.jsonl > "$OUT/results.jsonl"
rc=0
python3 "$REPO/scripts/verdict.py" redirect "$OUT" --out "$OUT/verdict.txt" || rc=$?
bench_seal "$OUT"
echo "== run directory: $OUT"
exit "$rc"
