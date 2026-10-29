#!/usr/bin/env bash
# The #19/#20 conduit experiment on real hardware, through the deployed gateways. In a confidential guest, the
# Attester produces Evidence for a Target that the honest EST server routes to ca1. The conduit (rrp-issue) then offers
# it to ca1 and to a second Credential Authority, ca2, and we record which issues. One pass since 12 October 2026, the
# binding without any identifier (the group's decision of 6 and 11 October, rats-tacra#20); the runs of 6 to 11 October
# have a second pass with the RRP identifier bound, which the code no longer makes (docs/rrp-identifier.md). This measures,
# per Freshness Kind, what freshness alone prevents. Then the conduit rewrites, one at a time, what it relays to
# ca1 on Evidence made for ca1 (#19): a made-up Handle, the Freshness Kind, a credential type the Target does not
# offer, another workload's Credential Hint, and the other credential type the Target offers; each outcome is recorded.
#
#   hwcheck/scripts/redirect.sh gcp-snp|gcp-tdx|aws-snp      (make redirect PLATFORM=...)
#   PASSPORT=1: the same in Passport: the conduit gets the Attestation Results for each Evidence from the verifier, as an
#   honest CAS does for ca1 (rrpverify ears), and offers those.
#   REDIRECT_VARIANT: what the second bank keeps of its own, and where the conduit starts (the two passes only, without
#   the #19 rewrites; the run directory and variant.txt name the variant):
#     own-epochs  ca2 keeps an epoch marker of its own (OWN_EPOCHS, e2e/scripts/bench.sh); the Evidence is made for
#                 ca1 as in the default run, with ca1's Handles and the deployment's epoch marker
#     start-ca2   ca2 keeps an epoch marker of its own, and the conduit starts the exchange there: the present-nonce and
#                 present-epoch Handles are ca2's, from its attest-initiate; the Attester holds the deployment's epoch
#                 marker (absent-epoch)
#     vault       the default run on the Secret Vaults: Retrieval Evidence for a ledger Target of vault1, offered to
#                 vault1 and to vault2, its copy (packs/tacra-bench); each asked for the
#                 workload's group's key, in the hpke-base container, signed, to an MLKEM768-P256 CEK
#     replay      the same request twice at ca1: what a conduit that holds a request gets by offering
#                 it again. The RRP keeps no record of a CSR it served, so only the freshness element can refuse the
#                 second offer: a present-nonce Handle serves once; an epoch marker serves while it is current, a
#                 timestamp while its window holds, absent-none always
#     replay-vault  the same on the Secret Vaults: Retrieval twice at vault1
#
# The guest only runs hwrun (offline); all gateway interaction is on this machine, where the bench runs. The bench runs
# the pass in Background Check (or Passport), reconfigured for it (OWN_EPOCHS in a variant), and is put back as it
# was however the run ends: its RATS model, one epoch marker.
#
# GCP_PROJECT, GCP_ZONE, AWS_REGION, AWS_AZ: where the VM goes (scripts/lib.sh). RUNS_DIR: where the run directory
# goes (default BENCH_HOME/runs). The run ends with its verdict (scripts/verdict.py) and exits 1 unless every outcome
# is the one the experiment expects.
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"   # BENCH_HOME, VERAISON_DEPLOYMENT, pinned tools
CLOUD="${1:?usage: redirect.sh gcp-snp|gcp-tdx|aws-snp}"
case "$CLOUD" in
  gcp-snp) TEE=sev-snp; MACHINE=(--machine-type=n2d-standard-2 --min-cpu-platform="AMD Milan" --confidential-compute-type=SEV_SNP);;
  gcp-tdx) TEE=tdx;     MACHINE=(--machine-type=c3-standard-4 --confidential-compute-type=TDX);;
  aws-snp) TEE=sev-snp; TYPE=c6a.large;;
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
MODEL=background-check; [ -n "${PASSPORT:-}" ] && MODEL=passport
VARIANT="${REDIRECT_VARIANT:-default}"
case "$VARIANT" in
  default|vault|replay|replay-vault) OWN="";;
  own-epochs|start-ca2) OWN=1;;   # ca2 keeps an epoch marker of its own
  *) echo "unknown REDIRECT_VARIANT $VARIANT: own-epochs, start-ca2, vault, replay or replay-vault" >&2; exit 2;;
esac
OUT="$RUNS_DIR/${STAMP}-${CLOUD}-redirect"; [ "$MODEL" = passport ] && OUT="$OUT-passport"
if [ "$VARIANT" != default ]; then OUT="$OUT-$VARIANT"; fi
BIN="$(mktemp -d)"
CA1=https://127.0.0.1:9101; CA2=https://127.0.0.1:9103
# The RRP pair the conduit plays: the Credential Authorities (Enrollment), or, in the vault variant, the Secret Vaults
# (Retrieval of the workload's group's key, sealed in the signed hpke-base container to an MLKEM768-P256 CEK, the only
# one the ledger Targets take)
if [ "$VARIANT" = vault ] || [ "$VARIANT" = replay-vault ]; then
  MODE=retrieve; RRP1=vault1; RRP2=vault2; URL1=https://127.0.0.1:9102; URL2=https://127.0.0.1:9104
  TPRE=ledger; CTYPE=api-key
else
  MODE=enroll; RRP1=ca1; RRP2=ca2; URL1="$CA1"; URL2="$CA2"; TPRE=db; CTYPE=x509
fi
B="$BENCH_HOME"; CERT="$B/tls/clients/est-server.crt"; KEY_C="$B/tls/clients/est-server.key"; ROOT="$B/tls/root.crt"
mkdir -p "$OUT"
git -C "$REPO" rev-parse --short=12 HEAD > "$OUT/code-rev.txt"
echo "$MODEL" > "$OUT/rats-model.txt"
echo "$VARIANT" > "$OUT/variant.txt"
MODEL_BEFORE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("rats_model") or "passport")' \
  "$B/config/vault-gateway.json")"
RECONFIGURED=""
restore_bench() { # the bench as it was before the experiment; nothing to do until reconfigure has run
  [ -n "$RECONFIGURED" ] || return 0
  bash "$REPO/e2e/scripts/bench.sh" stop >/dev/null 2>&1 || true
  RATS_MODEL="$MODEL_BEFORE" OWN_EPOCHS="" bash "$REPO/e2e/scripts/bench.sh" config >/dev/null 2>&1
  bash "$REPO/e2e/scripts/bench.sh" start >/dev/null 2>&1
  RECONFIGURED=""
}
"$REPO/e2e/scripts/veraison-build-info.sh" > "$OUT/veraison-build.txt"  # the Verifier the gateways ask (SEV-SNP)
ORDER=(nonce epoch lepoch time none)  # short name of each Target; fresh_of maps it to the Freshness Kind (bash 3.2: no associative arrays)
fresh_of() { case "$1" in nonce) echo present-nonce;; epoch) echo present-epoch;; lepoch) echo absent-epoch;; time) echo absent-timestamp;; none) echo absent-none;; esac; }

echo "== build hwrun, rrp-issue and rrpverify"
(cd "$HW" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/hwrun" ./cmd/hwrun)
shasum -a 256 "$BIN/hwrun" | awk '{print $1"  hwrun (linux/amd64)"}' > "$OUT/binaries.sha256"
(cd "$HW" && go build -o "$BIN/rrp-issue" ./cmd/rrp-issue && go build -o "$BIN/rrpverify" ./cmd/rrpverify)
# in Passport, the verifier an honest CAS asks: the deployed Veraison for SEV-SNP (rrpverify's default), the bench's
# TDX verifier for TDX
VERIFIER=()
if [ "$TEE" = tdx ]; then
  read -r TDX_URL TDX_CA < <(python3 -c 'import json, sys
v = json.load(open(sys.argv[1]))["tacra"]["verifiers"]["tdx"]
print(v["url"], v["ca"])' "$B/config/est-server.json")
  VERIFIER=(-url "$TDX_URL" -submod TDX -ca "$TDX_CA")
fi

# --- cloud glue: GUEST_SSH "<cmd>", GUEST_SCP_IN <files...> dst, GUEST_SCP_OUT src dst, vm_create, vm_delete ---
if [ "${CLOUD#gcp}" != "$CLOUD" ]; then
  GSSH=(gcloud compute ssh "$NAME" --project="$GCP_PROJECT" --zone="$ZONE" --command)
  vm_create() {
    echo "== create $NAME ($ZONE, $TEE)"
    gcloud compute instances create "$NAME" --project="$GCP_PROJECT" --zone="$ZONE" "${MACHINE[@]}" \
      --maintenance-policy=TERMINATE --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
      --boot-disk-size=20GB --labels=purpose=tacra-redir "${GCP_GUEST_METADATA[@]}" >/dev/null
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

# initiate URL TARGET [CTYPE]: attest-initiate for TARGET and credential type CTYPE (x509) at the RRP at URL, as the
# conduit sends it; prints the Handle it returned (base64url, as the RRP returned it)
initiate() {
  curl -s --cacert "$ROOT" --cert "$CERT" --key "$KEY_C" -H 'Content-Type: application/json' \
    -d "{\"target\":\"$2\",\"credential_type\":\"${3:-x509}\"}" "$1/tacra/v1/initiate" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['handle'])"
}
START="$URL1"; [ "$VARIANT" = start-ca2 ] && START="$CA2"   # where the conduit starts the exchange

# make_evidence PASS : mint a present-nonce Handle where the conduit starts (the first RRP; ca2 in start-ca2),
# make Evidence in the guest and copy it back; in Passport, also the Attestation Results the verifier
# issues for each case, as an honest CAS gets them. In start-ca2 the present-epoch Handle is ca2's epoch marker, from
# its attest-initiate. The Credential Authorities' cases are Enrollments; in the vault variant, Retrievals alone.
make_evidence() {
  local PASS="$1" d="$OUT/$1"; mkdir -p "$d"
  local nonce epoch epoch_handle="" guest_args
  nonce="$(initiate "$START" "https://$TPRE-nonce.tacra.example" "$CTYPE")"
  epoch="$(tr -d '[:space:]' < "$B/epoch.hex")"
  if [ "$VARIANT" = start-ca2 ]; then epoch_handle="$(initiate "$CA2" https://db-epoch.tacra.example)"; fi
  python3 - "$nonce" "$epoch" "$d" "$epoch_handle" "$MODE" "$TPRE" <<'PY'
import sys, json, base64, os, secrets
nonce_url, epoch_hex, d, epoch_handle_url, mode, tpre = sys.argv[1:7]
std = lambda b: base64.b64encode(b).decode()
url = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
minted, other = std(url(nonce_url)), std(secrets.token_bytes(32))  # the Handle the RRP minted goes to its mode
handles = {"nonce_enroll": minted if mode == "enroll" else other,
           "nonce_retrieve": other if mode == "enroll" else minted, "epoch": std(bytes.fromhex(epoch_hex))}
if epoch_handle_url:  # start-ca2: the present-epoch Handle is ca2's own epoch marker
    handles["epoch_handle"] = std(url(epoch_handle_url))
json.dump(handles, open(os.path.join(d, "handles.json"), "w"))
short = {"present-nonce": "nonce", "present-epoch": "epoch", "absent-epoch": "lepoch", "absent-timestamp": "time",
         "absent-none": "none"}
json.dump({k: f"https://{tpre}-{n}.tacra.example" for k, n in short.items()}, open(os.path.join(d, "targets.json"), "w"))
PY
  guest_args="-csr-cn payments.workload.tacra.example"
  [ "$MODE" = retrieve ] && guest_args="-modes retrieve -cek mlkem768-p256"
  guest_in "$BIN/hwrun" "$d/handles.json" "$d/targets.json" "$HW/scripts/guest-clock.sh"
  bench_guest_run "$OUT/run-ssh.stderr" "set -e
sudo ~/hwrun -tee $TEE -targets ~/targets.json -handles ~/handles.json $guest_args -out /root/redir 2>&1
sudo bash ~/guest-clock.sh /root/redir
sudo chmod -R a+rX /root/redir; rm -rf ~/redir; sudo cp -r /root/redir ~/redir; sudo chown -R \$(id -u):\$(id -g) ~/redir" \
    guest_ssh | tee -a "$OUT/hwrun-stdout.txt"
  [ -f "$OUT/clock-offset.txt" ] || bench_clock_offset "$OUT/clock-offset.txt" guest_ssh
  guest_out redir "$d/"
  if [ "$MODEL" = passport ]; then
    "$BIN/rrpverify" ears -in "$d/redir" -mode "$MODE" -out "$d/ears" ${VERIFIER[@]+"${VERIFIER[@]}"} \
      | tee "$d/ears.txt"
  fi
}

# post_case DIR KIND RRP [rrp-issue flags]: the conduit offers the case of KIND, as made in DIR, to RRP (the first or
# the second of the pair); later flags replace the honest ones (the #19 rewrites). Prints rrp-issue's JSON.
post_case() {
  local d="$1" fresh="$2" rrp="$3"; shift 3
  local url="$URL1" c="$d/redir/$MODE-$fresh" k handle
  [ "$rrp" = "$RRP2" ] && url="$URL2"
  for k in "${ORDER[@]}"; do [ "$(fresh_of "$k")" = "$fresh" ] && break; done
  handle="$(python3 -c "import json;print(json.load(open('$c/meta.json')).get('freshness_element_b64',''))")"
  local leg=(-evidence "$c/evidence.tsm.cbor") subj=(-csr "$c/subject.der")
  [ "$MODEL" = passport ] && leg=(-ear "$d/ears/$MODE-$fresh.ear.jws")
  # Retrieval: CEKpub as the binding took it, and the workload's group, which the Vault releases a key to
  [ "$MODE" = retrieve ] && subj=(-cek "$c/subject.der" -hint payments.workload.tacra.example)
  "$BIN/rrp-issue" "$MODE" -url "$url" -target "https://$TPRE-$k.tacra.example" -ctype "$CTYPE" -kind "$fresh" \
    ${handle:+-handle "$handle"} "${leg[@]}" "${subj[@]}" -ca "$ROOT" -cert "$CERT" -key "$KEY_C" "$@"
}

said() { python3 -c "import sys,json;d=json.load(sys.stdin);print('ISSUED' if d['issued'] else 'refused', d.get('reason',d.get('cert_subject',d.get('container_rrp_id',''))))"; }

# offer_redirect PASS: every case to the first RRP and to the second, as made
offer_redirect() {
  local PASS="$1" d="$OUT/$1" k fresh rrp res
  : > "$d/results.jsonl"
  for k in "${ORDER[@]}"; do
    fresh="$(fresh_of "$k")"
    for rrp in "$RRP1" "$RRP2"; do
      res="$(post_case "$d" "$fresh" "$rrp")"
      echo "{\"pass\":\"$PASS\",\"kind\":\"$fresh\",\"rrp\":\"$rrp\",\"result\":$res}" >> "$d/results.jsonl"
      echo "  $PASS $fresh -> $rrp : $(echo "$res" | said)"
    done
  done
}

# offer_replay PASS: every case to the first RRP twice, as made: what the conduit gets from a request it holds by
# offering it again. The RRP keeps no record of a CSR or CEKpub it served (rrp/internal/gateway), so only the freshness
# element can refuse the second offer (rrp/internal/fresh: a present-nonce Handle is deleted on its first use; an epoch
# marker is compared with the current one, a timestamp with its window, absent-none with nothing).
offer_replay() {
  local PASS="$1" d="$OUT/$1" k fresh n res
  : > "$d/results.jsonl"
  for k in "${ORDER[@]}"; do
    fresh="$(fresh_of "$k")"
    for n in 1 2; do
      res="$(post_case "$d" "$fresh" "$RRP1")"
      echo "{\"pass\":\"$PASS\",\"kind\":\"$fresh\",\"rrp\":\"$RRP1\",\"offer\":$n,\"result\":$res}" >> "$d/results.jsonl"
      echo "  $PASS $fresh -> $RRP1, offer $n : $(echo "$res" | said)"
    done
  done
}

# rewrite DIR KIND NAME [rrp-issue flags]: one rewrite by the conduit, offered to ca1
rewrite() {
  local d="$1" fresh="$2" name="$3" res; shift 3
  res="$(post_case "$d" "$fresh" "$RRP1" "$@")"
  echo "{\"pass\":\"$(basename "$d")\",\"kind\":\"$fresh\",\"rrp\":\"$RRP1\",\"rewrite\":\"$name\",\"result\":$res}" >> "$d/results.jsonl"
  echo "  $(basename "$d") $fresh, $name -> ca1 : $(echo "$res" | said)"
}

# offer_rewrites PASS: the #19 rewrites on Evidence made for ca1. In "rewrites" those a gateway refuses before it
# spends the freshness element come first, the Credential Hint last; "type-offered" sends the other credential type
# the Target offers.
offer_rewrites() {
  local PASS="$1" d="$OUT/$1" k fresh
  : > "$d/results.jsonl"
  for k in "${ORDER[@]}"; do
    fresh="$(fresh_of "$k")"
    if [ "$PASS" = rewrites ]; then
      if [ "$fresh" = present-nonce ]; then
        rewrite "$d" "$fresh" "made-up Handle" -handle "$(python3 -c 'import base64,secrets;print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))')"
      fi
      [ "$fresh" = absent-none ] || rewrite "$d" "$fresh" "Freshness Kind absent-none" -kind absent-none -handle ""
      rewrite "$d" "$fresh" "credential type not offered" -ctype wit
      rewrite "$d" "$fresh" "Credential Hint of another workload" -hint other.workload.tacra.example
    else
      rewrite "$d" "$fresh" "the other credential type offered" -ctype api-key
    fi
  done
}

reconfigure() { # the bench for the run: its RATS model, and OWN_EPOCHS in a variant
  RECONFIGURED=1
  bash "$REPO/e2e/scripts/bench.sh" stop >/dev/null 2>&1 || true
  RATS_MODEL="$MODEL" OWN_EPOCHS="$OWN" bash "$REPO/e2e/scripts/bench.sh" config >/dev/null 2>&1
  bash "$REPO/e2e/scripts/bench.sh" start >/dev/null 2>&1
}

echo "== bench: $MODEL, the binding without any identifier (variant: $VARIANT)"
reconfigure
vm_create
wait_ssh || { echo "ssh never came up" >&2; exit 1; }
guest_ssh "$PROVISION" 2>>"$OUT/run-ssh.stderr"
make_evidence no-rrp-id
case "$VARIANT" in replay|replay-vault) offer_replay no-rrp-id;; *) offer_redirect no-rrp-id;; esac
if [ "$VARIANT" = default ]; then
  echo "== the conduit's rewrites (#19), at ca1, on Evidence made for ca1"
  make_evidence rewrites; offer_rewrites rewrites
  make_evidence type-offered; offer_rewrites type-offered
fi

vm_delete; trap 'restore_bench; rm -rf "$BIN"' EXIT
echo "== bench: back as it was ($MODEL_BEFORE)"
restore_bench

cat "$OUT"/*/results.jsonl > "$OUT/results.jsonl"
rc=0
python3 "$REPO/scripts/verdict.py" redirect "$OUT" --out "$OUT/verdict.txt" || rc=$?
bench_seal "$OUT"
echo "== run directory: $OUT"
exit "$rc"
