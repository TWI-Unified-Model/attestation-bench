#!/usr/bin/env bash
# Demo Bank: a fictional bank built in the cloud to run TACRA end to end on real hardware. This machine is only the
# operator's console (it builds the programs, creates the VMs, collects evidence); it is on no data path.
#
#   trust zone (GCP)  Veraison, step-ca, Vault, the CA and Vault gateways, the TDX verifier; the EST server :18443
#   core (GCP)        the ledger (PostgreSQL :5432, client-certificate login) and the fraud service (:8444, API key)
#   payment service   in a confidential VM (GCP SEV-SNP, GCP TDX, AWS SEV-SNP), holding no credential of its own
#   controls          the same service on an ordinary VM, and on a genuine SEV-SNP VM of an unapproved configuration
#
#   e2e/bank/demo-bank.sh up                (then provision again after a fix: e2e/bank/demo-bank.sh provision)
#   e2e/bank/demo-bank.sh pay gcp-snp | gcp-tdx | aws-snp | ordinary | unapproved
#   e2e/bank/demo-bank.sh approve tdx|snp MEASUREMENT     (only on Google's signed endorsement)
#   e2e/bank/demo-bank.sh audit
#   e2e/bank/demo-bank.sh down
set -euo pipefail
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"   # BENCH_HOME, VERAISON_DEPLOYMENT, pinned tools
PROJECT="${PROJECT:-rats-probe}"
ZONE="${ZONE:-us-central1-c}"
AWS_REGION="${AWS_REGION:-us-east-2}"
AWS_AZ="${AWS_AZ:-us-east-2a}"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
ST="${DEMO_BANK_STATE:-$BENCH_HOME/demo-bank}"   # state and staging, outside git
D=/opt/demobank
# launch measurements the bank approves: GCP n2d-standard-2 and AWS c6a.large SEV-SNP, GCP c3-standard-4 TDX (MRTD);
# the same values as the bench, taken from the hardware runs in e2e/evidence and hwcheck/evidence
SNP_MEASUREMENTS="ccdc5cf01ba25526bd65503d95931b787b4385a3277cfe4448addf9c3e894948ae8cf7b099620e3e22717de2fb5d26fa 7a89cceaaba0bbdddc4f775acca3ef15d1f9bf8abccdc6115cfad7fb8eae113df3ee0bb50efa34db9c53ae065b1dc766"
TDX_MRTDS="c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5"
# what the bank has approved since, each on Google's signed endorsement (demo-bank.sh approve)
[ -s "$ST/approved-snp" ] && SNP_MEASUREMENTS="$(tr '\n' ' ' < "$ST/approved-snp")"
[ -s "$ST/approved-tdx" ] && TDX_MRTDS="$(tr '\n' ' ' < "$ST/approved-tdx")"
TRUST_LOGS="est-server est ca-gateway vault-gateway tdx-verifier veraison-vts veraison-verification step-ca"
export CLOUDSDK_CORE_DISABLE_PROMPTS=1 GOWORK=off AWS_PAGER=""
mkdir -p "$ST"
[ -f "$ST/state" ] && . "$ST/state"

save() { printf '%s\n' "STAMP=$STAMP" "TRUST=$TRUST" "CORE=$CORE" "OUT=$OUT" "TRUST_INT=${TRUST_INT:-}" \
  "TRUST_EXT=${TRUST_EXT:-}" "CORE_INT=${CORE_INT:-}" "CORE_EXT=${CORE_EXT:-}" > "$ST/state"; }
log() { echo "== $*" | tee -a "$OUT/console.log"; }
gssh() { local vm="$1"; shift; gcloud compute ssh "$vm" --project="$PROJECT" --zone="$ZONE" --command="$*" 2>>"$OUT/ssh.stderr"; }
gscp() { gcloud compute scp --project="$PROJECT" --zone="$ZONE" "$@" >/dev/null 2>>"$OUT/ssh.stderr"; }
wait_ssh() { for _ in $(seq 1 40); do gssh "$1" true >/dev/null 2>&1 && return 0; sleep 8; done; echo "!! no ssh to $1"; return 1; }
ip_of() { gcloud compute instances describe "$1" --project="$PROJECT" --zone="$ZONE" \
  --format="value(networkInterfaces[0].${2})"; }

build() {
  local S="$ST/stage" L=(env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOWORK=off)
  rm -rf "$S"; mkdir -p "$S"/{trust/bin,trust/src,core/bin,workload}
  (cd "$HERE/rrp" && for c in ca-gateway vault-gateway tdx-verifier; do "${L[@]}" go build -trimpath -o "$S/trust/bin/$c" ./cmd/$c; done)
  (cd "$HERE/third_party/globalsign-est/src" && "${L[@]}" go build -trimpath -o "$S/trust/bin/estserver" ./cmd/estserver)
  (cd "$HERE/e2e" && "${L[@]}" go build -trimpath -o "$S/workload/payments" ./bank/cmd/payments \
    && "${L[@]}" go build -trimpath -o "$S/workload/caapi-est" ./cmd/caapi-est \
    && "${L[@]}" go build -trimpath -o "$S/core/bin/fraud-api" ./bank/cmd/fraud-api)
  local m # step-ca and the step CLI from their released modules, built in the module cache as released
  for m in github.com/smallstep/certificates@v0.30.2 github.com/smallstep/cli@v0.30.2; do go mod download "$m"; done
  m="$(go env GOMODCACHE)"
  (cd "$m/github.com/smallstep/certificates@v0.30.2" && "${L[@]}" go build -trimpath -o "$S/trust/bin/step-ca" ./cmd/step-ca)
  (cd "$m/github.com/smallstep/cli@v0.30.2" && "${L[@]}" go build -trimpath -o "$S/trust/bin/step" ./cmd/step)
  cp "$S/trust/bin/step" "$S/core/bin/"
  # the tested source trees (pinned upstream + our patches, third_party/fetch.sh), as git holds them in the index: their
  # go-gen-ref path (../go-gen-ref-v123) is the trust VM's layout
  local V="$HERE/third_party/veraison-services/src" G="$HERE/third_party/go-gen-ref/src"
  git -C "$V" archive --format=tar.gz --prefix=veraison-services/ "$(git -C "$V" write-tree)" -- . ':(exclude)perf' > "$S/trust/src/veraison-services.tgz"
  git -C "$G" archive --format=tar.gz --prefix=go-gen-ref-v123/ "$(git -C "$G" write-tree)" > "$S/trust/src/go-gen-ref-v123.tgz"
  cp "$HERE/hwcheck/evidence/veraison-provisioned-corim-milan.cbor" "$S/trust/src/corim-milan.cbor"
  cp "$HERE/e2e/bank/remote/trust.sh" "$S/trust/"; cp "$HERE/e2e/bank/remote/core.sh" "$S/core/"
  { echo "attestation-bench $(git -C "$HERE" rev-parse --short=12 HEAD)$(git -C "$HERE" diff --quiet HEAD -- platform cai bundle rrp e2e || echo -dirty)"
    "$HERE/third_party/describe.sh" globalsign-est veraison-services go-gen-ref | grep -v -e '/src-fork ' -e '/src-der '
    echo "step-ca v0.30.2, step v0.30.2, vault 2.1.1 (official release, SHA-256 checked on the VM)"; } > "$OUT/code-revs.txt"
  (cd "$S" && find . -type f | sort | xargs shasum -a 256) > "$OUT/staged-files.sha256"
}

create_gcp() { # name machine-args...
  local name="$1"; shift
  gcloud compute instances create "$name" --project="$PROJECT" --zone="$ZONE" "$@" \
    --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud --boot-disk-size=30GB \
    --labels=purpose=demo-bank,stamp="$(echo "$STAMP" | tr -d 'TZ')" --metadata=enable-oslogin=TRUE >/dev/null 2>>"$OUT/ssh.stderr"
}

up() {
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"; local id; id="$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
  TRUST="demobank-trust-$id" CORE="demobank-core-$id" OUT="$HERE/e2e/evidence/${STAMP}-demo-bank"
  mkdir -p "$OUT/up" "$OUT/public" "$OUT/runs"; save
  log "build (linux/amd64)"; build
  log "create $TRUST (SEV-SNP n2d-standard-4) and $CORE (e2-standard-2) in $ZONE"
  create_gcp "$TRUST" --machine-type=n2d-standard-4 --min-cpu-platform="AMD Milan" --confidential-compute-type=SEV_SNP \
    --maintenance-policy=TERMINATE --tags=demobank
  create_gcp "$CORE" --machine-type=e2-standard-2 --tags=demobank
  TRUST_INT="$(ip_of "$TRUST" networkIP)" TRUST_EXT="$(ip_of "$TRUST" 'accessConfigs[0].natIP')"
  CORE_INT="$(ip_of "$CORE" networkIP)" CORE_EXT="$(ip_of "$CORE" 'accessConfigs[0].natIP')"; save
  printf '%s internal %s external %s\n' "$TRUST" "$TRUST_INT" "$TRUST_EXT" "$CORE" "$CORE_INT" "$CORE_EXT" | tee "$OUT/up/machines.txt"
  wait_ssh "$TRUST"; wait_ssh "$CORE"
  log "copy programs and sources"
  gscp --recurse "$ST/stage/trust" "$TRUST:~/"
  gscp --recurse "$ST/stage/core" "$CORE:~/"
  gssh "$TRUST" "sudo mkdir -p $D/src $D/bin && sudo cp ~/trust/bin/* $D/bin/ && sudo cp ~/trust/trust.sh $D/ && sudo cp ~/trust/src/corim-milan.cbor $D/src/ \
    && sudo tar -C $D/src -xzf ~/trust/src/veraison-services.tgz && sudo tar -C $D/src -xzf ~/trust/src/go-gen-ref-v123.tgz && rm -rf ~/trust"
  gssh "$CORE" "sudo mkdir -p $D/bin $D/public && sudo cp ~/core/bin/* $D/bin/ && sudo cp ~/core/core.sh $D/ && rm -rf ~/core"
  provision
}

# install, configure and start both machines; every step is safe to repeat
provision() {
  gscp "$HERE/e2e/bank/remote/trust.sh" "$TRUST:~/trust.sh"; gssh "$TRUST" "sudo cp ~/trust.sh $D/trust.sh && rm ~/trust.sh"
  gscp "$HERE/e2e/bank/remote/core.sh" "$CORE:~/core.sh"; gssh "$CORE" "sudo cp ~/core.sh $D/core.sh && rm ~/core.sh"
  log "install both (Veraison builds on the trust zone)"
  local tp cp code=0
  gssh "$TRUST" "sudo bash $D/trust.sh install" > "$OUT/up/trust-install.txt" 2>&1 & tp=$!
  gssh "$CORE" "sudo bash $D/core.sh install" > "$OUT/up/core-install.txt" 2>&1 & cp=$!
  wait "$tp" || code=$?; wait "$cp" || code=$?
  cat "$OUT/up/trust-install.txt" "$OUT/up/core-install.txt"
  [ "$code" = 0 ] || { echo "!! install failed ($code)"; exit 1; }
  log "trust zone: keys, CA, stores, policy"
  gssh "$TRUST" "sudo INTERNAL_IP=$TRUST_INT EXTERNAL_IP=$TRUST_EXT SNP_MEASUREMENTS='$SNP_MEASUREMENTS' TDX_MRTDS='$TDX_MRTDS' bash $D/trust.sh setup" | tee "$OUT/up/trust-setup.txt"
  gscp "$TRUST:$D/public/workload-ca.pem" "$TRUST:$D/public/trust-tls-root.crt" "$TRUST:$D/public/epoch.hex" "$TRUST:$D/public/policy.json" "$OUT/public/"
  log "core: the ledger trusts the bank's workload CA for client logins"
  gscp "$OUT/public/workload-ca.pem" "$CORE:~/"
  gssh "$CORE" "sudo cp ~/workload-ca.pem $D/public/ && sudo INTERNAL_IP=$CORE_INT EXTERNAL_IP=$CORE_EXT bash $D/core.sh setup && sudo bash $D/core.sh start" | tee "$OUT/up/core-setup.txt"
  gscp "$CORE:$D/public/core-tls-root.crt" "$OUT/public/"
  log "the fraud service's API key goes to the bank's Vault (piped machine to machine, never written here)"
  gssh "$CORE" "sudo cat $D/secrets/fraud-api-key" | gssh "$TRUST" "sudo bash -c 'umask 077; cat > $D/secrets/fraud-api-key'"
  [ "$(gssh "$TRUST" "sudo cat $D/secrets/fraud-api-key | wc -c" | tr -d '[:space:]')" = 59 ] || { echo "!! the key did not arrive"; exit 1; }
  log "trust zone: start"
  gssh "$TRUST" "sudo bash $D/trust.sh start" | tee "$OUT/up/trust-start.txt"
  gscp "$TRUST:$D/public/origin-keys.json" "$OUT/public/"
  gssh "$TRUST" "sudo cat $D/logs/corim-submit.json; echo; sudo grep -c . $D/secrets/fraud-api-key 2>/dev/null || echo 'fraud key file removed after loading into Vault'" \
    > "$OUT/up/trust-provisioning.txt"
  cat "$OUT/up/trust-provisioning.txt"
  log "up: $TRUST, $CORE"
}

# payment-service configuration: public material only (trust anchors, the Vault's origin keys, the epoch marker)
workload_config() { # tee out
  TEE="$1" P="$OUT/public" python3 - > "$2" <<'PY'
import json, os
P = os.environ["P"]
core_root = open(f"{P}/core-tls-root.crt").read()
ledger, fraud = "https://ledger-db.demobank.example", "https://fraud-api.demobank.example"
print(json.dumps({"tee": os.environ["TEE"], "caapi": "127.0.0.1:50061", "hint": "payments.workload.demobank.example",
  "ledger": {"target": ledger, "host": "core.demobank.internal", "port": 5432, "database": "bank", "user": "payments",
             "server_ca_pem": core_root},
  "fraud": {"target": fraud, "url": "https://core.demobank.internal:8444", "server_ca_pem": core_root},
  "relying_parties": {ledger: {"enroll": "https://ca.demobank.example"}, fraud: {"retrieve": "https://vault.demobank.example"}},
  "vault_origins": {"https://vault.demobank.example": json.load(open(f"{P}/origin-keys.json"))},
  "local_epoch_hex": open(f"{P}/epoch.hex").read().strip()}, indent=1))
PY
}

mark_logs() { # run dir
  gssh "$TRUST" "cd $D/logs && for f in $TRUST_LOGS; do printf '%s %s\n' \$f \$(sudo cat \$f.log 2>/dev/null | wc -l); done" > "$1/.trust-marks"
  gssh "$CORE" "printf 'postgresql %s\n' \$(sudo cat /var/log/postgresql/postgresql-16-main.log | wc -l); printf 'fraud-api %s\n' \$(sudo cat $D/logs/fraud-api.log | wc -l)" > "$1/.core-marks"
}

slice_logs() { # run dir
  mkdir -p "$1/trust-logs" "$1/core-logs"
  local spec
  spec="$(tr '\n' ' ' < "$1/.trust-marks")"
  gssh "$TRUST" "set -- $spec; while [ \$# -gt 0 ]; do echo \"### \$1\"; sudo tail -n +\$((\$2 + 1)) $D/logs/\$1.log 2>/dev/null | grep -v 'TLS handshake error' || true; shift 2; done" \
    | awk -v dir="$1/trust-logs" '/^### /{f=dir "/" $2 ".log"; printf "" > f; next} f != "" {print >> f}'
  spec="$(tr '\n' ' ' < "$1/.core-marks")"
  gssh "$CORE" "set -- $spec; echo '### postgresql'; sudo tail -n +\$((\$2 + 1)) /var/log/postgresql/postgresql-16-main.log; echo '### fraud-api'; sudo tail -n +\$((\$4 + 1)) $D/logs/fraud-api.log" \
    | awk -v dir="$1/core-logs" '/^### /{f=dir "/" $2 ".log"; printf "" > f; next} f != "" {print >> f}'
  rm -f "$1"/.trust-marks "$1"/.core-marks
}

guest_run() { # how-to-ssh... ; env: TRUST_IP CORE_IP FLAGS
  "$@" "
set -e
sudo modprobe sev-guest 2>/dev/null || sudo modprobe tdx_guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /sys/kernel/config/tsm/report 2>&1 || true
printf '%s trust.demobank.internal\n%s core.demobank.internal\n' $TRUST_IP $CORE_IP | sudo tee -a /etc/hosts >/dev/null
nohup ~/caapi-est -listen 127.0.0.1:50061 -est trust.demobank.internal:18443 -anchor ~/trust-tls-root.crt > ~/caapi-est.log 2>&1 &
echo \$! > ~/caapi-est.pid
sleep 1
sudo ~/payments -config ~/payments.json -from ACC-1001 -to ACC-2002 -amount 125.50 -out ~/report.json $FLAGS 2>&1 || true
sudo chown \$(id -u):\$(id -g) ~/report.json
uname -a > ~/kernel.txt
kill \"\$(cat ~/caapi-est.pid)\" || true"
}

verdict() { # run dir, expect
  python3 - "$1" "$2" <<'PY' | tee "$1/verdict.txt"
import json, sys
run, expect = sys.argv[1], sys.argv[2]
r = json.load(open(f"{run}/report.json"))
steps = {s["step"]: s for s in r["steps"]}
for s in r["steps"]:
    print(("ok " if s["ok"] else "NO ") + s["step"].ljust(38) + f'{s["ms"]:9.1f} ms  ' + (s.get("note") or "") + " " + (s.get("error") or ""))
paid = "ledger: transfer" in steps and steps["ledger: transfer"]["ok"] and r.get("receipt")
got_cred = any(s["ok"] for n, s in steps.items() if n.startswith("TACRA:"))
if expect == "pay":
    ok = bool(paid)
    print("VERDICT", "PASS: the payment went through, with credentials acquired by attestation" if ok else "FAIL: no payment")
elif expect == "ordinary":
    ok = not paid and not got_cred and all(steps.get(n, {}).get("ok") for n in ("ledger: login without a certificate", "fraud service: call without the key"))
    print("VERDICT", "PASS: no attestation, no credential; the ledger and the fraud service refused it" if ok else "FAIL")
else:  # unapproved: genuine hardware evidence, from a launch the bank has not approved
    hw = steps.get("attestation plug-in and CAI", {}).get("ok") is True
    ok = hw and not paid and not got_cred
    print("VERDICT", "PASS: genuine hardware evidence, unapproved launch: no credential issued" if ok else "FAIL")
sys.exit(0 if ok else 1)
PY
}

pay() {
  local kind="${1:?kind}" rs name R MACHINE=() FLAGS="" TEE=sev-snp EXPECT=pay
  rs="$(date -u +%Y%m%dT%H%M%SZ)"; name="demobank-pay-$(echo "$rs" | tr -d 'TZ' | cut -c7-12)-$kind"
  R="$OUT/runs/${rs}-$kind"; mkdir -p "$R"
  case "$kind" in
    gcp-snp)    MACHINE=(--machine-type=n2d-standard-2 --min-cpu-platform="AMD Milan" --confidential-compute-type=SEV_SNP --maintenance-policy=TERMINATE) ;;
    unapproved) MACHINE=(--machine-type=n2d-standard-4 --min-cpu-platform="AMD Milan" --confidential-compute-type=SEV_SNP --maintenance-policy=TERMINATE); EXPECT=unapproved ;;
    gcp-tdx)    MACHINE=(--machine-type=c3-standard-4 --confidential-compute-type=TDX --maintenance-policy=TERMINATE); TEE=tdx ;;
    ordinary)   MACHINE=(--machine-type=e2-small); FLAGS=-imposter; EXPECT=ordinary ;;
    aws-snp)    pay_aws "$R"; return ;;
    *) echo "unknown kind $kind" >&2; exit 2 ;;
  esac
  workload_config "$TEE" "$R/payments.json"
  mark_logs "$R"
  log "$kind: create $name (${MACHINE[*]})"
  create_gcp "$name" "${MACHINE[@]}"
  trap "gcloud compute instances delete '$name' --project='$PROJECT' --zone='$ZONE' --quiet >/dev/null 2>&1" EXIT
  wait_ssh "$name"
  gscp "$ST/stage/workload/payments" "$ST/stage/workload/caapi-est" "$R/payments.json" "$OUT/public/trust-tls-root.crt" "$name:~/"
  log "$kind: run the payment service"
  TRUST_IP="$TRUST_INT" CORE_IP="$CORE_INT" FLAGS="$FLAGS" guest_run gssh "$name" | tee "$R/guest-stdout.txt"
  gscp "$name:~/report.json" "$name:~/caapi-est.log" "$name:~/kernel.txt" "$R/"
  gcloud compute instances describe "$name" --project="$PROJECT" --zone="$ZONE" \
    --format="yaml(name,machineType,confidentialInstanceConfig,cpuPlatform)" > "$R/instance.yaml" 2>/dev/null || true
  log "$kind: delete $name"
  gcloud compute instances delete "$name" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1 || true
  trap - EXIT
  [ -z "$(gcloud compute instances list --project="$PROJECT" --filter="name=$name" --format='value(name)')" ] \
    && echo "$name is gone" > "$R/vm-deleted.txt"
  slice_logs "$R"
  (cd "$R" && find . -type f ! -name sha256sums.txt | sort | xargs shasum -a 256 > sha256sums.txt)
  verdict "$R" "$EXPECT"
}

pay_aws() { # run dir
  local R="$1" TYPE=c6a.large name ID="" SG="" KEY FW="" K AMI SUB VPC MYIP IP
  name="demobank-pay-$(basename "$R" | cut -c10-15)-aws-snp"; KEY="$name"; K="$(mktemp -d)"
  workload_config sev-snp "$R/payments.json"
  mark_logs "$R"
  aws_cleanup() {
    set +e
    [ -n "$ID" ] && { aws ec2 terminate-instances --region "$AWS_REGION" --instance-ids "$ID" >/dev/null
      aws ec2 wait instance-terminated --region "$AWS_REGION" --instance-ids "$ID"
      echo "instance $ID: $(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].State.Name' --output text)" >> "$R/vm-deleted.txt"; ID=""; }
    [ -n "$SG" ] && { aws ec2 delete-security-group --region "$AWS_REGION" --group-id "$SG" && echo "security group $SG deleted" >> "$R/vm-deleted.txt"; SG=""; }
    aws ec2 describe-key-pairs --region "$AWS_REGION" --key-names "$KEY" >/dev/null 2>&1 && aws ec2 delete-key-pair --region "$AWS_REGION" --key-name "$KEY" \
      && echo "key pair $KEY deleted" >> "$R/vm-deleted.txt"
    [ -n "$FW" ] && { gcloud compute firewall-rules delete "$FW" --project="$PROJECT" --quiet >/dev/null 2>&1 && echo "GCP firewall rule $FW deleted" >> "$R/vm-deleted.txt"; FW=""; }
    rm -rf "$K"
  }
  trap aws_cleanup EXIT
  log "aws-snp: key pair, security group (SSH from this address only), $TYPE with AmdSevSnp=enabled"
  aws ec2 create-key-pair --region "$AWS_REGION" --key-name "$KEY" --key-type ed25519 --query KeyMaterial --output text > "$K/key"
  chmod 600 "$K/key"
  VPC="$(aws ec2 describe-vpcs --region "$AWS_REGION" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
  SG="$(aws ec2 create-security-group --region "$AWS_REGION" --group-name "$name" --description "demo bank $STAMP" --vpc-id "$VPC" --query GroupId --output text)"
  MYIP="$(curl -sf -m 10 https://checkip.amazonaws.com | tr -d '[:space:]')"
  aws ec2 authorize-security-group-ingress --region "$AWS_REGION" --group-id "$SG" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null
  AMI="$(aws ssm get-parameter --region "$AWS_REGION" --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)"
  SUB="$(aws ec2 describe-subnets --region "$AWS_REGION" --filters Name=availability-zone,Values="$AWS_AZ" Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)"
  ID="$(aws ec2 run-instances --region "$AWS_REGION" --image-id "$AMI" --instance-type "$TYPE" --subnet-id "$SUB" \
    --cpu-options AmdSevSnp=enabled --key-name "$KEY" --security-group-ids "$SG" --metadata-options HttpTokens=required,HttpEndpoint=enabled \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$name},{Key=purpose,Value=demo-bank}]" --query 'Instances[0].InstanceId' --output text)"
  echo "$AWS_REGION $AWS_AZ $ID $AMI $TYPE" > "$R/instance.txt"
  aws ec2 wait instance-running --region "$AWS_REGION" --instance-ids "$ID"
  IP="$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
  FW="demobank-aws-$(basename "$R" | cut -c10-15)"
  log "aws-snp: GCP firewall rule $FW admits $IP to the EST server, the ledger and the fraud service only"
  gcloud compute firewall-rules create "$FW" --project="$PROJECT" --network=default --direction=INGRESS --action=ALLOW \
    --rules=tcp:18443,tcp:5432,tcp:8444 --source-ranges="$IP/32" --target-tags=demobank >/dev/null 2>>"$OUT/ssh.stderr"
  local SSHO=(-i "$K/key" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$K/known_hosts" -o ConnectTimeout=10)
  for _ in $(seq 1 40); do ssh "${SSHO[@]}" "ubuntu@$IP" true >/dev/null 2>&1 && break; sleep 8; done
  scp "${SSHO[@]}" "$ST/stage/workload/payments" "$ST/stage/workload/caapi-est" "$R/payments.json" "$OUT/public/trust-tls-root.crt" "ubuntu@$IP:~/" >/dev/null 2>>"$OUT/ssh.stderr"
  log "aws-snp: run the payment service (over the internet to the bank in GCP)"
  TRUST_IP="$TRUST_EXT" CORE_IP="$CORE_EXT" FLAGS="" guest_run ssh "${SSHO[@]}" "ubuntu@$IP" | tee "$R/guest-stdout.txt"
  scp "${SSHO[@]}" "ubuntu@$IP:~/report.json" "ubuntu@$IP:~/caapi-est.log" "ubuntu@$IP:~/kernel.txt" "$R/" >/dev/null 2>>"$OUT/ssh.stderr"
  log "aws-snp: terminate, delete the security group, key pair and firewall rule"
  aws_cleanup; trap - EXIT
  slice_logs "$R"
  (cd "$R" && find . -type f ! -name sha256sums.txt | sort | xargs shasum -a 256 > sha256sums.txt)
  verdict "$R" pay
}

# approve a launch measurement on Google's signed firmware endorsement, then have the trust zone apply the policy
approve() { # tdx|snp MEASUREMENT
  local tech="${1:?tdx or snp}" m="${2:?measurement}" f
  (cd "$HERE/rrp" && GOWORK=off go build -o "$ST/gce-endorsement" ./cmd/gce-endorsement)
  mkdir -p "$OUT/refvals"
  log "approve $tech $m: Google's endorsement, verified against the pinned GCE TCB root"
  "$ST/gce-endorsement" -root "$HERE/e2e/bank/refvals/GCE-cc-tcb-root_1.crt" "-$tech" "$m" -save "$OUT/refvals/$tech-$m.binarypb" \
    | tee "$OUT/refvals/$tech-$m.json"   # exits non-zero unless Google endorses it
  f="$ST/approved-$tech"
  [ -s "$f" ] || { if [ "$tech" = tdx ]; then echo "$TDX_MRTDS"; else echo "$SNP_MEASUREMENTS"; fi; } | tr ' ' '\n' | grep . > "$f"
  grep -qx "$m" "$f" || echo "$m" >> "$f"
  [ -s "$ST/approved-snp" ] && SNP_MEASUREMENTS="$(tr '\n' ' ' < "$ST/approved-snp")"
  [ -s "$ST/approved-tdx" ] && TDX_MRTDS="$(tr '\n' ' ' < "$ST/approved-tdx")"
  log "trust zone: new policy, restart the verifier and the gateways"
  gscp "$HERE/e2e/bank/remote/trust.sh" "$TRUST:~/trust.sh"; gssh "$TRUST" "sudo cp ~/trust.sh $D/trust.sh && rm ~/trust.sh"
  gssh "$TRUST" "sudo INTERNAL_IP=$TRUST_INT EXTERNAL_IP=$TRUST_EXT SNP_MEASUREMENTS='$SNP_MEASUREMENTS' TDX_MRTDS='$TDX_MRTDS' bash $D/trust.sh setup \
    && sudo bash $D/trust.sh restart tdx-verifier ca-gateway vault-gateway" | tee -a "$OUT/refvals/policy-changes.txt"
  gscp "$TRUST:$D/public/policy.json" "$OUT/public/policy.json"
}

audit() {
  mkdir -p "$OUT/audit"
  gssh "$CORE" "sudo bash $D/core.sh audit" | tee "$OUT/audit/ledger.txt"
  gssh "$TRUST" "sudo bash $D/trust.sh status" > "$OUT/audit/trust-status.txt"
  gssh "$CORE" "sudo bash $D/core.sh status" > "$OUT/audit/core-status.txt"
}

down() {
  mkdir -p "$OUT"
  log "delete $TRUST and $CORE"
  gcloud compute instances delete "$TRUST" "$CORE" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1 || true
  for fw in $(gcloud compute firewall-rules list --project="$PROJECT" --filter="name~^demobank-" --format='value(name)'); do
    gcloud compute firewall-rules delete "$fw" --project="$PROJECT" --quiet >/dev/null 2>&1
  done
  {
    echo "GCP instances labelled purpose=demo-bank: $(gcloud compute instances list --project="$PROJECT" --filter='labels.purpose=demo-bank' --format='value(name)' | wc -l | tr -d ' ')"
    echo "GCP instances in $PROJECT: $(gcloud compute instances list --project="$PROJECT" --format='value(name)' | wc -l | tr -d ' ')"
    echo "GCP firewall rules demobank-*: $(gcloud compute firewall-rules list --project="$PROJECT" --filter='name~^demobank-' --format='value(name)' | wc -l | tr -d ' ')"
    echo "AWS $AWS_REGION instances tagged purpose=demo-bank, not terminated: $(aws ec2 describe-instances --region "$AWS_REGION" \
      --filters Name=tag:purpose,Values=demo-bank Name=instance-state-name,Values=pending,running,stopping,stopped \
      --query 'length(Reservations[].Instances[])' --output text)"
    echo "AWS $AWS_REGION key pairs demobank-*: $(aws ec2 describe-key-pairs --region "$AWS_REGION" --filters 'Name=key-name,Values=demobank-*' --query 'length(KeyPairs)' --output text)"
    echo "AWS $AWS_REGION security groups demobank-*: $(aws ec2 describe-security-groups --region "$AWS_REGION" --filters 'Name=group-name,Values=demobank-*' --query 'length(SecurityGroups)' --output text)"
  } | tee "$OUT/teardown.txt"
  rm -f "$ST/state"
}

case "${1:-}" in
  up) up ;;
  provision) provision ;;
  pay) shift; pay "$@" ;;
  approve) shift; approve "$@" ;;
  audit) audit ;;
  down) down ;;
  *) echo "usage: $0 up | pay KIND | audit | down" >&2; exit 2 ;;
esac
