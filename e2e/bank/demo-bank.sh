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
#   e2e/bank/demo-bank.sh approve tdx MRTD  (only on Google's signed endorsement)
#   e2e/bank/demo-bank.sh audit
#   e2e/bank/demo-bank.sh down
#   BANK=acme-bank e2e/bank/demo-bank.sh up     (a bank of your own: scripts/bank-new.sh)
#
# The trust zone is configured by the bench's own program (scripts/trustzone.py) from the bank's pack and the launches
# the bank approves: trust/approved-launches.json when the bank comes up, plus what it approves while it runs.
#
# GCP_PROJECT, GCP_ZONE: where the bank's VMs go; AWS_REGION, AWS_AZ: where "pay aws-snp" goes (scripts/lib.sh).
# BANK: which bank, packs/BANK/pack.json (default demo-bank; make bank-new makes another). RATS_MODEL: passport
# (default) or background-check. Both are set when the bank comes up and kept until it goes down. RUNS_DIR: where
# the bank's run directory goes (default BENCH_HOME/runs).
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"   # BENCH_HOME, VERAISON_DEPLOYMENT, pinned tools
bench_gcp
PROJECT="$GCP_PROJECT" ZONE="$GCP_ZONE"
RUNS_DIR="${RUNS_DIR:-$BENCH_HOME/runs}"
RATS_MODEL="${RATS_MODEL:-passport}"
BANK="${BANK:-demo-bank}"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
ST="${DEMO_BANK_STATE:-$BENCH_HOME/demo-bank}"   # state and staging, outside git
APPROVED="$ST/approved-launches.json"            # the launches this bank approves
D=/opt/demobank
TRUST_LOGS="est-server ca-gateway vault-gateway tdx-verifier veraison-vts veraison-verification step-ca"
export AWS_PAGER=""
mkdir -p "$ST"
# shellcheck source=/dev/null  # the bank's state, written by save()
[ -f "$ST/state" ] && . "$ST/state"
PACK="$HERE/packs/$BANK/pack.json"                # the bank that is up, or the one BANK names

save() { printf '%s\n' "STAMP=$STAMP" "BANK=$BANK" "TRUST=$TRUST" "CORE=$CORE" "OUT=$OUT" "RATS_MODEL=$RATS_MODEL" "TRUST_INT=${TRUST_INT:-}" \
  "TRUST_EXT=${TRUST_EXT:-}" "CORE_INT=${CORE_INT:-}" "CORE_EXT=${CORE_EXT:-}" > "$ST/state"; }
log() { echo "== $*" | tee -a "$OUT/console.log"; }
pack_hint() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["workload"]["hint"])' "$PACK"; }
need_pack() { [ -f "$PACK" ] || bench_die "no bank $BANK: packs/$BANK/pack.json does not exist (make bank-new NAME=$BANK)"; }
need_bank() { [ -n "${OUT:-}" ] && [ -n "${TRUST:-}" ] || bench_die "no Demo Bank is up (no state in $ST): make bank-up"; }
gssh() { local vm="$1"; shift; gcloud compute ssh "$vm" --project="$PROJECT" --zone="$ZONE" --command="$*" 2>>"$OUT/ssh.stderr"; }
gscp() { gcloud compute scp --project="$PROJECT" --zone="$ZONE" "$@" >/dev/null 2>>"$OUT/ssh.stderr"; }
wait_ssh() { for _ in $(seq 1 40); do gssh "$1" true >/dev/null 2>&1 && return 0; sleep 8; done; echo "!! no ssh to $1"; return 1; }
ip_of() { gcloud compute instances describe "$1" --project="$PROJECT" --zone="$ZONE" \
  --format="value(networkInterfaces[0].${2})"; }

build() {
  local S="$ST/stage" L=(env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOWORK=off)
  rm -rf "${S:?}"; mkdir -p "$S"/{trust/bin,trust/src,core/bin,workload}
  (cd "$HERE/rrp" && for c in ca-gateway vault-gateway tdx-verifier; do "${L[@]}" go build -trimpath -o "$S/trust/bin/$c" ./cmd/$c; done)
  (cd "$HERE/third_party/globalsign-est/src" && "${L[@]}" go build -trimpath -o "$S/trust/bin/estserver" ./cmd/estserver)
  (cd "$HERE/e2e" && "${L[@]}" go build -trimpath -o "$S/workload/payments" ./bank/cmd/payments \
    && "${L[@]}" go build -trimpath -o "$S/workload/caapi-est" ./cmd/caapi-est \
    && "${L[@]}" go build -trimpath -o "$S/core/bin/fraud-api" ./bank/cmd/fraud-api)
  local m # step-ca and the step CLI from their released modules (scripts/versions.env), built in the module cache
  for m in "github.com/smallstep/certificates@$STEP_VERSION" "github.com/smallstep/cli@$STEP_VERSION"; do go mod download "$m"; done
  m="$(go env GOMODCACHE)"
  (cd "$m/github.com/smallstep/certificates@$STEP_VERSION" && "${L[@]}" go build -trimpath -o "$S/trust/bin/step-ca" ./cmd/step-ca)
  (cd "$m/github.com/smallstep/cli@$STEP_VERSION" && "${L[@]}" go build -trimpath -o "$S/trust/bin/step" ./cmd/step)
  cp "$S/trust/bin/step" "$S/core/bin/"
  # the tested source trees (pinned upstream + our patches, third_party/fetch.sh), as git holds them in the index: their
  # go-gen-ref path (../go-gen-ref-v123) is the trust VM's layout
  local V="$HERE/third_party/veraison-services/src" G="$HERE/third_party/go-gen-ref/src"
  git -C "$V" archive --format=tar.gz --prefix=veraison-services/ "$(git -C "$V" write-tree)" -- . ':(exclude)perf' > "$S/trust/src/veraison-services.tgz"
  git -C "$G" archive --format=tar.gz --prefix=go-gen-ref-v123/ "$(git -C "$G" write-tree)" > "$S/trust/src/go-gen-ref-v123.tgz"
  stage_text "$S/trust"
  cp "$HERE/e2e/bank/remote/core.sh" "$S/core/"
  { echo "attestation-bench $(git -C "$HERE" rev-parse --short=12 HEAD)$(git -C "$HERE" diff --quiet HEAD -- platform cai bundle rrp e2e scripts packs trust || echo -dirty)"
    "$HERE/third_party/describe.sh" globalsign-est veraison-services go-gen-ref | grep -v -e '/src-fork ' -e '/src-der '
    echo "step-ca $STEP_VERSION, step $STEP_VERSION (built from their release modules); vault $VAULT_VERSION, go $GO_VERSION" \
      "(official releases, SHA-256 checked on the VM against scripts/versions.env)"; } > "$OUT/code-revs.txt"
  (cd "$S" && find . -type f | sort | xargs shasum -a 256) > "$OUT/staged-files.sha256"
}

# The trust VM's text files, staged by build and copied again by provision: the trust zone's script, the bench's
# configuration program, the bank's pack, the launches it approves, Veraison's CoRIM, the pinned versions.
stage_text() { # dir
  mkdir -p "$1/scripts" "$1/trust"
  cp "$HERE/e2e/bank/remote/trust.sh" "$HERE/scripts/versions.env" "$HERE/scripts/requirements.txt" "$1/"
  cp "$HERE/scripts/trustzone.py" "$1/scripts/"
  cp "$PACK" "$1/pack.json"
  cp "$APPROVED" "$1/trust/approved-launches.json"
  cp "$HERE/trust/veraison-corim-milan.cbor" "$1/trust/"
}

# Google's signed endorsement of each launch the bank approves at start, checked again and kept with the run
# (rrp/cmd/gce-endorsement against the pinned root); a launch Google does not endorse, AWS's, is recorded as such.
initial_endorsements() {
  (cd "$HERE/rrp" && go build -o "$ST/gce-endorsement" ./cmd/gce-endorsement)
  log "Google's endorsements of the approved launches, verified to the pinned GCE TCB root"
  local tech v r said
  python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); [print("snp", e["measurement"]) for e in a["sev-snp"]]; [print("tdx", e["mrtd"]) for e in a["tdx"]]' \
    "$APPROVED" > "$ST/approved.list"
  while read -r tech v; do
    r="$OUT/refvals/initial-$tech-$v"
    "$ST/gce-endorsement" -root "$HERE/trust/GCE-cc-tcb-root_1.crt" "-$tech" "$v" -save "$r.binarypb" > "$r.json" || true
    said="$(python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); print("endorsed by Google" if j["endorsed"] else "not endorsed: " + j.get("reason", ""))' \
      "$r.json" 2>/dev/null || echo "no answer")"
    echo "   $tech ${v:0:16}...: $said" | tee -a "$OUT/console.log"
  done < "$ST/approved.list"
  rm -f "$ST/approved.list"
}

create_gcp() { # name machine-args...
  local name="$1"; shift
  gcloud compute instances create "$name" --project="$PROJECT" --zone="$ZONE" "$@" \
    --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud --boot-disk-size=30GB \
    --labels=purpose=demo-bank,stamp="$(echo "$STAMP" | tr -d 'TZ')" --metadata=enable-oslogin=TRUE >/dev/null 2>>"$OUT/ssh.stderr"
}

up() {
  need_pack
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"; local id; id="$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
  TRUST="demobank-trust-$id" CORE="demobank-core-$id" OUT="$RUNS_DIR/${STAMP}-$BANK"
  mkdir -p "$OUT/up" "$OUT/public" "$OUT/runs" "$OUT/refvals"; save
  echo "$RATS_MODEL" > "$OUT/rats-model.txt"
  echo "$BANK packs/$BANK/pack.json $(bench_sha256 "$PACK")" > "$OUT/bank.txt"
  cp "$HERE/trust/approved-launches.json" "$APPROVED"   # the bank starts from the bench's approved launches
  log "build (linux/amd64)"; build
  initial_endorsements
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
  gssh "$TRUST" "sudo mkdir -p ${D:?} && sudo cp -r ~/trust/. ${D:?}/ && sudo tar -C ${D:?}/src -xzf ${D:?}/src/veraison-services.tgz \
    && sudo tar -C ${D:?}/src -xzf ${D:?}/src/go-gen-ref-v123.tgz && rm -r ~/trust"
  gssh "$CORE" "sudo mkdir -p ${D:?}/bin ${D:?}/public && sudo cp ~/core/bin/* ${D:?}/bin/ && sudo cp ~/core/core.sh ${D:?}/ && rm -r ~/core"
  provision
}

# install, configure and start both machines; every step is safe to repeat
provision() {
  need_bank
  need_pack
  local T; T="$(mktemp -d)"
  stage_text "$T/trust"
  gscp --recurse "$T/trust" "$TRUST:~/"
  rm -r "${T:?}"
  gssh "$TRUST" "sudo cp -r ~/trust/. ${D:?}/ && rm -r ~/trust"
  gscp "$HERE/e2e/bank/remote/core.sh" "$CORE:~/core.sh"; gssh "$CORE" "sudo cp ~/core.sh ${D:?}/core.sh && rm ~/core.sh"
  log "install both (Veraison builds on the trust zone)"
  local tp cp code=0
  gssh "$TRUST" "sudo bash $D/trust.sh install" > "$OUT/up/trust-install.txt" 2>&1 & tp=$!
  gssh "$CORE" "sudo bash $D/core.sh install" > "$OUT/up/core-install.txt" 2>&1 & cp=$!
  wait "$tp" || code=$?; wait "$cp" || code=$?
  cat "$OUT/up/trust-install.txt" "$OUT/up/core-install.txt"
  [ "$code" = 0 ] || { echo "!! install failed ($code)"; exit 1; }
  log "trust zone: TLS, the workload CA, the configuration (RATS model: $RATS_MODEL)"
  gssh "$TRUST" "sudo INTERNAL_IP=$TRUST_INT EXTERNAL_IP=$TRUST_EXT RATS_MODEL=$RATS_MODEL bash $D/trust.sh setup" | tee "$OUT/up/trust-setup.txt"
  gscp "$TRUST:$D/public/workload-ca.pem" "$TRUST:$D/public/workload-ca-intermediate.crt" "$TRUST:$D/public/trust-tls-root.crt" \
    "$TRUST:$D/public/epoch.hex" "$TRUST:$D/public/policy.json" "$OUT/public/"
  log "core: the ledger trusts the bank's workload CA for client logins"
  gscp "$OUT/public/workload-ca.pem" "$CORE:~/"
  gssh "$CORE" "sudo cp ~/workload-ca.pem $D/public/ && sudo INTERNAL_IP=$CORE_INT EXTERNAL_IP=$CORE_EXT HINT=$(pack_hint) bash $D/core.sh setup && sudo bash $D/core.sh start" | tee "$OUT/up/core-setup.txt"
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

# payment-service configuration: public material only (trust anchors, the Vault's public keys, the epoch marker); the
# Targets and RRP identifiers come from the bank's pack
workload_config() { # tee out
  TEE="$1" P="$OUT/public" PACK="$PACK" python3 - > "$2" <<'PY'
import json, os
P, pack = os.environ["P"], json.load(open(os.environ["PACK"]))
kind = {r["name"]: r["kind"] for r in pack["rrps"] if "kind" in r}
rrp_id = {r["name"]: r["rrp_id"] for r in pack["rrps"]}
ledger = next(t for t in pack["targets"] if kind[t["rrp"]] == "credential-authority")
fraud = next(t for t in pack["targets"] if kind[t["rrp"]] == "secret-vault")
ca, vault = rrp_id[ledger["rrp"]], rrp_id[fraud["rrp"]]
keys = json.load(open(f"{P}/origin-keys.json"))
core_root = open(f"{P}/core-tls-root.crt").read()
print(json.dumps({"tee": os.environ["TEE"], "caapi": "127.0.0.1:50061", "hint": pack["workload"]["hint"],
  "ledger": {"target": ledger["target"], "host": "core.demobank.internal", "port": 5432, "database": "bank",
             "user": "payments", "server_ca_pem": core_root},
  "fraud": {"target": fraud["target"], "url": "https://core.demobank.internal:8444", "server_ca_pem": core_root},
  "relying_parties": {ledger["target"]: {"enroll": ca}, fraud["target"]: {"retrieve": vault}},
  "vault_origins": {vault: {k: v for k, v in keys.items() if k.startswith("DHKEM")}},
  # the hpke-base-signed container's trust anchor: the Vault's signature key, held for its RRP identifier
  "vault_signers": {vault: keys["ECDSA-P256-SHA256"]},
  # tacra-est N15: the CA the CAI holds for Enrollment, the bank's step-ca intermediate (public)
  "ca_anchors": {ca: open(f"{P}/workload-ca-intermediate.crt").read()},
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
  # step-ca logs each signing request's one-time token: single-use and expired by now, and not evidence
  python3 - "$1/trust-logs/step-ca.log" <<'PY'
import re, sys
try:
    s = open(sys.argv[1]).read()
except OSError:
    sys.exit(0)
open(sys.argv[1], "w").write(re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
                                    "REDACTED(single-use step-ca token, used and expired)", s))
PY
  spec="$(tr '\n' ' ' < "$1/.core-marks")"
  gssh "$CORE" "set -- $spec; echo '### postgresql'; sudo tail -n +\$((\$2 + 1)) /var/log/postgresql/postgresql-16-main.log; echo '### fraud-api'; sudo tail -n +\$((\$4 + 1)) $D/logs/fraud-api.log" \
    | awk -v dir="$1/core-logs" '/^### /{f=dir "/" $2 ".log"; printf "" > f; next} f != "" {print >> f}'
  rm -f "$1"/.trust-marks "$1"/.core-marks
}

guest_run() { # trust-zone-ip core-ip payments-flags how-to-ssh...
  local trust_ip="$1" core_ip="$2" flags="$3"; shift 3
  "$@" "
set -e
sudo modprobe sev-guest 2>/dev/null || sudo modprobe tdx_guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /sys/kernel/config/tsm/report 2>&1 || true
printf '%s trust.demobank.internal\n%s core.demobank.internal\n' $trust_ip $core_ip | sudo tee -a /etc/hosts >/dev/null
nohup ~/caapi-est -listen 127.0.0.1:50061 -est trust.demobank.internal:18443 -anchor ~/trust-tls-root.crt > ~/caapi-est.log 2>&1 &
echo \$! > ~/caapi-est.pid
sleep 1
sudo ~/payments -config ~/payments.json -from ACC-1001 -to ACC-2002 -amount 125.50 -out ~/report.json $flags 2>&1 || true
sudo chown \$(id -u):\$(id -g) ~/report.json
uname -a > ~/kernel.txt
kill \"\$(cat ~/caapi-est.pid)\" || true"
}

finish_run() { # run dir, expect: the run's verdict (scripts/verdict.py, kept in verdict.txt), then its seal
  local rc=0
  python3 "$HERE/scripts/verdict.py" bank-pay "$1" --expect "$2" --out "$1/verdict.txt" || rc=$?
  bench_seal "$1"
  return "$rc"
}

pay() {
  local kind="${1:-}" rs name R MACHINE=() FLAGS="" TEE=sev-snp EXPECT=pay
  case "$kind" in
    gcp-snp | gcp-tdx | aws-snp | ordinary | unapproved) ;;
    *) echo "pay: gcp-snp, gcp-tdx or aws-snp (a confidential VM), or the controls ordinary or unapproved" >&2; exit 2 ;;
  esac
  need_bank
  need_pack
  if [ "$kind" = aws-snp ]; then bench_aws; fi
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
  PAY_VM="$name"   # deleted however the run ends
  trap 'gcloud compute instances delete "$PAY_VM" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1' EXIT
  wait_ssh "$name"
  gscp "$ST/stage/workload/payments" "$ST/stage/workload/caapi-est" "$R/payments.json" "$OUT/public/trust-tls-root.crt" "$name:~/"
  log "$kind: run the payment service"
  guest_run "$TRUST_INT" "$CORE_INT" "$FLAGS" gssh "$name" | tee "$R/guest-stdout.txt"
  gscp "$name:~/report.json" "$name:~/caapi-est.log" "$name:~/kernel.txt" "$R/"
  gcloud compute instances describe "$name" --project="$PROJECT" --zone="$ZONE" \
    --format="yaml(name,machineType,confidentialInstanceConfig,cpuPlatform)" > "$R/instance.yaml" 2>/dev/null || true
  log "$kind: delete $name"
  gcloud compute instances delete "$name" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1 || true
  trap - EXIT
  [ -z "$(gcloud compute instances list --project="$PROJECT" --filter="name=$name" --format='value(name)')" ] \
    && echo "$name is gone" > "$R/vm-deleted.txt"
  slice_logs "$R"
  finish_run "$R" "$EXPECT"
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
  guest_run "$TRUST_EXT" "$CORE_EXT" "" ssh "${SSHO[@]}" "ubuntu@$IP" | tee "$R/guest-stdout.txt"
  scp "${SSHO[@]}" "ubuntu@$IP:~/report.json" "ubuntu@$IP:~/caapi-est.log" "ubuntu@$IP:~/kernel.txt" "$R/" >/dev/null 2>>"$OUT/ssh.stderr"
  log "aws-snp: terminate, delete the security group, key pair and firewall rule"
  aws_cleanup; trap - EXIT
  slice_logs "$R"
  finish_run "$R" pay
}

# approve a launch measurement on Google's signed firmware endorsement, then have the trust zone apply the policy
# A new TDX firmware build, approved only on Google's signed endorsement. A new SEV-SNP launch needs a reference value
# in Veraison's CoRIM as well (hwcheck/cmd/mkcorim; trust/README.md), so it is not approved here.
approve() { # tdx MRTD
  local tech="${1:?tdx}" m="${2:?MRTD}"
  need_bank
  [ "$tech" = tdx ] || { echo "approve: TDX only; a SEV-SNP launch needs a new CoRIM for Veraison too (trust/README.md)" >&2; exit 2; }
  (cd "$HERE/rrp" && go build -o "$ST/gce-endorsement" ./cmd/gce-endorsement)
  mkdir -p "$OUT/refvals"
  log "approve tdx $m: Google's endorsement, verified against the pinned GCE TCB root"
  "$ST/gce-endorsement" -root "$HERE/trust/GCE-cc-tcb-root_1.crt" -tdx "$m" -save "$OUT/refvals/tdx-$m.binarypb" \
    | tee "$OUT/refvals/tdx-$m.json"   # exits non-zero unless Google endorses it
  python3 - "$APPROVED" "$m" "$OUT/refvals/tdx-$m.json" <<'PY'
import json, re, sys
path, m, record = sys.argv[1:]
a, e = json.load(open(path)), json.load(open(record))
if m not in [x["mrtd"] for x in a["tdx"]]:
    signer = (re.search(r"CN=([^,]+)", e.get("signer", "")) or [None, "?"])[1]
    a["tdx"].append({"mrtd": m, "launch": "Google Cloud confidential VM with Intel TDX: Google's TDX firmware build",
                     "endorsement": f"Google's signed launch endorsement ({signer}), SVN {e['svn']}, {e['timestamp']}",
                     "checked": f"this bank's run directory: refvals/tdx-{m}.json"})
    with open(path, "w") as f:
        json.dump(a, f, indent=1)
PY
  log "trust zone: the new policy; the verifier and the gateways read it again"
  gscp "$APPROVED" "$TRUST:~/approved-launches.json"
  gssh "$TRUST" "sudo cp ~/approved-launches.json ${D:?}/trust/approved-launches.json && rm ~/approved-launches.json \
    && sudo RATS_MODEL=$RATS_MODEL bash $D/trust.sh config && sudo bash $D/trust.sh restart tdx-verifier ca-gateway vault-gateway" \
    | tee -a "$OUT/refvals/policy-changes.txt"
  gscp "$TRUST:$D/public/policy.json" "$OUT/public/policy.json"
}

audit() {
  need_bank
  mkdir -p "$OUT/audit"
  gssh "$CORE" "sudo bash $D/core.sh audit" | tee "$OUT/audit/ledger.txt"
  gssh "$TRUST" "sudo bash $D/trust.sh status" > "$OUT/audit/trust-status.txt"
  gssh "$CORE" "sudo bash $D/core.sh status" > "$OUT/audit/core-status.txt"
}

# Deletes every VM labelled purpose=demo-bank (the trust zone, the core, any payment VM a broken run left) and every
# demobank-* firewall rule, then checks both clouds and writes the bank's report. Without a bank in the state it still
# cleans up, and records it in a run directory of its own.
down() {
  [ -n "${OUT:-}" ] || OUT="$RUNS_DIR/$(date -u +%Y%m%dT%H%M%SZ)-demo-bank-down"
  mkdir -p "$OUT"
  local name zone fw
  gcloud compute instances list --project="$PROJECT" --filter='labels.purpose=demo-bank' --format='value(name,zone.basename())' \
    > "$ST/vms.list"
  while read -r name zone; do
    log "delete $name ($zone)"
    gcloud compute instances delete "$name" --project="$PROJECT" --zone="$zone" --quiet >/dev/null 2>&1 || true
  done < "$ST/vms.list"
  rm -f "$ST/vms.list"
  for fw in $(gcloud compute firewall-rules list --project="$PROJECT" --filter="name~^demobank-" --format='value(name)'); do
    gcloud compute firewall-rules delete "$fw" --project="$PROJECT" --quiet >/dev/null 2>&1
  done
  {
    echo "GCP instances labelled purpose=demo-bank: $(gcloud compute instances list --project="$PROJECT" --filter='labels.purpose=demo-bank' --format='value(name)' | wc -l | tr -d ' ')"
    echo "GCP instances in the project, any purpose: $(gcloud compute instances list --project="$PROJECT" --format='value(name)' | wc -l | tr -d ' ')"
    echo "GCP firewall rules demobank-*: $(gcloud compute firewall-rules list --project="$PROJECT" --filter='name~^demobank-' --format='value(name)' | wc -l | tr -d ' ')"
    # AWS only where this machine has a signed-in AWS CLI (the bank uses AWS for "pay aws-snp" alone)
    if command -v aws >/dev/null 2>&1 && aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1; then
      echo "AWS $AWS_REGION instances tagged purpose=demo-bank, not terminated: $(aws ec2 describe-instances --region "$AWS_REGION" \
        --filters Name=tag:purpose,Values=demo-bank Name=instance-state-name,Values=pending,running,stopping,stopped \
        --query 'length(Reservations[].Instances[])' --output text)"
      echo "AWS $AWS_REGION key pairs demobank-*: $(aws ec2 describe-key-pairs --region "$AWS_REGION" --filters 'Name=key-name,Values=demobank-*' --query 'length(KeyPairs)' --output text)"
      echo "AWS $AWS_REGION security groups demobank-*: $(aws ec2 describe-security-groups --region "$AWS_REGION" --filters 'Name=group-name,Values=demobank-*' --query 'length(SecurityGroups)' --output text)"
    else
      echo "AWS: not checked (no signed-in AWS CLI on this machine)"
    fi
  } | tee "$OUT/teardown.txt"
  rm -f "$ST/state" "$APPROVED"
  if [ -d "$OUT/up" ]; then
    python3 "$HERE/e2e/bank/report.py" "$OUT" >/dev/null && echo "== report: $OUT/README.md"
  fi
  bench_seal "$OUT"
  echo "== run directory: $OUT"
}

case "${1:-}" in
  up) up ;;
  provision) provision ;;
  pay) shift; pay "$@" ;;
  approve) shift; approve "$@" ;;
  audit) audit ;;
  down) down ;;
  *) echo "usage: $0 up | provision | pay gcp-snp|gcp-tdx|aws-snp|ordinary|unapproved | approve tdx MRTD | audit | down" >&2; exit 2 ;;
esac
