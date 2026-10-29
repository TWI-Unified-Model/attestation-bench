#!/usr/bin/env bash
# End-to-end run on an AWS EC2 AMD SEV-SNP guest (shared tenancy: VLEK-signed reports). In the guest: the workload
# (e2e-attester: the SIG's CAI with the SEV-SNP plug-in) and the CAS Client (caapi-est). On the test bench (this
# machine): the EST server, Veraison, the CA and Vault gateways over step-ca and HashiCorp Vault, and the mTLS
# service. The guest reaches the bench through an SSH reverse tunnel; TLS runs end to end over it. A throwaway key
# pair and a security group admitting SSH from this address only are deleted with the instance.
#
#   e2e/scripts/aws-snp-e2e.sh                (make demo PLATFORM=aws-snp)
#
# AWS_REGION, AWS_AZ: where the instance goes (scripts/lib.sh). RUNS_DIR: where the run directory goes (default
# BENCH_HOME/runs). Env: TYPE (default c6a.large), AMI_PARAM (SSM parameter of the image; default Ubuntu 24.04).
# OTHER_PLATFORM=1: the workload asks for the Targets that take another platform's verifier alone (tacra-est N24),
# and every one must be refused. UNAPPROVED=1: the instance is a c6a.xlarge, whose launch (four vCPUs) the bench does
# not approve (trust/approved-launches.json): Veraison does not affirm it, and every Target must be refused for it.
# The run ends with its verdict (scripts/verdict.py) and exits 1 unless every Target was admitted (refused, with
# OTHER_PLATFORM or UNAPPROVED).
# CONDUIT_ATTACK=redirect: the EST server, as the conduit, routes every request to the second Credential Authority and
# the second Secret Vault, the RRPs the Attester did not ask for (CONDUIT_ATTACK=redirect make config; COPIES_OWN_KEYS=1
# gives the second Vault keys of its own); the run is judged by what the CAI does with what comes back (verdict conduit).
# CONDUIT_ATTACK=seal|swap|hint|hint-group: the CAS Client is the attacker of docs/attacks.md, section 6, in the
# Retrieval container (caapi-est -attack): seal returns a container it sealed itself, swap the Vault's container of
# the Retrieval before, hint and hint-group ask the Vault with another Credential Hint. The run is judged by what the CAI does with
# it (scripts/verdict.py conduit): every Enrollment admitted, each Retrieval refused for the drill's reason.
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"   # BENCH_HOME, VERAISON_DEPLOYMENT, pinned tools
[ $# -eq 0 ] || bench_die "no arguments: the region and zone come from AWS_REGION and AWS_AZ (scripts/lib.sh)"
bench_aws
REGION="$AWS_REGION" AZ="$AWS_AZ"
TYPE="${TYPE:-c6a.large}"
AMI_PARAM="${AMI_PARAM:-/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id}"
TEE=sev-snp
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-e2e-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
B="$BENCH_HOME"
# the bench's RATS model (bench.sh config, RATS_MODEL): who asks the verifiers
MODEL="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('rats_model') or 'passport')" "$B/config/vault-gateway.json")"
OTHER_PLATFORM="${OTHER_PLATFORM:-}"
UNAPPROVED="${UNAPPROVED:-}"
CONDUIT_ATTACK="${CONDUIT_ATTACK:-}"
case "$CONDUIT_ATTACK" in "" | seal | swap | hint | hint-group | verifier | redirect) ;; *) bench_die "CONDUIT_ATTACK=$CONDUIT_ATTACK: seal, swap, hint, hint-group, verifier or redirect" ;; esac
[ -z "$CONDUIT_ATTACK" ] || [ -z "$OTHER_PLATFORM$UNAPPROVED" ] || bench_die "CONDUIT_ATTACK runs on its own, without OTHER_PLATFORM or UNAPPROVED"
ORIGIN_AUTH="${ORIGIN_AUTH:-on}" # off: the Vault's Targets release containers without origin authentication, and the
case "$ORIGIN_AUTH" in on | off) ;; *) bench_die "ORIGIN_AUTH=$ORIGIN_AUTH: on or off" ;; esac # workload holds no Vault key
if [ "$ORIGIN_AUTH" = off ]; then
  python3 - "$B/config/vault-gateway.json" <<'PY' || bench_die "ORIGIN_AUTH=off: the trust zone's Secret Vault still signs: ORIGIN_AUTH=off make config && make start (and make config && make start to restore it)"
import json, sys
targets = json.load(open(sys.argv[1]))["targets"].values()
sys.exit(0 if targets and all(t.get("sign") is False for t in targets) else 1)
PY
fi
GUEST_ATTACK="" # the CAS Client is the attacker of the container drills; of verifier, the EST server is (bench.sh config)
case "$CONDUIT_ATTACK" in seal | swap | hint | hint-group) GUEST_ATTACK=" -attack $CONDUIT_ATTACK" ;; esac
[ "$ORIGIN_AUTH" = on ] || [ "$CONDUIT_ATTACK" != seal ] || GUEST_ATTACK="$GUEST_ATTACK -no-origin" # its container as the Vault's: unsigned
if [ "$CONDUIT_ATTACK" = verifier ]; then
  # the EST server is the attacker of this drill: the trust zone has to be configured with it
  python3 - "$B/config/est-server.json" <<'PY' || bench_die "CONDUIT_ATTACK=verifier: the EST server is not configured as the attacking conduit: CONDUIT_ATTACK=verifier make config && make start (and make config && make start to put it back)"
import json, sys
rrps = json.load(open(sys.argv[1]))["tacra"]["rrps"].values()
sys.exit(0 if any(r.get("conduit_attack") == "verifier" and r.get("rats_model", "passport") == "passport" for r in rrps) else 1)
PY
  [ -f "$B/est-conduit.log" ] || : > "$B/est-conduit.log"
fi
EXPECT=(--expect admitted) # what the run must show (scripts/verdict.py)
[ -z "$OTHER_PLATFORM" ] || EXPECT=(--expect refused --reason "none of the verifiers this RRP takes for the Target")
# UNAPPROVED=1: a c6a.xlarge, whose launch (four vCPUs) the bench does not approve; every Target must be refused for it
[ -z "$UNAPPROVED" ] || { TYPE=c6a.xlarge; EXPECT=(--expect refused --reason "ear: not affirming: SEVSNP is"); }
RUNS_DIR="${RUNS_DIR:-$B/runs}"
OUT="$RUNS_DIR/${STAMP}-aws-${TEE}-e2e-${MODEL}${OTHER_PLATFORM:+-other-platform}${UNAPPROVED:+-unapproved}${CONDUIT_ATTACK:+-conduit-$CONDUIT_ATTACK}${COPIES_OWN_KEYS:+-own-keys}$([ "$ORIGIN_AUTH" = on ] || echo -no-origin-auth)"
BIN="$(mktemp -d)"
mkdir -p "$OUT/bench-logs"
if [ "$CONDUIT_ATTACK" = redirect ]; then
  # the EST server, as the conduit, routes every Target to the copies of the RRPs (bench.sh config, CONDUIT_ATTACK=redirect);
  # the run keeps the routing it ran under, and whether the copies had keys of their own (COPIES_OWN_KEYS=1)
  python3 - "$B/config/est-server.json" "$OUT/bench-logs/est-routing.json" "${COPIES_OWN_KEYS:-}" <<'PY' || bench_die "CONDUIT_ATTACK=redirect: the EST server is not configured as the redirecting conduit (CONDUIT_ATTACK=redirect make config)"
import json, sys
c = json.load(open(sys.argv[1]))["tacra"]
targets = {t: {"rrp": r, "url": c["rrps"][r]["url"]} for t, r in c["targets"].items()}
if not all(r.endswith("-2") for r in c["targets"].values()):
    sys.exit("not every Target is routed to a copy: " + json.dumps(c["targets"]))
json.dump({"attack": "redirect", "copies_own_keys": sys.argv[3] == "1", "targets": targets}, open(sys.argv[2], "w"), indent=1)
PY
fi
ID="" SG="" KEY="$NAME"
echo "== bench"
"$HERE/e2e/scripts/bench.sh" status | tee "$OUT/bench-status.txt"
if grep -q stopped "$OUT/bench-status.txt"; then echo "!! start the bench first: make start"; exit 1; fi
{ echo "attestation-bench $(git -C "$HERE" rev-parse --short=12 HEAD)$(git -C "$HERE" diff --quiet HEAD -- platform cai bundle rrp e2e/cmd || echo -dirty)"
  # the sources of the EST server and of the deployed Veraison (upstream commit, our patches, tree)
  "$HERE/third_party/describe.sh" globalsign-est veraison-services go-gen-ref | grep -v -e '/src-fork ' -e '/src-der '
  # the deployed Veraison, as its binaries say they were built
  "$HERE/e2e/scripts/veraison-build-info.sh"; cat "$B/est-source.txt" 2>/dev/null; } > "$OUT/code-revs.txt"
echo "$MODEL" > "$OUT/rats-model.txt"
# the platform rule the RRPs apply (trust/platform-policy.json, as scripts/trustzone.py gave it to them)
python3 -c "import json,sys; json.dump(json.load(open(sys.argv[1])).get('platform'), sys.stdout, indent=1)" \
  "$B/config/vault-gateway.json" > "$OUT/platform-rule.json"
# the EST server writes every attest-* exchange to its wire log (scripts/trustzone.py, wire_log), from its start
[ -f "$B/est-wire.log" ] || bench_die "no EST wire log in $B: the EST server runs with an older configuration;" \
  "make config, then make stop start"
[ -f "$B/est-conduit.log" ] || : > "$B/est-conduit.log"
for f in est-server est-wire est-conduit ca-gateway ca-gateway-2 vault-gateway vault-gateway-2 rup tdx-verifier; do { [ -f "$B/$f.log" ] && wc -l < "$B/$f.log" || echo 0; } > "$OUT/bench-logs/.$f.start"; done
wc -l < "$VERAISON_DEPLOYMENT/logs/vts.log" > "$OUT/bench-logs/.vts.start"
wc -l < "$VERAISON_DEPLOYMENT/logs/verification.log" > "$OUT/bench-logs/.verification.start"

echo "== build (linux/amd64)"
(cd "$HERE/e2e" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/e2e-attester" ./cmd/e2e-attester \
  && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/caapi-est" ./cmd/caapi-est)
shasum -a 256 "$BIN/e2e-attester" "$BIN/caapi-est" | sed "s#$BIN/##" > "$OUT/binaries.sha256"

echo "== guest configuration (public material only)"
# the Vault gateway takes callers with a certificate of the bench (mutual TLS): the operator's
curl -sf --cacert "$B/tls/root.crt" --cert "$B/tls/clients/operator.crt" --key "$B/tls/clients/operator.key" https://127.0.0.1:9102/tacra/v1/origin-keys > "$BIN/origin-keys.json"
cp "$B/tls/root.crt" "$BIN/bench-tls-root.crt"
TEE="$TEE" B="$B" BIN="$BIN" TARGETS="${OTHER_PLATFORM:+other-platform}" ORIGIN_AUTH="$ORIGIN_AUTH" python3 "$HERE/e2e/scripts/guest_config.py"
cp "$BIN/e2e-attester.json" "$OUT/e2e-attester.json"

cleanup() {
  set +e
  [ -n "${TUNNEL:-}" ] && kill "$TUNNEL" 2>/dev/null
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
for _ in $(seq 1 40); do "${SSH[@]}" true >/dev/null 2>&1 && break; sleep 10; done
"${SSH[@]}" '
set -e
sudo modprobe sev-guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /sys/kernel/config/tsm/report; uname -r' 2>>"$OUT/ssh.stderr" | tee "$OUT/provision.txt"

echo "== copy the workload, the CAS Client and the public configuration"
bench_retry "$OUT/ssh.stderr" scp "${SSHO[@]}" "$BIN/e2e-attester" "$BIN/caapi-est" "$BIN/e2e-attester.json" \
  "$BIN/bench-tls-root.crt" "$HERE/hwcheck/scripts/guest-clock.sh" "ubuntu@$IP:~/" >/dev/null

echo "== reverse tunnel to the bench (EST server 18443, mTLS service 19443)"
# up to three tries: the tunnel is opened again when its SSH session ends (a connection that drops or times out); a
# run whose tunnel never comes up stops here, as none of its requests would reach the bench
UP=""
for try in 1 2 3; do
  ssh "${SSHO[@]}" -N -o ExitOnForwardFailure=yes -R 18443:127.0.0.1:18443 -R 19443:127.0.0.1:19443 "ubuntu@$IP" 2>>"$OUT/ssh.stderr" &
  TUNNEL=$!
  for _ in $(seq 1 20); do
    kill -0 "$TUNNEL" 2>/dev/null || break
    "${SSH[@]}" 'nc -z 127.0.0.1 18443 && nc -z 127.0.0.1 19443' >/dev/null 2>&1 && { UP=1; break; }
    sleep 3
  done
  [ -z "$UP" ] || break
  kill "$TUNNEL" 2>/dev/null || true
  echo "$(bench_now) the reverse tunnel is not up, try $try of 3" >>"$OUT/ssh.stderr"
done
[ -n "$UP" ] || bench_die "the reverse tunnel to the bench never came up ($OUT/ssh.stderr): no request of this run would reach it"

echo "== run in the guest"
NB="$(date -u +%s)"
# detached from the SSH session: one that breaks costs a call, not the run (scripts/lib.sh)
# shellcheck disable=SC2016  # the $ in the single-quoted script expands in the guest, not here
bench_guest_run "$OUT/ssh.stderr" '
set -e
nohup ~/caapi-est -listen 127.0.0.1:50061 -est localhost:18443 -anchor ~/bench-tls-root.crt'"$GUEST_ATTACK"' > ~/caapi-est.log 2>&1 &
echo $! > ~/caapi-est.pid
sleep 1
sudo ~/e2e-attester -config ~/e2e-attester.json -out ~/results.json 2>&1
sudo chown $(id -u):$(id -g) ~/results.json; uname -a > ~/kernel.txt
sudo bash ~/guest-clock.sh ~ && sudo chown $(id -u):$(id -g) ~/clock.txt
kill "$(cat ~/caapi-est.pid)" || true' "${SSH[@]}" | tee "$OUT/e2e-attester-stdout.txt"
NA="$(date -u +%s)"
echo "$NB $NA" > "$OUT/run-window.txt"
bench_clock_offset "$OUT/clock-offset.txt" "${SSH[@]}"
bench_retry "$OUT/ssh.stderr" scp "${SSHO[@]}" "ubuntu@$IP:~/results.json" "ubuntu@$IP:~/caapi-est.log" \
  "ubuntu@$IP:~/kernel.txt" "ubuntu@$IP:~/clock.txt" "$OUT/" >/dev/null
trap 'rm -rf "$BIN"' EXIT
cleanup

echo "== bench logs for the run"
for f in est-server est-wire est-conduit ca-gateway ca-gateway-2 vault-gateway vault-gateway-2 rup tdx-verifier; do [ -f "$B/$f.log" ] || continue; tail -n +"$(( $(cat "$OUT/bench-logs/.$f.start") + 1 ))" "$B/$f.log" | grep -v "TLS handshake error" > "$OUT/bench-logs/$f.log" || true; done
tail -n +"$(( $(cat "$OUT/bench-logs/.vts.start") + 1 ))" "$VERAISON_DEPLOYMENT/logs/vts.log" | grep -v DEBUG > "$OUT/bench-logs/veraison-vts.log" || true
# Veraison's verification API: who asked for each session (client-ca)
tail -n +"$(( $(cat "$OUT/bench-logs/.verification.start") + 1 ))" "$VERAISON_DEPLOYMENT/logs/verification.log" | grep -v DEBUG \
  > "$OUT/bench-logs/veraison-verification.log" || true
rm -f "$OUT"/bench-logs/.*.start
rc=0
if [ -n "$CONDUIT_ATTACK" ]; then
  python3 "$HERE/scripts/verdict.py" conduit "$OUT" --attack "$CONDUIT_ATTACK" --origin-auth "$ORIGIN_AUTH" --out "$OUT/verdict.txt" || rc=$?
else
  python3 "$HERE/scripts/verdict.py" demo "$OUT" "${EXPECT[@]}" --out "$OUT/verdict.txt" || rc=$?
fi
bench_seal "$OUT"
echo "== run directory: $OUT"
exit "$rc"
