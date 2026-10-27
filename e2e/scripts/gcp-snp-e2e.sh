#!/usr/bin/env bash
# End-to-end run on a Google Cloud AMD SEV-SNP guest. In the guest: the workload (e2e-attester: the SIG's CAI with
# the SEV-SNP plug-in) and the CAS Client (caapi-est). On the test bench (this machine, e2e/scripts/bench.sh): the
# EST server, Veraison, the Credential Authority and Secret Vault gateways over step-ca and HashiCorp Vault, and the
# RATS-unaware mTLS service. The guest reaches the bench through an SSH reverse tunnel; TLS runs end to end over it.
# The guest receives trust anchors, the Vault's public origin keys and the epoch marker: nothing secret.
#
#   e2e/scripts/gcp-snp-e2e.sh                (make demo PLATFORM=gcp-snp)
#   TEE=tdx e2e/scripts/gcp-snp-e2e.sh        (make demo PLATFORM=gcp-tdx)
#
# GCP_PROJECT, GCP_ZONE: where the VM goes (scripts/lib.sh). RUNS_DIR: where the run directory goes (default
# BENCH_HOME/runs). The run ends with its verdict (scripts/verdict.py) and exits 1 unless every Target was admitted
# (refused, with OTHER_PLATFORM or UNAPPROVED).
#
# CAS_OUTSIDE=1 runs the CAS Client (caapi-est, the conduit) outside the guest, on this machine, and gives the
# workload's CAI the way to it through the reverse tunnel (tacra-est N1: "a run with the conduit outside the guest").
# OTHER_PLATFORM=1: the workload asks for the Targets that take another platform's verifier alone (tacra-est N24),
# and every one must be refused.
# UNAPPROVED=1 (SEV-SNP): the guest is an n2d-standard-4, whose launch (four vCPUs, four VMSAs in the measurement) is
# not one the bench approves (trust/approved-launches.json): Veraison does not affirm it, and every Target must be
# refused for it. A real VM, so the refusal is the hardware's measurement against the approved list.
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
[ $# -eq 0 ] || bench_die "no arguments: the project and zone come from GCP_PROJECT and GCP_ZONE (scripts/lib.sh)"
bench_gcp
PROJECT="$GCP_PROJECT" ZONE="$GCP_ZONE"
TEE="${TEE:-sev-snp}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-e2e-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
B="$BENCH_HOME"
# the bench's RATS model (bench.sh config, RATS_MODEL): who asks the verifiers
MODEL="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('rats_model') or 'passport')" "$B/config/vault-gateway.json")"
CAS_OUTSIDE="${CAS_OUTSIDE:-}"
OTHER_PLATFORM="${OTHER_PLATFORM:-}"
UNAPPROVED="${UNAPPROVED:-}"
CONDUIT_ATTACK="${CONDUIT_ATTACK:-}"
case "$CONDUIT_ATTACK" in "" | seal | swap | hint | hint-group | verifier | redirect) ;; *) bench_die "CONDUIT_ATTACK=$CONDUIT_ATTACK: seal, swap, hint, hint-group, verifier or redirect" ;; esac
[ -z "$CONDUIT_ATTACK" ] || [ -z "$OTHER_PLATFORM$UNAPPROVED" ] || bench_die "CONDUIT_ATTACK runs on its own, without OTHER_PLATFORM or UNAPPROVED"
GUEST_ATTACK="" # the CAS Client is the attacker of the container drills; of verifier, the EST server is (bench.sh config)
case "$CONDUIT_ATTACK" in seal | swap | hint | hint-group) GUEST_ATTACK=" -attack $CONDUIT_ATTACK" ;; esac
if [ "$CONDUIT_ATTACK" = verifier ]; then
  # the EST server is the attacker of this drill: the trust zone has to be configured with it
  python3 - "$B/config/est-server.json" <<'PY' || bench_die "CONDUIT_ATTACK=verifier: the EST server is not configured as the attacking conduit: CONDUIT_ATTACK=verifier make config && make start (and make config && make start to put it back)"
import json, sys
rrps = json.load(open(sys.argv[1]))["tacra"]["rrps"].values()
sys.exit(0 if any(r.get("conduit_attack") == "verifier" and r.get("rats_model", "passport") == "passport" for r in rrps) else 1)
PY
  [ -f "$B/est-conduit.log" ] || : > "$B/est-conduit.log"
fi
[ -z "$UNAPPROVED" ] || [ "$TEE" = sev-snp ] || bench_die "UNAPPROVED is for SEV-SNP: a TDX launch's MRTD does not change with the machine size"
EXPECT=(--expect admitted) # what the run must show (scripts/verdict.py)
[ -z "$OTHER_PLATFORM" ] || EXPECT=(--expect refused --reason "none of the verifiers this RRP takes for the Target")
[ -z "$UNAPPROVED" ] || EXPECT=(--expect refused --reason "ear: not affirming: SEVSNP is")
RUNS_DIR="${RUNS_DIR:-$B/runs}"
OUT="$RUNS_DIR/${STAMP}-gcp-${TEE}-e2e-${MODEL}${CAS_OUTSIDE:+-cas-outside}${OTHER_PLATFORM:+-other-platform}${UNAPPROVED:+-unapproved}${CONDUIT_ATTACK:+-conduit-$CONDUIT_ATTACK}${COPIES_OWN_KEYS:+-own-keys}"
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
SSH=(gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE")

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
if [ -n "$CAS_OUTSIDE" ]; then
  # the CAS Client for this machine; the guest gets none
  (cd "$HERE/e2e" && go build -trimpath -o "$BIN/caapi-est-local" ./cmd/caapi-est)
  shasum -a 256 "$BIN/caapi-est-local" | sed "s#$BIN/##" >> "$OUT/binaries.sha256"
  if nc -z 127.0.0.1 50061 2>/dev/null; then echo "!! port 50061 is taken on this machine"; exit 1; fi
fi

echo "== guest configuration (public material only)"
# the Vault gateway takes callers with a certificate of the bench (mutual TLS): the operator's
curl -sf --cacert "$B/tls/root.crt" --cert "$B/tls/clients/operator.crt" --key "$B/tls/clients/operator.key" https://127.0.0.1:9102/tacra/v1/origin-keys > "$BIN/origin-keys.json"
cp "$B/tls/root.crt" "$BIN/bench-tls-root.crt"
TEE="$TEE" B="$B" BIN="$BIN" TARGETS="${OTHER_PLATFORM:+other-platform}" python3 "$HERE/e2e/scripts/guest_config.py"
cp "$BIN/e2e-attester.json" "$OUT/e2e-attester.json"

if [ "$TEE" = tdx ]; then
  MACHINE=(--machine-type=c3-standard-4 --confidential-compute-type=TDX)
else
  MACHINE=(--machine-type=n2d-standard-2 --min-cpu-platform="AMD Milan" --confidential-compute-type=SEV_SNP)
  [ -z "$UNAPPROVED" ] || MACHINE=(--machine-type=n2d-standard-4 --min-cpu-platform="AMD Milan" --confidential-compute-type=SEV_SNP)
fi
echo "== create $NAME ($ZONE, $TEE)"
gcloud compute instances create "$NAME" --project="$PROJECT" --zone="$ZONE" "${MACHINE[@]}" \
  --maintenance-policy=TERMINATE --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB --labels=purpose=tacra-e2e,stamp="$(echo "$STAMP" | tr -d 'TZ')" "${GCP_GUEST_METADATA[@]}" >/dev/null
TUNNEL=""
CAS_PID=""
cleanup() {
  set +e
  [ -n "$TUNNEL" ] && kill "$TUNNEL" 2>/dev/null
  [ -n "$CAS_PID" ] && kill "$CAS_PID" 2>/dev/null
  echo "== delete $NAME"
  gcloud compute instances delete "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1
  left="$(gcloud compute instances list --project="$PROJECT" --filter="name=$NAME" --format='value(name)' 2>/dev/null)"
  if [ -n "$left" ]; then echo "!! $NAME still exists"; else echo "== $NAME is gone at $(bench_now)" | tee "$OUT/vm-deleted.txt"; fi
  rm -rf "$BIN"
}
trap cleanup EXIT

echo "== wait for ssh"
for _ in $(seq 1 30); do "${SSH[@]}" --command=true >/dev/null 2>&1 && break; sleep 10; done
"${SSH[@]}" --command='
set -e
sudo modprobe sev-guest 2>/dev/null || sudo modprobe tdx_guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /sys/kernel/config/tsm/report; uname -r' 2>>"$OUT/ssh.stderr" | tee "$OUT/provision.txt"

echo "== copy the workload, the CAS Client and the public configuration"
GUEST_FILES=("$BIN/e2e-attester" "$BIN/e2e-attester.json" "$BIN/bench-tls-root.crt" "$HERE/hwcheck/scripts/guest-clock.sh")
[ -n "$CAS_OUTSIDE" ] || GUEST_FILES+=("$BIN/caapi-est")
bench_retry "$OUT/ssh.stderr" gcloud compute scp "${GUEST_FILES[@]}" "$NAME:~/" --project="$PROJECT" --zone="$ZONE" >/dev/null
if [ -n "$CAS_OUTSIDE" ]; then
  echo "== the CAS Client outside the guest, on this machine (127.0.0.1:50061, through the tunnel to the guest)"
  ATTACK_ARGS=()
  case "$CONDUIT_ATTACK" in seal | swap | hint | hint-group) ATTACK_ARGS=(-attack "$CONDUIT_ATTACK") ;; esac
  "$BIN/caapi-est-local" -listen 127.0.0.1:50061 -est localhost:18443 -anchor "$B/tls/root.crt" ${ATTACK_ARGS[@]+"${ATTACK_ARGS[@]}"} \
    > "$OUT/caapi-est-outside.log" 2>&1 &
  CAS_PID=$!
  for _ in $(seq 1 20); do nc -z 127.0.0.1 50061 2>/dev/null && break; sleep 0.5; done
  echo "outside the guest: caapi-est on the bench machine, pid $CAS_PID, reached by the guest through ssh -R 50061" > "$OUT/cas-placement.txt"
else
  echo "inside the guest: caapi-est on 127.0.0.1:50061 of the guest" > "$OUT/cas-placement.txt"
fi

echo "== reverse tunnel to the bench (EST server 18443, mTLS service 19443)"
FWD=(-R 18443:127.0.0.1:18443 -R 19443:127.0.0.1:19443)
[ -n "$CAS_OUTSIDE" ] && FWD+=(-R 50061:127.0.0.1:50061)
# up to three tries: the tunnel is opened again when its SSH session ends (a connection that drops or times out); a
# run whose tunnel never comes up stops here, as none of its requests would reach the bench
UP=""
for try in 1 2 3; do
  "${SSH[@]}" -- -N -o ExitOnForwardFailure=yes "${FWD[@]}" 2>>"$OUT/ssh.stderr" &
  TUNNEL=$!
  for _ in $(seq 1 20); do
    kill -0 "$TUNNEL" 2>/dev/null || break
    "${SSH[@]}" --command='nc -z 127.0.0.1 18443 && nc -z 127.0.0.1 19443' >/dev/null 2>&1 && { UP=1; break; }
    sleep 3
  done
  [ -z "$UP" ] || break
  kill "$TUNNEL" 2>/dev/null || true
  echo "$(bench_now) the reverse tunnel is not up, try $try of 3" >>"$OUT/ssh.stderr"
done
[ -n "$UP" ] || bench_die "the reverse tunnel to the bench never came up ($OUT/ssh.stderr): no request of this run would reach it"

echo "== run in the guest"
NB="$(date -u +%s)"
if [ -n "$CAS_OUTSIDE" ]; then
  START_CAS='echo "the CAS Client is outside this guest" > ~/caapi-est.log; echo 0 > ~/caapi-est.pid'
else
  START_CAS="nohup ~/caapi-est -listen 127.0.0.1:50061 -est localhost:18443 -anchor ~/bench-tls-root.crt$GUEST_ATTACK > ~/caapi-est.log 2>&1 &
echo \$! > ~/caapi-est.pid
sleep 1"
fi
# detached from the SSH session: one that breaks costs a call, not the run (scripts/lib.sh)
# shellcheck disable=SC2016  # the $ in the single-quoted script expands in the guest, not here
bench_guest_run "$OUT/ssh.stderr" "
set -e
$START_CAS"'
sudo ~/e2e-attester -config ~/e2e-attester.json -out ~/results.json 2>&1
sudo chown $(id -u):$(id -g) ~/results.json; uname -a > ~/kernel.txt
sudo bash ~/guest-clock.sh ~ && sudo chown $(id -u):$(id -g) ~/clock.txt
(curl -s -H Metadata-Flavor:Google http://metadata.google.internal/computeMetadata/v1/instance/machine-type > ~/machine-type.txt || true)
[ "$(cat ~/caapi-est.pid)" = 0 ] || kill "$(cat ~/caapi-est.pid)" || true' "${SSH[@]}" --command | tee "$OUT/e2e-attester-stdout.txt"
NA="$(date -u +%s)"
echo "$NB $NA" > "$OUT/run-window.txt"
bench_clock_offset "$OUT/clock-offset.txt" "${SSH[@]}" --command
bench_retry "$OUT/ssh.stderr" gcloud compute scp "$NAME:~/results.json" "$NAME:~/caapi-est.log" "$NAME:~/kernel.txt" \
  "$NAME:~/machine-type.txt" "$NAME:~/clock.txt" "$OUT/" --project="$PROJECT" --zone="$ZONE" >/dev/null
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
  python3 "$HERE/scripts/verdict.py" conduit "$OUT" --attack "$CONDUIT_ATTACK" --out "$OUT/verdict.txt" || rc=$?
else
  python3 "$HERE/scripts/verdict.py" demo "$OUT" "${EXPECT[@]}" --out "$OUT/verdict.txt" || rc=$?
fi
bench_seal "$OUT"
echo "== run directory: $OUT"
exit "$rc"
