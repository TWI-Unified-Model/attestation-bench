#!/usr/bin/env bash
# End-to-end run on a Google Cloud AMD SEV-SNP guest. In the guest: the workload (e2e-attester: the SIG's CAI with
# the SEV-SNP plug-in) and the CAS Client (caapi-est). On the test bench (this machine, e2e/scripts/bench.sh): the
# EST server, Veraison, the Credential Authority and Secret Vault gateways over step-ca and HashiCorp Vault, and the
# RATS-unaware mTLS service. The guest reaches the bench through an SSH reverse tunnel; TLS runs end to end over it.
# The guest receives trust anchors, the Vault's public origin keys and the epoch marker: nothing secret.
#
#   e2e/scripts/gcp-snp-e2e.sh [PROJECT] [ZONE]
set -euo pipefail
PROJECT="${1:-rats-probe}"
ZONE="${2:-us-central1-c}"
TEE="${TEE:-sev-snp}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-e2e-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
B="${TACRA_BENCH:-$HOME/tacra-bench}"
# the bench's RATS model (bench.sh config, RATS_MODEL): who asks the verifiers
MODEL="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('rats_model') or 'passport')" "$B/config/vault-gateway.json")"
OUT="$HERE/e2e/evidence/${STAMP}-gcp-${TEE}-e2e-${MODEL}"
BIN="$(mktemp -d)"
export CLOUDSDK_CORE_DISABLE_PROMPTS=1 GOWORK=off
mkdir -p "$OUT/bench-logs"
SSH=(gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE")

echo "== bench"
"$HERE/e2e/scripts/bench.sh" status | tee "$OUT/bench-status.txt"
if grep -q stopped "$OUT/bench-status.txt"; then echo "!! start the bench first: e2e/scripts/bench.sh start"; exit 1; fi
{ echo "twi-tacra $(git -C "$HERE" rev-parse --short=12 HEAD)$(git -C "$HERE" diff --quiet HEAD -- platform cai bundle rrp e2e/cmd || echo -dirty)"
  echo "globalsign-est $(git -C "$HOME/dev/globalsign-est" rev-parse --short=12 HEAD)"
  echo "veraison-services $(git -C "$HOME/dev/veraison-services-der" rev-parse --short=12 HEAD)"
  # the deployed verification service may be built from another commit (tacra/verification-client-ca): its hash
  echo "veraison verification-service sha256 $(shasum -a 256 "$HOME/veraison-deployment/bin/verification-service" | cut -c1-16)"; } > "$OUT/code-revs.txt"
echo "$MODEL" > "$OUT/rats-model.txt"
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
       "vault_origins": {"https://vault1.tacra.example": {k: v for k, v in json.load(open(f"{BIN}/origin-keys.json")).items()
                                                          if k.startswith("DHKEM")}},
       # the hpke-base-signed container's trust anchor: the Vault's signature key, held for its RRP identifier
       "vault_signers": {"https://vault1.tacra.example": json.load(open(f"{BIN}/origin-keys.json"))["ECDSA-P256-SHA256"]},
       "local_epoch_hex": open(f"{B}/epoch.hex").read().strip(),
       "rup": {"url": "https://localhost:19443", "anchor_pem": open(f"{B}/tls/root.crt").read()}}
json.dump(cfg, open(f"{BIN}/e2e-attester.json", "w"), indent=1)
PY
cp "$BIN/e2e-attester.json" "$OUT/e2e-attester.json"

if [ "$TEE" = tdx ]; then
  MACHINE=(--machine-type=c3-standard-4 --confidential-compute-type=TDX)
else
  MACHINE=(--machine-type=n2d-standard-2 --min-cpu-platform="AMD Milan" --confidential-compute-type=SEV_SNP)
fi
echo "== create $NAME ($ZONE, $TEE)"
gcloud compute instances create "$NAME" --project="$PROJECT" --zone="$ZONE" "${MACHINE[@]}" \
  --maintenance-policy=TERMINATE --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB --labels=purpose=tacra-e2e,stamp="$(echo "$STAMP" | tr -d 'TZ')" --metadata=enable-oslogin=TRUE >/dev/null
TUNNEL=""
cleanup() {
  set +e
  [ -n "$TUNNEL" ] && kill "$TUNNEL" 2>/dev/null
  echo "== delete $NAME"
  gcloud compute instances delete "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1
  left="$(gcloud compute instances list --project="$PROJECT" --filter="name=$NAME" --format='value(name)' 2>/dev/null)"
  if [ -n "$left" ]; then echo "!! $NAME still exists"; else echo "== $NAME is gone" | tee "$OUT/vm-deleted.txt"; fi
  rm -rf "$BIN"
}
trap cleanup EXIT

echo "== wait for ssh"
for i in $(seq 1 30); do "${SSH[@]}" --command=true >/dev/null 2>&1 && break; sleep 10; done
"${SSH[@]}" --command='
set -e
sudo modprobe sev-guest 2>/dev/null || sudo modprobe tdx_guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /sys/kernel/config/tsm/report; uname -r' 2>>"$OUT/ssh.stderr" | tee "$OUT/provision.txt"

echo "== copy the workload, the CAS Client and the public configuration"
gcloud compute scp "$BIN/e2e-attester" "$BIN/caapi-est" "$BIN/e2e-attester.json" "$BIN/bench-tls-root.crt" "$NAME:~/" \
  --project="$PROJECT" --zone="$ZONE" >/dev/null 2>>"$OUT/ssh.stderr"

echo "== reverse tunnel to the bench (EST server 18443, mTLS service 19443)"
"${SSH[@]}" -- -N -o ExitOnForwardFailure=yes -R 18443:127.0.0.1:18443 -R 19443:127.0.0.1:19443 2>>"$OUT/ssh.stderr" &
TUNNEL=$!
for i in $(seq 1 20); do "${SSH[@]}" --command='nc -z 127.0.0.1 18443 && nc -z 127.0.0.1 19443' >/dev/null 2>&1 && break; sleep 3; done

echo "== run in the guest"
NB="$(date -u +%s)"
"${SSH[@]}" --command='
set -e
nohup ~/caapi-est -listen 127.0.0.1:50061 -est localhost:18443 -anchor ~/bench-tls-root.crt > ~/caapi-est.log 2>&1 &
echo $! > ~/caapi-est.pid
sleep 1
sudo ~/e2e-attester -config ~/e2e-attester.json -out ~/results.json 2>&1
sudo chown $(id -u):$(id -g) ~/results.json; uname -a > ~/kernel.txt
(curl -s -H Metadata-Flavor:Google http://metadata.google.internal/computeMetadata/v1/instance/machine-type > ~/machine-type.txt || true)
kill "$(cat ~/caapi-est.pid)" || true' 2>>"$OUT/ssh.stderr" | tee "$OUT/e2e-attester-stdout.txt"
NA="$(date -u +%s)"
echo "$NB $NA" > "$OUT/run-window.txt"
gcloud compute scp "$NAME:~/results.json" "$NAME:~/caapi-est.log" "$NAME:~/kernel.txt" "$NAME:~/machine-type.txt" "$OUT/" \
  --project="$PROJECT" --zone="$ZONE" >/dev/null 2>>"$OUT/ssh.stderr"
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
