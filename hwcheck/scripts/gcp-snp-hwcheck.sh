#!/usr/bin/env bash
# Runs hwrun in a live AMD SEV-SNP guest on Google Cloud and verifies what it wrote with rrpverify against the
# veraison-services fork as it is, with the DER and signer-info fixes, and with those fixes on go-sev-guest v0.15.0
# with AMD's roots for VCEK and VLEK (third_party/veraison-services). Creates the VM, mints the Freshness
# Handles (RRP side), copies hwrun and the handles in, runs it as root (configfs-tsm), copies the output back,
# deletes the VM and checks that it is gone.
#
#   hwcheck/scripts/gcp-snp-hwcheck.sh        (make attacks PLATFORM=gcp-snp)
#
# GCP_PROJECT, GCP_ZONE: where the VM goes (scripts/lib.sh). RUNS_DIR: where the run directory goes (default
# BENCH_HOME/runs). Cost: one n2d-standard-2 confidential VM for ~10 minutes.
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"   # BENCH_HOME, VERAISON_DEPLOYMENT, pinned tools
[ $# -eq 0 ] || bench_die "no arguments: the project and zone come from GCP_PROJECT and GCP_ZONE (scripts/lib.sh)"
bench_gcp
PROJECT="$GCP_PROJECT" ZONE="$GCP_ZONE"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-hwcheck-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
HW="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HW/.." && pwd)"
CODE_REV="$(git -C "$REPO" rev-parse --short=12 HEAD)$(git -C "$REPO" diff --quiet HEAD -- platform cai hwcheck/cmd || echo -dirty)"
RUNS_DIR="${RUNS_DIR:-$BENCH_HOME/runs}"
OUT="$RUNS_DIR/${STAMP}-gcp-sev-snp"
BIN="$(mktemp -d)"
mkdir -p "$OUT"
echo "$CODE_REV" > "$OUT/code-rev.txt"

echo "== build hwrun (linux/amd64) and rrpverify (three Veraison builds)"
(cd "$HW" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/hwrun" ./cmd/hwrun)
(cd "$HW" && go build -o "$BIN/rrpverify-fork" ./cmd/rrpverify && go build -modfile=go.patched.mod -o "$BIN/rrpverify-fixed" ./cmd/rrpverify \
  && go build -modfile=go.v015.mod -o "$BIN/rrpverify-v015" ./cmd/rrpverify)
shasum -a 256 "$BIN/hwrun" | awk '{print $1"  hwrun (linux/amd64)"}' > "$OUT/binaries.sha256"
{ # in-process builds: fork = src-fork, fixed = src-der, v015 = src (third_party/veraison-services/UPSTREAM)
  "$REPO/third_party/describe.sh" veraison-services go-gen-ref
  "$REPO/e2e/scripts/veraison-build-info.sh"; } > "$OUT/veraison-revs.txt"

echo "== RRP mints the Freshness Handles"
"$BIN/rrpverify-fork" mint -out "$OUT/handles.json"

echo "== create $NAME ($ZONE, n2d-standard-2, SEV_SNP)"
gcloud compute instances create "$NAME" --project="$PROJECT" --zone="$ZONE" \
  --machine-type=n2d-standard-2 --min-cpu-platform="AMD Milan" \
  --confidential-compute-type=SEV_SNP --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB --labels=purpose=tacra-hwcheck,stamp="$(echo "$STAMP" | tr -d 'TZ')" \
  --metadata=enable-oslogin=TRUE >/dev/null
cleanup() {
  echo "== delete $NAME"
  gcloud compute instances delete "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1 || true
  left="$(gcloud compute instances list --project="$PROJECT" --filter="name=$NAME" --format='value(name)' 2>/dev/null)"
  if [ -n "$left" ]; then echo "!! $NAME still exists"; else echo "== $NAME is gone" | tee "$OUT/vm-deleted.txt"; fi
}
trap 'cleanup; rm -rf "$BIN"' EXIT

echo "== wait for ssh"
for _ in $(seq 1 30); do
  if gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --command='true' >/dev/null 2>&1; then break; fi
  sleep 10
done

echo "== provision: sev-guest module, configfs-tsm"
# shellcheck disable=SC2016  # the $ in the single-quoted script expands in the guest, not here
gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --command='
set -e
sudo modprobe sev-guest 2>/dev/null || true
if [ ! -e /dev/sev-guest ]; then sudo apt-get update -qq >/dev/null; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-modules-extra-$(uname -r) >/dev/null; sudo modprobe sev-guest || true; fi
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /dev/sev-guest /sys/kernel/config/tsm/report
uname -r
'

echo "== copy hwrun and the handles"
gcloud compute scp "$BIN/hwrun" "$OUT/handles.json" "$NAME:~/" --project="$PROJECT" --zone="$ZONE" >/dev/null

echo "== run hwrun as root"
NB="$(date -u +%s)"
gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --command="
set -e
sudo ~/hwrun -handles ~/handles.json -out /root/hwrun-out -burst 100 2>&1
sudo sh -c 'cd /root/hwrun-out && uname -a > kernel.txt && (dmesg 2>/dev/null | grep -i -E \"sev|snp|tsm\" > dmesg-sev.txt || true) && (curl -s -H Metadata-Flavor:Google http://metadata.google.internal/computeMetadata/v1/instance/machine-type > machine-type.txt || true) && date -u +%s > guest-clock.txt'
sudo chmod -R a+rX /root/hwrun-out; rm -rf ~/hwrun-out; sudo cp -r /root/hwrun-out ~/hwrun-out; sudo chown -R \$(id -u):\$(id -g) ~/hwrun-out
" 2>>"$OUT/run-ssh.stderr" | tee "$OUT/hwrun-stdout.txt"
NA="$(date -u +%s)"
echo "$NB $NA" > "$OUT/rrp-clock-window.txt"

echo "== copy the output back"
gcloud compute scp --recurse "$NAME:~/hwrun-out/*" "$OUT/" --project="$PROJECT" --zone="$ZONE" >/dev/null
trap 'rm -rf "$BIN"' EXIT
cleanup

echo "== RRP verification: Veraison fork as it is, with the DER and signer-info fixes, and on v0.15.0 with AMD roots"
cp "$REPO/trust/amd-kds-milan-cert_chain.pem" "$OUT/amd-kds-milan-cert_chain.pem"
for v in fork fixed v015; do
  "$BIN/rrpverify-$v" verify -in "$OUT" -handles "$OUT/handles.json" -ark "$OUT/amd-kds-milan-cert_chain.pem" \
    -not-before "$NB" -not-after "$NA" -out "$OUT/rrpverify-veraison-$v.json" | tee "$OUT/rrpverify-veraison-$v.txt"
done
if curl -sf --cacert "$VERAISON_DEPLOYMENT/certs/rootCA.crt" --cert "$BENCH_HOME/tls/clients/ca-gateway.crt" \
  --key "$BENCH_HOME/tls/clients/ca-gateway.key" https://localhost:8443/.well-known/veraison/verification >/dev/null 2>&1; then
  echo "== RRP verification through the deployed Veraison service (https://localhost:8443)"
  "$BIN/rrpverify-fixed" service -in "$OUT" -handles "$OUT/handles.json" -not-before "$NB" -not-after "$NA" \
    -out "$OUT/rrpverify-service.json" | tee "$OUT/rrpverify-service.txt"
fi
bench_seal "$OUT"
echo "== run directory: $OUT"
