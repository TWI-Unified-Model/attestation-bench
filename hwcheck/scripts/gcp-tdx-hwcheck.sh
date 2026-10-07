#!/usr/bin/env bash
# Runs hwrun in a live Intel TDX Trust Domain on Google Cloud and verifies what it wrote with rrpverify (TDX quotes
# are checked with go-tdx-guest against Intel PCS collateral: the veraison-services fork has no TDX scheme). Creates
# the VM, mints the Freshness Handles (RRP side), copies hwrun and the handles in, runs it as root (configfs-tsm),
# copies the output back, deletes the VM and checks that it is gone.
#
#   hwcheck/scripts/gcp-tdx-hwcheck.sh        (make attacks PLATFORM=gcp-tdx)
#
# GCP_PROJECT, GCP_ZONE: where the VM goes (scripts/lib.sh). RUNS_DIR: where the run directory goes (default
# BENCH_HOME/runs). Cost: one c3-standard-4 confidential VM for ~10 minutes.
# The run ends with its verdict (scripts/verdict.py) and exits 1 unless every check came out as expected.
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"   # BENCH_HOME, pinned tools, cloud settings
[ $# -eq 0 ] || bench_die "no arguments: the project and zone come from GCP_PROJECT and GCP_ZONE (scripts/lib.sh)"
bench_gcp
PROJECT="$GCP_PROJECT" ZONE="$GCP_ZONE"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-hwcheck-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
HW="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$HW/.." && pwd)"
CODE_REV="$(git -C "$REPO" rev-parse --short=12 HEAD)$(git -C "$REPO" diff --quiet HEAD -- platform cai hwcheck/cmd || echo -dirty)"
RUNS_DIR="${RUNS_DIR:-$BENCH_HOME/runs}"
OUT="$RUNS_DIR/${STAMP}-gcp-tdx"
BIN="$(mktemp -d)"
mkdir -p "$OUT"
echo "$CODE_REV" > "$OUT/code-rev.txt"

echo "== build hwrun (linux/amd64) and rrpverify"
(cd "$HW" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$BIN/hwrun" ./cmd/hwrun)
(cd "$HW" && go build -o "$BIN/rrpverify" ./cmd/rrpverify)
shasum -a 256 "$BIN/hwrun" | awk '{print $1"  hwrun (linux/amd64)"}' > "$OUT/binaries.sha256"
echo "TDX quotes verified with github.com/google/go-tdx-guest $(cd "$HW" && go list -m -f '{{.Version}}' github.com/google/go-tdx-guest)" > "$OUT/verifier.txt"

echo "== RRP mints the Freshness Handles"
"$BIN/rrpverify" mint -out "$OUT/handles.json"

echo "== create $NAME ($ZONE, c3-standard-4, TDX)"
gcloud compute instances create "$NAME" --project="$PROJECT" --zone="$ZONE" \
  --machine-type=c3-standard-4 \
  --confidential-compute-type=TDX --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB --labels=purpose=tacra-hwcheck,stamp="$(echo "$STAMP" | tr -d 'TZ')" \
  --metadata=enable-oslogin=TRUE >/dev/null
cleanup() {
  echo "== delete $NAME"
  gcloud compute instances delete "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1 || true
  left="$(gcloud compute instances list --project="$PROJECT" --filter="name=$NAME" --format='value(name)' 2>/dev/null)"
  if [ -n "$left" ]; then echo "!! $NAME still exists"; else echo "== $NAME is gone at $(bench_now)" | tee "$OUT/vm-deleted.txt"; fi
}
trap 'cleanup; rm -rf "$BIN"' EXIT

echo "== wait for ssh"
for _ in $(seq 1 30); do
  if gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --command='true' >/dev/null 2>&1; then break; fi
  sleep 10
done

echo "== provision: tdx_guest, configfs-tsm"
gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --command='
set -e
sudo modprobe tdx_guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
ls -ld /dev/tdx_guest /sys/kernel/config/tsm/report
uname -r
'

echo "== copy hwrun and the handles"
bench_retry "$OUT/run-ssh.stderr" gcloud compute scp "$BIN/hwrun" "$OUT/handles.json" "$NAME:~/" --project="$PROJECT" \
  --zone="$ZONE" >/dev/null

echo "== run hwrun as root"
NB="$(date -u +%s)"
gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --command="
set -e
sudo ~/hwrun -tee tdx -handles ~/handles.json -out /root/hwrun-out -burst 30 2>&1
sudo sh -c 'cd /root/hwrun-out && uname -a > kernel.txt && (dmesg 2>/dev/null | grep -i -E \"tdx|tsm|confidential\" > dmesg-tdx.txt || true) && (curl -s -H Metadata-Flavor:Google http://metadata.google.internal/computeMetadata/v1/instance/machine-type > machine-type.txt || true) && date -u +%s > guest-clock.txt'
sudo chmod -R a+rX /root/hwrun-out; rm -rf ~/hwrun-out; sudo cp -r /root/hwrun-out ~/hwrun-out; sudo chown -R \$(id -u):\$(id -g) ~/hwrun-out
" 2>>"$OUT/run-ssh.stderr" | tee "$OUT/hwrun-stdout.txt"
NA="$(date -u +%s)"
echo "$NB $NA" > "$OUT/rrp-clock-window.txt"

echo "== copy the output back"
bench_retry "$OUT/run-ssh.stderr" gcloud compute scp --recurse "$NAME:~/hwrun-out/*" "$OUT/" --project="$PROJECT" \
  --zone="$ZONE" >/dev/null
trap 'rm -rf "$BIN"' EXIT
cleanup

echo "== RRP verification (go-tdx-guest, Intel PCS collateral)"
"$BIN/rrpverify" verify -in "$OUT" -handles "$OUT/handles.json" -not-before "$NB" -not-after "$NA" \
  -out "$OUT/rrpverify-tdx.json" > "$OUT/rrpverify-tdx.txt" 2> "$OUT/rrpverify-tdx.stderr.log"
rc=0
python3 "$BENCH_REPO/scripts/verdict.py" attacks "$OUT" --out "$OUT/verdict.txt" || rc=$?
bench_seal "$OUT"
echo "== run directory: $OUT"
exit "$rc"
