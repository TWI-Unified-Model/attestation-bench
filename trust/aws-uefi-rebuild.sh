#!/usr/bin/env bash
# Rebuilds AWS's EC2 SEV-SNP UEFI from its source, as AWS's README says (github.com/aws/uefi: `nix-build --pure`), for
# each release given, on a fresh Google Cloud VM, and compares the build with the binary AWS published for that release:
# their SHA-256, how many octets differ, and the launch measurement sev-snp-measure computes for each. It records what
# a rebuild gives; the approved AWS launch rests on AWS's published binary, which trust/check.sh measures again.
#
#   trust/aws-uefi-rebuild.sh [RELEASE...]        (default: 20260814 20240809)
#
# RUNS_DIR: where the run directory goes (default BENCH_HOME/runs). The VM is deleted at the end and its deletion
# checked (vm-deleted.txt).
set -euo pipefail
# shellcheck source=SCRIPTDIR/../scripts/lib.sh
. "$(cd "$(dirname "$0")/.." && pwd)/scripts/lib.sh"
bench_gcp
NIX_VERSION=2.35.2
MEASURE="sev-snp-measure==0.0.13"
VCPUS=2 # c6a.large, the machine of the approved AWS launch
[ $# -gt 0 ] || set -- 20260814 20240809
RUNS_DIR="${RUNS_DIR:-$BENCH_HOME/runs}"
OUT="$RUNS_DIR/$(date -u +%Y%m%dT%H%M%SZ)-aws-uefi-rebuild"
mkdir -p "$OUT"
git -C "$BENCH_REPO" rev-parse --short=12 HEAD >"$OUT/code-rev.txt"
NAME="tacra-awsuefi-$(date -u +%m%d%H%M)"
SSH=(gcloud compute ssh "$NAME" --project="$GCP_PROJECT" --zone="$GCP_ZONE")
cleanup() {
  set +e
  gcloud compute instances delete "$NAME" --project="$GCP_PROJECT" --zone="$GCP_ZONE" --quiet >/dev/null 2>&1
  local left
  left="$(gcloud compute instances list --project="$GCP_PROJECT" --filter="name=$NAME" --format='value(name)' 2>/dev/null)"
  if [ -n "$left" ]; then echo "!! $NAME still exists"; else echo "== $NAME is gone at $(bench_now)" | tee "$OUT/vm-deleted.txt"; fi
}
trap cleanup EXIT

echo "== create $NAME (e2-standard-8, Ubuntu 24.04, 80 GB) in $GCP_PROJECT/$GCP_ZONE"
gcloud compute instances create "$NAME" --project="$GCP_PROJECT" --zone="$GCP_ZONE" --machine-type=e2-standard-8 \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud --boot-disk-size=80GB \
  --labels=purpose=tacra-awsuefi --metadata=enable-oslogin=TRUE >/dev/null 2>>"$OUT/ssh.stderr"
echo "== wait for ssh"
for _ in $(seq 1 30); do "${SSH[@]}" --command=true >/dev/null 2>&1 && break; sleep 10; done

echo "== in the VM: Nix $NIX_VERSION (its installer checked against its SHA-256), $MEASURE; each release built and measured"
# shellcheck disable=SC2016  # the $ in the single-quoted part expands in the guest, not here
bench_guest_run "$OUT/ssh.stderr" "set -euo pipefail
RELEASES='$*' NIX_VERSION=$NIX_VERSION MEASURE='$MEASURE' VCPUS=$VCPUS"'
sudo apt-get update -qq && sudo apt-get install -y -qq git xz-utils python3-venv >/dev/null 2>&1
curl -sfL -o /tmp/install https://releases.nixos.org/nix/nix-$NIX_VERSION/install
echo "$(curl -sfL https://releases.nixos.org/nix/nix-$NIX_VERSION/install.sha256)  /tmp/install" | sha256sum -c -
sh /tmp/install --no-daemon --yes > /tmp/nix-install.log 2>&1 || { tail -20 /tmp/nix-install.log; exit 1; }
. ~/.nix-profile/etc/profile.d/nix.sh
echo "nix: $(nix --version)"
python3 -m venv ~/m && ~/m/bin/pip install -q "$MEASURE"
echo "sev-snp-measure: $(~/m/bin/pip show sev-snp-measure 2>/dev/null | sed -n "s/^Version: //p")"
git clone -q https://github.com/aws/uefi.git ~/uefi
for r in $RELEASES; do
  echo "## release $r"
  cd ~/uefi && git checkout -q "refs/tags/$r" && echo "commit $(git rev-parse HEAD)"
  t0=$(date +%s); nix-build --pure > ~/nix-build-$r.log 2>&1 || { tail -30 ~/nix-build-$r.log; exit 1; }
  echo "nix-build: $(( $(date +%s) - t0 )) s, $(readlink result)"
  cp result/ovmf_img.fd ~/built-$r.fd
  curl -sfL -o ~/released-$r.fd "https://github.com/aws/uefi/releases/download/$r/ovmf_img.fd"
  echo "built    sha256 $(sha256sum < ~/built-$r.fd | cut -d" " -f1), $(stat -c %s ~/built-$r.fd) octets"
  echo "released sha256 $(sha256sum < ~/released-$r.fd | cut -d" " -f1), $(stat -c %s ~/released-$r.fd) octets"
  # cmp exits 1 when the files differ; the || true keeps that from failing the pipe under pipefail
  echo "octets that differ: $({ cmp -l ~/built-$r.fd ~/released-$r.fd || true; } | wc -l)"
  first=$({ cmp ~/built-$r.fd ~/released-$r.fd || true; } | sed -n -E "s/.*differ: (byte|char) ([0-9]+).*/\2/p")
  echo "first octet that differs (counted from 1): ${first:-none}"
  echo "measure built    ($VCPUS vCPUs, ec2): $(~/m/bin/sev-snp-measure --mode snp --vcpus $VCPUS --vmm-type ec2 --ovmf ~/built-$r.fd)"
  echo "measure released ($VCPUS vCPUs, ec2): $(~/m/bin/sev-snp-measure --mode snp --vcpus $VCPUS --vmm-type ec2 --ovmf ~/released-$r.fd)"
done' "${SSH[@]}" --command | tee "$OUT/rebuild.txt"

# the approved launch, for the reader to compare with the measurements above
python3 -c 'import json,sys; [print("approved AWS launch:", e["measurement"]) for e in json.load(open(sys.argv[1]))["sev-snp"] if "firmware" in e]' \
  "$BENCH_REPO/trust/approved-launches.json" | tee -a "$OUT/rebuild.txt"
trap - EXIT
cleanup
bench_seal "$OUT"
echo "== run directory: $OUT"
