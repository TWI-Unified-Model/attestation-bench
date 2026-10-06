#!/usr/bin/env bash
# Prints what the deployed Veraison was built from, read from its binaries (go version -m), so a run's evidence names
# the verifier that answered it, not whatever a source checkout holds now. One line per binary: the commit, whether
# the tree was modified at build time, the go-sev-guest version linked (- if none) and the first 16 hex of SHA-256.
#
#   e2e/scripts/veraison-build-info.sh [DEPLOYMENT]
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"
D="${1:-$VERAISON_DEPLOYMENT}"
for f in bin/verification-service bin/vts-service plugins/scheme-sevsnp.plugin; do
  info="$(go version -m "$D/$f")"
  rev="$(awk -F= '/vcs.revision/{print substr($2, 1, 12)}' <<<"$info")"
  mod="$(awk -F= '/vcs.modified/{print $2}' <<<"$info")"
  sev="$(awk '$2 == "github.com/google/go-sev-guest" {print $3}' <<<"$info")"
  echo "veraison $(basename "$f") rev ${rev:-?} modified ${mod:-?} go-sev-guest ${sev:--} sha256 $(shasum -a 256 "$D/$f" | cut -c1-16)"
done
