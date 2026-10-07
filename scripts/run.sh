#!/usr/bin/env bash
# The bench's three experiments, on real hardware in your own cloud account:
#
#   scripts/run.sh demo|attacks|redirect PLATFORM        (make demo|attacks|redirect PLATFORM=...)
#
#   demo      end to end: the workload acquires a credential for each of 10 Targets and presents it to the Relying
#             Party
#   attacks   the substitution suite: honest Evidence, then one attack per changed input, each to be refused for its
#             own reason
#   redirect  the #20 redirection experiment: one Evidence offered to two Credential Authorities, with and without the
#             RRP identifier in the binding
#
# PLATFORM is where the TEE runs:
#   gcp-snp   a Google Cloud AMD SEV-SNP VM (n2d-standard-2)
#   gcp-tdx   a Google Cloud Intel TDX VM (c3-standard-4)
#   aws-snp   an AWS EC2 AMD SEV-SNP instance (c6a.large)
#
# A run creates one VM in your account (GCP_PROJECT, GCP_ZONE, AWS_REGION, AWS_AZ: scripts/lib.sh), deletes it at the
# end and checks that it is gone. Every run writes a run directory under RUNS_DIR (default BENCH_HOME/runs). Nothing
# stands in for the hardware: there is no run without it.
set -euo pipefail
R="$(cd "$(dirname "$0")/.." && pwd)"
usage() { echo "usage: scripts/run.sh demo|attacks|redirect gcp-snp|gcp-tdx|aws-snp" >&2; exit 2; }
[ $# -eq 2 ] || usage
platform="$2"
case "$1/$platform" in
  demo/gcp-snp)    exec env TEE=sev-snp "$R/e2e/scripts/gcp-snp-e2e.sh" ;;
  demo/gcp-tdx)    exec env TEE=tdx "$R/e2e/scripts/gcp-snp-e2e.sh" ;;
  demo/aws-snp)    exec "$R/e2e/scripts/aws-snp-e2e.sh" ;;
  attacks/gcp-snp) exec "$R/hwcheck/scripts/gcp-snp-hwcheck.sh" ;;
  attacks/gcp-tdx) exec "$R/hwcheck/scripts/gcp-tdx-hwcheck.sh" ;;
  attacks/aws-snp) exec "$R/hwcheck/scripts/aws-snp-hwcheck.sh" ;;
  redirect/gcp-snp | redirect/gcp-tdx | redirect/aws-snp)
    exec "$R/hwcheck/scripts/redirect.sh" "$platform" ;;
  *) usage ;;
esac
