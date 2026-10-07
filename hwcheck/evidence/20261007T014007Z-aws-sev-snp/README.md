# hwcheck on AWS SEV-SNP (VLEK) (2026-10-07, 01:40Z): gate 7

Gate 7 of the attestation-bench plan: every command in the docs run as they write it, at the release's code. The command: `RUNS_DIR="$PWD/hwcheck/evidence" AWS_REGION=us-east-2 make attacks PLATFORM=aws-snp`. Code: attestation-bench `83dea653cf72`.

**Verdict** (`verdict.txt`):

- rrpverify-service: 50 checks, 0 not as expected
- rrpverify-veraison-fixed: 122 checks, 120 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-fork: 122 checks, 120 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-v015: 162 checks, 0 not as expected
- VERDICT PASS: 212 checks: the honest Evidence passed, every attack refused for its own reason

**Compared check by check with gate 5's `20261006T225323Z-aws-sev-snp`:**

- `compare-service-with-20261006T225323Z.txt`: 50 checks before, 50 after, 0 differ
- `compare-veraison-fixed-with-20261006T225323Z.txt`: 122 checks before, 122 after, 0 differ
- `compare-veraison-fork-with-20261006T225323Z.txt`: 122 checks before, 122 after, 0 differ
- `compare-veraison-v015-with-20261006T225323Z.txt`: 162 checks before, 162 after, 0 differ
- The VM was deleted and the deletion checked: `instance i-09e3c1b469facd741: terminated at 2026-10-07T01:42:06Z` (`vm-deleted.txt`), 119 s after the run started.
