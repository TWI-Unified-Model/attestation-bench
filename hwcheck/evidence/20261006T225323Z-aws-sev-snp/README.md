# hwcheck on AWS SEV-SNP (VLEK) (2026-10-06, 22:53Z): gate 5

Gate 5 of the attestation-bench plan: the S5 run again, from a bench set up from zero with `make setup` and run
with `make attacks PLATFORM=...` on the user's own cloud settings (`scripts/lib.sh`).

**Results** (the last line of each `rrpverify-*.txt`):

- `rrpverify-service.txt`: 50 checks, 0 not as expected; written /Users/serhiinikolaichuk/dev/attestation-bench/hwcheck/evidence/20261006T225323Z-aws-sev-snp/rrpverify-service.json
- `rrpverify-veraison-fixed.txt`: 122 checks, 120 not as expected; written /Users/serhiinikolaichuk/dev/attestation-bench/hwcheck/evidence/20261006T225323Z-aws-sev-snp/rrpverify-veraison-fixed.json
- `rrpverify-veraison-fork.txt`: 122 checks, 120 not as expected; written /Users/serhiinikolaichuk/dev/attestation-bench/hwcheck/evidence/20261006T225323Z-aws-sev-snp/rrpverify-veraison-fork.json
- `rrpverify-veraison-v015.txt`: 162 checks, 0 not as expected; written /Users/serhiinikolaichuk/dev/attestation-bench/hwcheck/evidence/20261006T225323Z-aws-sev-snp/rrpverify-veraison-v015.json

**Compared check by check with S5 `20261006T190213Z-aws-sev-snp`:**

- `compare-service-with-20261006T190213Z.txt`: 50 checks before, 50 after, 0 differ
- `compare-veraison-fixed-with-20261006T190213Z.txt`: 122 checks before, 122 after, 0 differ
- `compare-veraison-fork-with-20261006T190213Z.txt`: 122 checks before, 122 after, 0 differ
- `compare-veraison-v015-with-20261006T190213Z.txt`: 162 checks before, 162 after, 0 differ
- The VM was deleted and the deletion checked: instance i-009a5754b79f5a9d5: terminated; security group sg-04ccef39a2927aa0a deleted; key pair tacra-hwcheck-2610062253 deleted (`vm-deleted.txt`).
- Code: `code-rev.txt` (0c82e2f6182a).
