# hwcheck on GCP SEV-SNP (2026-10-07, 01:32Z): gate 7

Gate 7 of the attestation-bench plan: every command in the docs run as they write it, at the release's code. The command: `RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=gcp-snp`. Code: attestation-bench `83dea653cf72`.

**Verdict** (`verdict.txt`):

- rrpverify-service: 50 checks, 0 not as expected
- rrpverify-veraison-fixed: 162 checks, 0 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-fork: 142 checks, 60 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-v015: 162 checks, 0 not as expected
- VERDICT PASS: 212 checks: the honest Evidence passed, every attack refused for its own reason

**Compared check by check with gate 5's `20261006T224346Z-gcp-sev-snp`:**

- `compare-service-with-20261006T224346Z.txt`: 50 checks before, 50 after, 0 differ
- `compare-veraison-fixed-with-20261006T224346Z.txt`: 162 checks before, 162 after, 0 differ
- `compare-veraison-fork-with-20261006T224346Z.txt`: 142 checks before, 142 after, 0 differ
- `compare-veraison-v015-with-20261006T224346Z.txt`: 162 checks before, 162 after, 0 differ
- The VM was deleted and the deletion checked: `tacra-hwcheck-2610070132 is gone at 2026-10-07T01:37:21Z` (`vm-deleted.txt`), 272 s after the run started.
