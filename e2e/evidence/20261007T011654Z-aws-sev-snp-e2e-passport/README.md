# e2e on AWS SEV-SNP (VLEK), Passport (2026-10-07, 01:16Z): gate 7

Gate 7 of the attestation-bench plan: every command in the docs run as they write it, at the release's code. The command: `RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=aws-snp`. Code: attestation-bench `31be7049807f`.

**VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party** (`verdict.txt`).

- The VM was deleted and the deletion checked: `instance i-07854ab18940491ff: terminated at 2026-10-07T01:18:47Z` (`vm-deleted.txt`), 113 s after the run started.
- Compared Target by Target with gate 5's `20261006T223210Z-aws-sev-snp-e2e-passport`: 10 Targets before, 10 after (10 ok), 0 differ (`compare-with-20261006T223210Z.txt`).
