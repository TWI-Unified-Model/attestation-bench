# e2e on GCP SEV-SNP, Passport (2026-10-07, 01:09Z): gate 7

Gate 7 of the attestation-bench plan: every command in the docs run as they write it, at the release's code. The command: `RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=gcp-snp`. Code: attestation-bench `f7908200478e`.

**VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party** (`verdict.txt`).

- Machine: `n2d-standard-2` (`machine-type.txt`).
- The VM was deleted and the deletion checked: `tacra-e2e-2610070109 is gone at 2026-10-07T01:12:40Z` (`vm-deleted.txt`), 172 s after the run started.
- Compared Target by Target with gate 5's `20261006T222601Z-gcp-sev-snp-e2e-passport`: 10 Targets before, 10 after (10 ok), 0 differ (`compare-with-20261006T222601Z.txt`).
