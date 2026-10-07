# e2e on GCP TDX, Passport (2026-10-07, 01:12Z): gate 7

Gate 7 of the attestation-bench plan: every command in the docs run as they write it, at the release's code. The command: `RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=gcp-tdx`. Code: attestation-bench `f7908200478e`.

**VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party** (`verdict.txt`).

- Machine: `c3-standard-4` (`machine-type.txt`).
- The VM was deleted and the deletion checked: `tacra-e2e-2610070112 is gone at 2026-10-07T01:15:09Z` (`vm-deleted.txt`), 142 s after the run started.
- Compared Target by Target with gate 5's `20261006T222921Z-gcp-tdx-e2e-passport`: 10 Targets before, 10 after (10 ok), 0 differ (`compare-with-20261006T222921Z.txt`).
