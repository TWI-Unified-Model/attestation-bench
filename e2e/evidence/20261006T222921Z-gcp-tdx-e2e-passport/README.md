# e2e on GCP TDX, passport (2026-10-06, 22:29Z): gate 5

Gate 5 of the attestation-bench plan: the S5 run again, from a bench set up from zero with `make setup` and run
with `make demo PLATFORM=...` (RATS model `passport`), on the user's own cloud settings (`scripts/lib.sh`).

**Result:** 10 of 10 Targets: credential acquired and admitted by the relying party (`results.json`).

- The TDX verifier's log for this run has 10 `affirming` line(s) (`bench-logs/tdx-verifier.log`).
- Who asked the verifier: the EST server (Passport); the gateways asked none (0 `background-check` lines in `bench-logs/`).
- Machine: `c3-standard-4` (`machine-type.txt`).
- The VM was deleted and the deletion checked: `== tacra-e2e-2610062229 is gone` (`vm-deleted.txt`).
- Compared Target by Target with S5 `20261006T183654Z-gcp-tdx-e2e-passport`: 10 Targets before, 10 after (10 ok), 0 differ (`compare-with-20261006T183654Z.txt`).
- Code: `code-revs.txt` (attestation-bench 0c82e2f6182a).
