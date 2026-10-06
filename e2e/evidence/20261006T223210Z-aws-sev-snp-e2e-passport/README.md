# e2e on AWS SEV-SNP (VLEK), passport (2026-10-06, 22:32Z): gate 5

Gate 5 of the attestation-bench plan: the S5 run again, from a bench set up from zero with `make setup` and run
with `make demo PLATFORM=...` (RATS model `passport`), on the user's own cloud settings (`scripts/lib.sh`).

**Result:** 10 of 10 Targets: credential acquired and admitted by the relying party (`results.json`).

- Veraison's logs for this run hold 10 `affirming` SEV-SNP result(s) (`bench-logs/veraison-*.log`).
- Who asked the verifier: the EST server (Passport); the gateways asked none (0 `background-check` lines in `bench-logs/`).
- Machine: see `instance.txt`.
- The VM was deleted and the deletion checked: `instance i-0c8d6a9972120ca3d: terminated` (`vm-deleted.txt`).
- Compared Target by Target with S5 `20261006T184014Z-aws-sev-snp-e2e-passport`: 10 Targets before, 10 after (10 ok), 0 differ (`compare-with-20261006T184014Z.txt`).
- Code: `code-revs.txt` (attestation-bench 0c82e2f6182a).
