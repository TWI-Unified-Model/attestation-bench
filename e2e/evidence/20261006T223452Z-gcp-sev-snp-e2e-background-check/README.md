# e2e on GCP SEV-SNP, background-check (2026-10-06, 22:34Z): gate 5

Gate 5 of the attestation-bench plan: the S5 run again, from a bench set up from zero with `make setup` and run
with `make demo PLATFORM=...` (RATS model `background-check`), on the user's own cloud settings (`scripts/lib.sh`).

**Result:** 10 of 10 Targets: credential acquired and admitted by the relying party (`results.json`).

- Veraison's logs for this run hold 10 `affirming` SEV-SNP result(s) (`bench-logs/veraison-*.log`).
- Who asked the verifier: ca-gateway 5, vault-gateway 5 (`background-check: this RRP asks` in `bench-logs/`); the EST server forwarded the Evidence.
- Machine: `n2d-standard-2` (`machine-type.txt`).
- The VM was deleted and the deletion checked: `== tacra-e2e-2610062234 is gone` (`vm-deleted.txt`).
- Compared Target by Target with S5 `20261006T184448Z-gcp-sev-snp-e2e-background-check`: 10 Targets before, 10 after (10 ok), 0 differ (`compare-with-20261006T184448Z.txt`).
- Code: `code-revs.txt` (attestation-bench 0c82e2f6182a).
