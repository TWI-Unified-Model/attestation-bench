# End to end on Google Cloud SEV-SNP, Passport, the EST server without a mock CA (2026-10-07, 15:15Z)

Plan 09, step N4: `RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=gcp-snp`, at `220e75c`, the bench back in Passport
(`make config`, `make stop start`). The EST server was built from EST patches 0001-0010 (no mock CA, the configuration
read strictly), Veraison from patches 0001-0008 and go-gen-ref from patches 0001-0003, each the tested tree
(`code-revs.txt`).

**Verdict** (`verdict.txt`): VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party

Compared Target by Target with `20261007T141502Z-gcp-sev-snp-e2e-passport`, the run of step N2: 10 before, 10 after,
0 differ.

The VM was deleted and the deletion checked: `== tacra-e2e-2610071515 is gone at 2026-10-07T15:18:15Z`
(`vm-deleted.txt`); `gcloud compute instances list` showed no instance afterwards.
