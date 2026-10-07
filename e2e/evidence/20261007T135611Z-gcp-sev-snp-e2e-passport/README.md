# End to end on Google Cloud SEV-SNP, Passport, after the PoC's simulated parts left the tree (2026-10-07, 13:56Z)

Plan 09, step N1: the live check after the proof of concept's simulated parts left the tree. The command: `RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=gcp-snp`, at `15a58e0` (`code-revs.txt`). The CAI and the SEV-SNP plug-in the workload runs are the ones that stayed.

**Verdict** (`verdict.txt`): VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party

Compared Target by Target with `20261007T054201Z-gcp-sev-snp-e2e-passport` (the release's last): 10 before, 10 after, 0 differ (`e2e/scripts/compare-e2e.py`).

The VM was deleted and the deletion checked: `== tacra-e2e-2610071356 is gone at 2026-10-07T13:59:13Z` (`vm-deleted.txt`).
