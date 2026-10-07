# End to end on Google Cloud SEV-SNP, Passport, with no stand-in in the trust zone (2026-10-07, 14:15Z)

Plan 09, step N2: `RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=gcp-snp`, at `355156d`: the first run whose trust zone has no stand-in verifier and whose RRPs have no allowance for one (12 services; the verifiers `veraison` and `tdx`).

**Verdict** (`verdict.txt`): VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party

Compared Target by Target with `20261007T054201Z-gcp-sev-snp-e2e-passport`: 10 before, 10 after, 0 differ.

The VM was deleted and the deletion checked: `== tacra-e2e-2610071415 is gone at 2026-10-07T14:18:03Z` (`vm-deleted.txt`).
