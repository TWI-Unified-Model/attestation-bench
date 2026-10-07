# End to end on AWS SEV-SNP, Passport, with no stand-in in the trust zone (2026-10-07, 14:18Z)

Plan 09, step N2: `RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=aws-snp`, at `355156d`.

**Verdict** (`verdict.txt`): VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party

Compared Target by Target with `20261007T054504Z-aws-sev-snp-e2e-passport`: 10 before, 10 after, 0 differ.

The VM was deleted and the deletion checked: `instance i-003d4aeb0fed6792a: terminated at 2026-10-07T14:20:02Z` (`vm-deleted.txt`).
