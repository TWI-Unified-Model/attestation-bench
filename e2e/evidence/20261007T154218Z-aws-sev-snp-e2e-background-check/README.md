# End to end on AWS SEV-SNP, Background Check, the EST library without the mock TEE (2026-10-07, 15:42Z)

Plan 09, step N7: with the bench in Background Check (`RATS_MODEL=background-check make config`, `make stop start`),
`RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=aws-snp`, at `e1bcdcf`. The EST server was built from EST patches
0001-0011, Veraison from patches 0001-0008 and go-gen-ref from patches 0001-0003, each the tested tree
(`code-revs.txt`). The report is signed with a VLEK.

**Verdict** (`verdict.txt`): VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party

Compared Target by Target with `20261007T055226Z-aws-sev-snp-e2e-background-check`: 10 before, 10 after, 0 differ.

The instance was terminated and the deletion checked: `instance i-06bf0b1b63bd75a7f: terminated at
2026-10-07T15:44:15Z`, with its security group and key pair deleted (`vm-deleted.txt`); afterwards no instance in
us-east-2 was in any state but terminated.
