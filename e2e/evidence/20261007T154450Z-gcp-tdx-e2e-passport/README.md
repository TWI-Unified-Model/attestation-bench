# End to end on Google Cloud TDX, Passport, the EST library without the mock TEE (2026-10-07, 15:44Z)

Plan 09, step N7: `RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=gcp-tdx`, at `e1bcdcf`, the bench back in Passport
(`make config`, `make stop start`). The EST server was built from EST patches 0001-0011, Veraison from patches
0001-0008 and go-gen-ref from patches 0001-0003, each the tested tree (`code-revs.txt`).

**Verdict** (`verdict.txt`): VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party

Compared Target by Target with `20261007T054706Z-gcp-tdx-e2e-passport`: 10 before, 10 after, 0 differ.

The VM was deleted and the deletion checked: `== tacra-e2e-2610071544 is gone at 2026-10-07T15:47:13Z`
(`vm-deleted.txt`); `gcloud compute instances list` showed no instance afterwards, and no AWS instance was in any
state but terminated.
