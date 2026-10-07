# A launch the bench does not approve, on Google Cloud SEV-SNP (2026-10-07, 14:09Z)

Plan 09, step N2: `UNAPPROVED=1 RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=gcp-snp`, at `355156d`. The guest is a genuine SEV-SNP VM, an `n2d-standard-4` (`machine-type.txt`): four vCPUs, so a launch measurement that is not among the approved ones (`trust/approved-launches.json`). Veraison appraised its real reports and did not affirm them: every Target refused with `ear: not affirming: SEVSNP is "contraindicated"`. This replaces the software stand-in's `SIM_LABEL` scenario with the hardware's own measurement.

**Verdict** (`verdict.txt`): VERDICT PASS: 10 of 10 Targets refused, no credential issued, each with 'ear: not affirming: SEVSNP is'

The VM was deleted and the deletion checked: `== tacra-e2e-2610071409 is gone at 2026-10-07T14:13:01Z` (`vm-deleted.txt`).
