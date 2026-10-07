# A launch the bench does not approve, on AWS SEV-SNP (2026-10-07, 14:13Z)

Plan 09, step N2: `UNAPPROVED=1 RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=aws-snp`, at `355156d`. The instance is a genuine SEV-SNP `c6a.xlarge` (`instance.txt`), four vCPUs, a launch the bench does not approve (the approved AWS launch is AWS's published firmware for two vCPUs, `trust/README.md`). Veraison appraised its VLEK-signed reports and did not affirm them: every Target refused with `ear: not affirming: SEVSNP is "contraindicated"`.

**Verdict** (`verdict.txt`): VERDICT PASS: 10 of 10 Targets refused, no credential issued, each with 'ear: not affirming: SEVSNP is'

The VM was deleted and the deletion checked: `instance i-04bee59ff04dfec1c: terminated at 2026-10-07T14:14:58Z` (`vm-deleted.txt`).
