# e2e on AWS SEV-SNP (VLEK), Passport, with Veraison on go-sev-guest v0.15.0 (06.10.2026, 18:40Z)

This repeats `20261006T160602Z-aws-sev-snp-e2e` with the only change being the Verifier.
- The Verifier is Veraison `2d18260`: go-sev-guest v0.15.0 with AMD's roots for VCEK and VLEK
  (`hwcheck/evidence/20261006T181314Z-veraison-go-sev-guest-v0.15.0`).
- On go-sev-guest v0.15.0 without those roots, Veraison refuses every AWS report.
- `code-revs.txt` names the deployed Veraison from its binaries.

- RATS model: Passport (`rats-model.txt`; the AWS script records it from this run on).
- Machine: c6a.large, us-east-2, shared tenancy.
- Cleanup: the instance was terminated and the key pair and security group deleted (`vm-deleted.txt`). Afterwards the
  region had 0 instances, 0 tacra security groups, 0 tacra key pairs and 0 volumes.

**Result:** 10 of 10 Targets. The credential was acquired and admitted by the relying party (`results.json`).
- Veraison evaluated 10 SEV-SNP attestations, all `affirming` (`bench-logs/veraison-vts.log`).
- Compared Target by Target with `20261006T160602Z`: 0 differ (`compare-with-160602Z.txt`).

**Signing key.** This e2e run does not save the reports, so the signing key is not recorded here per Target.
- Every AWS report saved today records SIGNING_KEY = VLEK: 30 of 30, in `hwcheck/evidence/20261006T161751Z-aws-sev-snp`
  and `20261006T174402Z-aws-snp-redirect`.
- The hwcheck and #20 reruns on this Verifier save and record theirs.
