# e2e on AWS SEV-SNP (VLEK), Background Check, with Veraison on go-sev-guest v0.15.0 (06.10.2026, 18:51Z)

The same run as `20261006T184014Z-aws-sev-snp-e2e-passport`, with the bench in the Background Check model
(`rats-model.txt`).
- The Verifier is Veraison `2d18260`, go-sev-guest v0.15.0 with AMD's roots for VCEK and VLEK (`code-revs.txt`).
- Machine: c6a.large, us-east-2.
- Cleanup: the instance was terminated and the key pair and security group deleted (`vm-deleted.txt`). Afterwards the
  region had 0 instances, 0 tacra security groups, 0 tacra key pairs and 0 volumes.

**The model took effect.** Veraison's verification log names the callers: 5 `ca-gateway` and 5 `vault-gateway`. Under
Passport all 10 were `est-server`.

**Result:** 10 of 10 Targets. The credential was acquired and admitted by the relying party (`results.json`).
- Veraison evaluated 10 SEV-SNP attestations, all `affirming`.
- Compared Target by Target with the Passport run: 0 differ (`compare-with-184014Z-passport.txt`).
- The signing key is not saved by e2e runs; see the Passport run's README.
