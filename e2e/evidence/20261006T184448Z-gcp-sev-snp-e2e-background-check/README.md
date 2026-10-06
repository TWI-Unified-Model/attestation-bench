# e2e on GCP SEV-SNP, Background Check, with Veraison on go-sev-guest v0.15.0 (06.10.2026, 18:44Z)

The same run as `20261006T182621Z-gcp-sev-snp-e2e-passport`, with the bench in the Background Check model
(`rats-model.txt`). The Verifier is Veraison `2d18260` (`code-revs.txt`, read from the binaries). The VM was deleted
and the deletion checked (`vm-deleted.txt`); afterwards the project had 0 instances and 0 disks.

**The model took effect.** Veraison's verification log (`bench-logs/veraison-verification.log`) names the caller of
each session:
- here, 5 by `ca-gateway` (Enrollment) and 5 by `vault-gateway` (Retrieval): the Relying Parties ask the Verifier
  themselves;
- under Passport (`182621Z`), all 10 were opened by `est-server`.

**Result:** 10 of 10 Targets. The credential was acquired and admitted by the relying party (`results.json`).
- Veraison evaluated 10 SEV-SNP attestations, all `affirming`.
- Compared Target by Target with the Passport run on the same Verifier: 0 differ (`compare-with-182621Z-passport.txt`).
