# e2e on GCP SEV-SNP, Passport, with Veraison on go-sev-guest v0.15.0 (06.10.2026, 18:26Z)

This repeats `20261006T155456Z-gcp-sev-snp-e2e-passport` with the only change being the Verifier.
- The Verifier is Veraison `2d18260`: go-sev-guest v0.15.0 with AMD's roots for VCEK and VLEK. See
  `hwcheck/evidence/20261006T181314Z-veraison-go-sev-guest-v0.15.0`.
- `code-revs.txt` names the deployed Veraison from its binaries (`e2e/scripts/veraison-build-info.sh`).
- RATS model: Passport (`rats-model.txt`). The EST server asks Veraison with the binding value as the session nonce.
- Machine: n2d-standard-2, AMD Milan, `machine-type.txt`, VCEK. The VM was deleted and the deletion checked:
  `vm-deleted.txt`, and afterwards the project had 0 instances and 0 disks.

**Result:** 10 of 10 Targets. The credential was acquired and admitted by the relying party (`results.json`).
- Veraison evaluated 10 SEV-SNP attestations (`application/vnd.veraison.tsm-report+cbor`), all `affirming`
  (`bench-logs/veraison-vts.log`).
- Compared Target by Target with `20261006T155456Z` (`e2e/scripts/compare-e2e.py`; type, ok, attempts, relying-party
  status, certified names, issuer): 0 differ (`compare-with-155456Z.txt`).
