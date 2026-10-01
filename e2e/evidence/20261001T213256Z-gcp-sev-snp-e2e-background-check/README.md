# The SIG's workload with the CAI's certificate checks (N15) and the Vault's groups per Target (N2) (01.10.2026, 21:33Z)

`e2e/scripts/gcp-snp-e2e.sh` on GCP SEV-SNP in Background Check, at `8bd3948`. The bench was rebuilt from that commit
(mutual TLS 40 of 40: `../20261001T213250Z-bench-mtls-check`).

**N15.** The CAI held the bench's step-ca intermediate as the CA of `https://ca1.tacra.example` (`ca_anchors`), and
an hour as the longest validity. It took each of the five certificates only after these checks:

- the certificate is for its CSK;
- it chains to that CA with clientAuth;
- keyUsage is critical, digitalSignature alone;
- it is no CA;
- it is valid at most an hour;
- it carries the name the CSR asked for.

All five passed, and the relying party admitted them.

**N2.** The Vault gateway's five releases carry five different group IDs (`bench-logs/vault-gateway.log`); before
`63169f2` the five ledger Targets shared one. The five releases still carry one API key. The bench's five ledger Targets
name one secret, the API key of its one relying party, so they share it by configuration.

**Result.** 10 of 10 (`results.json`).
