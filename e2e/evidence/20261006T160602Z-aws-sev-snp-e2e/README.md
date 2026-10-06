# AWS SEV-SNP end to end on the rebuilt bench, after the script fix: 10 of 10 (06.10.2026, 16:06–16:08Z)

**Code:**
- branch `bench/rebuild` at `8377ca8` (`code-revs.txt`), which includes `guest_config.py`, the one guest configuration
  for every cloud;
- globalsign-est `tacra/deployed-rrp`;
- Veraison `cd2afab`.

RATS model: Passport.

**Platform:** EC2 c6a.large, us-east-2a, shared tenancy (VLEK-signed reports) (`instance.txt`).

**Result: 10 of 10.** Five Freshness Kinds × Enrollment (x509) and Retrieval (api-key, `hpke-base-signed` container).
Each credential was acquired on the first attempt in 618–737 ms and admitted by the relying party (200). The run of
16:02Z (`../20261006T160234Z-aws-sev-snp-e2e`) had failed Retrieval for lack of `vault_signers`; this run shows the fix.

**Veraison:** every SEVSNP session affirming (`bench-logs/veraison-vts.log`). The VLEK path runs on the group's
platform code (PR #8: `reportSigner` by SIGNING_KEY) and on our Veraison and go-gen-ref fixes, which are not upstream.

**Cloud:** the instance was terminated, and the security group and key pair deleted (`vm-deleted.txt`). Checked again
afterwards: 0 instances, 0 `tacra` security groups, 0 `tacra` key pairs.

**Not proved here:** attacks. They follow on the rebuilt bench.
