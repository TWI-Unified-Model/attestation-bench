# AWS SEV-SNP end to end on the rebuilt bench: 5 of 10, a bug in our run script (06.10.2026, 16:02–16:04Z)

**Code:**
- branch `bench/rebuild` at `72cf314` (see `code-revs.txt`);
- globalsign-est `tacra/deployed-rrp`;
- Veraison `cd2afab`.

RATS model: Passport.

**Platform:** EC2 c6a.large, us-east-2a, shared tenancy, so the reports are signed with the VLEK (`instance.txt`,
`kernel.txt`).

**Result: 5 of 10.**
- Enrollment for all five Freshness Kinds: issued and admitted by the relying party (200).
- Retrieval for all five kinds: refused in the guest by the CAI, `no trust anchor for the Secret Vault's signature key`
  (`results.json`, `e2e-attester-stdout.txt`).

**Cause.** The fault is in our run script, not in the protocol or the hardware.
- The Vault releases in the `hpke-base-signed` container, which the Vault signs. The CAI accepts it only under a
  signature key it holds for the Vault's RRP identifier (`vault_signers`).
- The guest configuration was written by two copies of the same block. The GCP copy got `vault_signers` with the
  signed container (30.09–01.10). The AWS copy did not: it also passed the Vault's whole key set as `vault_origins`
  instead of the DHKEM keys only.
- AWS had not been run since 28.09, before the signed container existed, so the drift stayed hidden until the rebuild.

The CAI's refusal is the designed behaviour: without the anchor it must not accept a bundle.

**Fix:** the next commit. Both scripts now use one `e2e/scripts/guest_config.py`. For GCP its output is byte-identical
to the old block's; AWS now gets `vault_signers`.

**Cloud:** the instance was terminated, and the security group and the key pair were deleted (`vm-deleted.txt`).
Checked again afterwards: 0 instances not terminated in us-east-2, 0 `tacra` security groups, 0 `tacra` key pairs.
