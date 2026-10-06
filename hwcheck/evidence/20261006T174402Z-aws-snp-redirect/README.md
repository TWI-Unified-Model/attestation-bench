# The #19/#20 redirection experiment on AWS SEV-SNP (VLEK) (06.10.2026)

Same method and finding as the GCP SEV-SNP run (`../*-gcp-snp-redirect/README.md`), on a real AWS EC2 SEV-SNP guest
(c6a.large, shared tenancy, VLEK-signed reports), verified through the deployed Veraison (which trusts the ASVK from
the KDS chain, so VLEK Evidence verifies; the in-process go-sev-guest v0.15.0 limitation does not apply here). Code
`code-rev.txt`.

## Result (`results.jsonl`)
| Pass | ca2, present-nonce | ca2, present-epoch / absent-epoch / absent-timestamp / absent-none |
|---|---|---|
| with-rrp-id | refused (freshness) | refused (binding: contraindicated) |
| no-rrp-id | refused (freshness) | **ISSUED** |

ca1 issued in all ten cases. Identical to GCP SEV-SNP and GCP TDX: across all three platforms, the RRP identifier binds
Evidence to one RRP for every Freshness Kind; without it, only an RRP-issued single-use nonce still prevents a second
CA from issuing.

**Cloud:** the instance, security group and key pair were deleted (`vm-deleted.txt`); checked afterwards: 0 instances,
0 tacra security groups, 0 tacra key pairs.
