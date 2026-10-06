# The #19/#20 redirection experiment on GCP Intel TDX (06.10.2026)

Same method and finding as the SEV-SNP run (`../*-gcp-snp-redirect/README.md`), on a real Intel TDX guest
(c3-standard-4), the TDX verifier (go-tdx-guest, Intel PCS). Code `code-rev.txt`.

## Result (`results.jsonl`)
| Pass | ca2, present-nonce | ca2, present-epoch / absent-epoch / absent-timestamp / absent-none |
|---|---|---|
| with-rrp-id | refused (freshness) | refused (binding: contraindicated) |
| no-rrp-id | refused (freshness) | **ISSUED** |

ca1 issued in all ten cases. The result is identical to SEV-SNP: the RRP identifier binds Evidence to one RRP for
every Freshness Kind; without it, only an RRP-issued single-use nonce still prevents a second CA from issuing. The
mechanism is platform-independent.

**Cloud:** VM deleted (`vm-deleted.txt`); checked afterwards: 0 instances, 0 disks.
