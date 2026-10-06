# The #20 redirection experiment on AWS SEV-SNP (VLEK), rerun on Veraison with go-sev-guest v0.15.0 (06.10.2026, 19:14Z)

This repeats `20261006T174402Z-aws-snp-redirect` (see `bench/05-S4-REDIRECTION-2026-10-06.md`).
- **The change:** the Verifier the gateways ask is now Veraison `2d18260`, go-sev-guest v0.15.0 with AMD's roots
  (`veraison-build.txt`, read from the deployed binaries).
- **Why it matters:** on go-sev-guest v0.15.0 without those roots, this experiment could not run on AWS at all.
  Every VLEK report would be refused before any binding is compared.
- Background Check; both passes as before.
- The guest was a c6a.large in us-east-2, shared tenancy. All 20 reports are signed with the **VLEK**
  (`*/redir/*/meta.json`).
- Cleanup: the instance was terminated, the key pair and security group deleted (`vm-deleted.txt`). Afterwards the
  region had 0 instances, 0 tacra security groups, 0 tacra key pairs and 0 volumes.

**Result:** the same 20 cases with the same outcomes, HTTP statuses and refusal reasons as the morning, 0 differ
(`compare-with-174402Z.txt`).

| | present-nonce | present-epoch | absent-epoch | absent-timestamp | absent-none |
|---|---|---|---|---|---|
| with RRP id, ca2 | refused | refused | refused | refused | refused |
| no RRP id, ca2 | refused | **ISSUED** | **ISSUED** | **ISSUED** | **ISSUED** |

ca1 issued in every case.

**Character-level recompute** (`recompute-binding.txt`). In all 10 Enrollment cases REPORT_DATA matches as the pass
requires:
- the with-rrp-id pass matches the binding with ca1's identifier;
- the no-rrp-id pass matches the binding with no identifier.

No other candidate matches.
