# The substitution attacks on real AWS SEV-SNP (VLEK) Evidence, Veraison on go-sev-guest v0.15.0 (06.10.2026, 19:02Z)

This repeats `20261006T161751Z-aws-sev-snp` on a new instance, with a third in-process Verifier and the deployed one
swapped.

**Code:** `code-rev.txt` and `veraison-revs.txt`.
- **In process:** the SIG's fork `f997c52`; our fixes `cd2afab`; and our fixes on go-sev-guest v0.15.0 with AMD's
  roots `2d18260`. All three link go-sev-guest v0.15.0.
- **Deployed service:** `2d18260`, read from its binaries.

**Platform:** c6a.large, us-east-2, shared tenancy. **All 10 reports are signed with the VLEK** (`*/meta.json`). The
AMD KDS VLEK chain fetched by the script is in `amd-kds-milan-vlek-cert_chain.pem`.

**What ran:** the same suite as in `161751Z`. Each token is checked honest, then with one input changed by the conduit:
- the Target;
- the RRP identifier;
- the CSR or CEKpub;
- the freshness element;
- the trust anchor;
- the launch MEASUREMENT;
- a timestamp outside the window.

**Results** (`compare.txt`, `hwcheck/scripts/compare-rrpverify.py`, check by check):

| Verifier | Result | Compared with |
|---|---|---|
| SIG fork as it is | 122 checks, 120 not as expected | morning: 0 differ |
| Our fixes `cd2afab`, without AMD's VLEK roots | 122 checks, 120 not as expected | morning: 0 differ |
| **Our fixes on v0.15.0 + AMD roots `2d18260`** | **162 of 162 as expected** | GCP `185416Z` v015: 0 differ; offline on the morning AWS Evidence: 0 differ |
| Deployed service, now `2d18260` | 50 of 50 | morning service (then v0.14.2-pre): 0 differ |

**What it shows:**
- Without AMD's roots, go-sev-guest v0.15.0 refuses every VLEK report. Honest AWS Evidence then fails, and the
  attacks come out refused for the wrong reason.
- With the roots, the same VLEK Evidence passes and every attack is refused for its own reason, exactly as on GCP
  (VCEK).

**Cloud:** the instance was terminated, the key pair and security group deleted (`vm-deleted.txt`). Checked again
afterwards: 0 instances, 0 tacra security groups, 0 tacra key pairs and 0 volumes.
