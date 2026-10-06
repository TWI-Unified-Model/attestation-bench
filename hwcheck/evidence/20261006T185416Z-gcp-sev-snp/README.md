# The substitution attacks on real GCP SEV-SNP Evidence, Veraison on go-sev-guest v0.15.0 (06.10.2026, 18:54Z)

This repeats `20261006T160939Z-gcp-sev-snp` on a new VM. It adds a third in-process Verifier and swaps the deployed
one.

**Code:** `code-rev.txt`; the Veraison builds are in `veraison-revs.txt`.
- **In process:** the SIG's fork `f997c52`; our DER and SIGNER_INFO fixes `cd2afab`; and those fixes on go-sev-guest
  v0.15.0 with AMD's roots `2d18260`. All three link go-sev-guest v0.15.0 through hwcheck's modules.
- **Deployed service:** `2d18260`, read from its binaries.

**Platform:** `tacra-hwcheck-2610061854`, n2d-standard-2, AMD Milan SEV-SNP, us-central1-c. All 10 reports are signed
with the VCEK (`*/meta.json`).

**What ran:** the same suite as in `160939Z` (its README lists the attacks). Each token is checked honest, then with
one input changed by the conduit:
- the Target;
- the RRP identifier;
- the CSR or CEKpub;
- the freshness element;
- the trust anchor;
- the launch MEASUREMENT;
- a timestamp outside the window.

**Results** (`compare-with-160939Z.txt`, `hwcheck/scripts/compare-rrpverify.py`, check by check):

| Verifier | Result | Against the morning |
|---|---|---|
| SIG fork as it is (`rrpverify-veraison-fork.json`) | 142 checks, 60 not as expected | the same checks and outcomes (0 differ) |
| Our fixes `cd2afab` (`…-fixed.json`) | 162 of 162 as expected | 0 differ |
| Our fixes on v0.15.0 + AMD roots `2d18260` (`…-v015.json`) | 162 of 162 | 0 differ from the morning's `fixed` |
| Deployed service, now `2d18260` (`rrpverify-service.json`) | 50 of 50 | 0 differ from the morning's service (then v0.14.2-pre) |

The fork's 60 are still the DER certificate table: GCP hosts write DER, and that Veraison reads only PEM. This is our
finding of 28.09; the fix exists only in our branch.

**Cloud:** the VM was deleted (`vm-deleted.txt`). Checked again afterwards: 0 instances and 0 disks.
