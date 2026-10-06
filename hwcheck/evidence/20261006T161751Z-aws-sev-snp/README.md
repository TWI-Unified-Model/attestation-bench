# The substitution attacks on real AWS SEV-SNP Evidence (VLEK), the rebuilt bench (06.10.2026, 16:17Z)

**Code:** `code-rev.txt`, branch `bench/rebuild`. **Platform:** EC2 c6a.large, us-east-2a, shared tenancy
(VLEK-signed reports).

## In-process Veraison (`rrpverify verify`): 120 of 122 not as expected, in both builds
- **What happened.** Honest tokens fail, and the attacks come out "inconclusive": "VLEK could not be verified by any
  trusted roots. Last error: root of trust missing intermediate certificate authority certificate for key VLEK"
  (`rrpverify-veraison-*.json`).
- **The table is right.** The certificate table in the token is the full AMD chain: VLEK, then the ASVK
  `CN=SEV-VLEK-Milan` under the ASK GUID, then `CN=ARK-Milan`, all DER. The group's platform package (PR #8)
  completes it.
- **Cause: go-sev-guest v0.15.0.**
  - The platform module of main requires v0.15.0, and because `rrpverify` links the platform and Veraison into one
    binary, Veraison runs with v0.15.0 here.
  - v0.15.0 hardened verification: "We strictly avoid using the unverified certificates from the incoming chain as
    the root of trust" (`verify/verify.go`, `trust.GetDefaultRootCerts`).
  - Its embedded roots for Milan hold the ASK and the ARK but no ASVK, so for a VLEK report the intermediate is
    missing (`verify/verify.go:415`).
  - v0.14.2-0.20251119154202 trusted the incoming chain's intermediate. That is Veraison's own pinned version
    (`veraison-services-der/go.mod:19`), the one the deployed bench Veraison is built with, and the one the old
    `p0/step3` used, so AWS passed on 28.09 and in today's end-to-end run.
- **Consequence for the group.** Any build that puts the group's platform module and Veraison's sevsnp scheme in one
  binary, or any Veraison upgraded to go-sev-guest v0.15.0, refuses all VLEK (AWS) Evidence until the ASVK is provided
  as a trusted root.
- **The right fix** follows v0.15.0's hardening: the ASVK comes from a trusted source (AMD KDS), not from the Evidence.
  It is not done here.

## Through the deployed Veraison (`rrpverify service`): 50 of 50 as expected
- Run after the tool fix `5465972`, on the Evidence saved in this folder. Not part of the script run: the script had
  skipped this check, because since N23 the deployed Veraison requires a client certificate and the probe sent none.
- Honest: 10 pass. Other Target, other RRP identifier, other CSR or CEKpub, other freshness element: each refused
  10 of 10 (EAR status contraindicated) (`rrpverify-service.json`, `rrpverify-service.txt`).
- The trust-anchor and reference-value checks exist only in the in-process mode, so they wait for the ASVK fix above.

**Cloud:** the instance was terminated, and the security group and key pair deleted (`vm-deleted.txt`). Checked
again afterwards: 0 instances, 0 `tacra` security groups, 0 `tacra` key pairs.
