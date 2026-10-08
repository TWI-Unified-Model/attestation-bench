# Attacks on AWS SEV-SNP without the RRP identifier, the run that found the script's gap (2026-10-08, 21:03Z)

`OMIT_RRP_ID=1 RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=aws-snp`, at `c3909630`: the guest's hwrun bound
no RRP identifier (`-rrp-ca '' -rrp-vault ''`), as the bench's CAI, EST server and RRPs were configured to (TACRA #20).

**Verdict** (`verdict.txt`): VERDICT FAIL: 120 of 212 checks not as expected

**What failed, and why.** All 120 are in the in-process appraisals (`rrpverify-veraison-v015.json`, and the two builds
the bench compares with): the honest Evidence of every request was refused, "nonce in the evidence doesn't match the
session nonce", and the other cases of the same request are then inconclusive. The three files record why:
`"rrp_ca": "https://ca1.tacra.example", "rrp_vault": "https://vault1.tacra.example"`. The `verify` line of
`hwcheck/scripts/aws-snp-hwcheck.sh` had not been given the empty identifiers that its hwrun, pre-play and `service`
lines were given (the GCP scripts' `verify` lines had them; their runs of the same hour record `""`), so rrpverify
recomputed the binding with an identifier the guest had not bound. The service path of this same run, given them
(`rrpverify-service.json`: `"rrp_ca": ""`), is the measurement of the protocol: 40 checks, 0 not as expected, the
honest Evidence accepted by the deployed Veraison and every substitution of the Target, the CSR or CEKpub and the
freshness element refused. A gap in the script, not in the protocol. Fixed in `1c1df049`: the `verify` line takes the
same flags as the `service` line; the run was made again after the fix (the run beside this one).

**Everything else as expected.** `rrpverify-platform`: 50 checks, 0 not as expected; `rrpverify-service`: 40, 0; the
pre-play with the guest's clock ahead as in the runs with the identifier (`20261008T155945Z-aws-sev-snp`). The two
builds the bench compares with are reported, not judged.

The instance was deleted and the deletion checked (`vm-deleted.txt`).
