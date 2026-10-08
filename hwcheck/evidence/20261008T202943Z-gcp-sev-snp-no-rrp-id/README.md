# Attacks on Google Cloud SEV-SNP without the RRP identifier, the first run of the #20 variant (2026-10-08, 20:29Z)

`OMIT_RRP_ID=1 RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=gcp-snp`, at `153eb2f`: the guest's hwrun bound
no RRP identifier (`-rrp-ca '' -rrp-vault ''`), as the bench's CAI, EST server and RRPs were configured to (TACRA #20).

**Verdict** (`verdict.txt`): VERDICT FAIL: 10 of 242 checks not as expected

**What failed, and why.** All ten are `rrpverify-service: other RRP identifier: want fail, got pass`, one per request.
With no identifier bound there is none to substitute: the "other" identifier is the empty one again, the binding value
of the case equals the honest request's, and the Verifier rightly answered "affirming"; the check, which expected a
refusal, counted that as wrong. rrpverify's own `verify` path already left the case out when `-rrp-ca` and
`-rrp-vault` are empty (142 checks here against 162 with the identifier: the 20 rows of that case), but the `service`
path, the one that puts the binding value to the deployed Veraison as the expected nonce, kept its own list of cases. A
gap in the tool, not a finding about the protocol: the request that "passed" is the honest one. Fixed in
`hwcheck/cmd/rrpverify/service.go` (`c3909630`): the service path leaves the case out as `verify` does. The AWS
SEV-SNP run of the same batch was stopped before it verified anything and is not kept; after the fix the three attack
runs are made again (the runs beside this one).

**Everything else as expected.** `rrpverify-platform`: 50 checks, 0 not as expected; `rrpverify-service`: the other
40 of its 50; Veraison v0.15: 142 checks, 0 not as expected; the pre-play with the guest's clock ahead as in the runs
with the identifier (`20261008T154907Z-gcp-sev-snp`). The two builds the bench compares with are reported, not judged
(the fixed build 142, 0; the fork 122, 50).

The VM was deleted and the deletion checked (`vm-deleted.txt`).
