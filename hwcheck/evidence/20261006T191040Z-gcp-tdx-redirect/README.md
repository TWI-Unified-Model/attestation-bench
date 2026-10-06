# The #20 redirection experiment on GCP TDX, rerun (06.10.2026, 19:10Z)

This repeats `20261006T174020Z-gcp-tdx-redirect` during the full rerun on the new SEV-SNP Verifier.
- TDX quotes go to the bench's TDX verifier (go-tdx-guest), not to Veraison, so the Verifier change does not touch
  them. `veraison-build.txt` is recorded all the same.
- The bench admits both of Google's endorsed TDX firmware builds (`c64519c`). This VM had MRTD `c1ee9c16…`, the older
  one (20 of 20 reports).
- Background Check; both passes as before.
- The VM was deleted and the deletion checked (`vm-deleted.txt`). Afterwards there were 0 instances and 0 disks.

**Result:** the same 20 cases with the same outcomes, HTTP statuses and refusal reasons as the morning: 0 differ
(`compare-with-174020Z.txt`). That is the S4 table:
- with the RRP identifier, ca2 refuses all five Freshness Kinds;
- without it, ca2 refuses only present-nonce;
- ca1 issues in every case.

**Character-level recompute** (`recompute-binding.txt`; REPORTDATA at quote offset 48+520, as in
`hwcheck/cmd/rrpverify/tdx.go:90`). In all 10 Enrollment cases the binding matches as the pass requires:
- the with-rrp-id pass binds ca1's identifier;
- the no-rrp-id pass binds no identifier.

No other candidate matches.
