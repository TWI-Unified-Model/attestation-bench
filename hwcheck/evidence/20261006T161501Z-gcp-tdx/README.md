# The substitution attacks on real GCP Intel TDX Evidence, the rebuilt bench (06.10.2026, 16:15Z)

**Code:** `code-rev.txt`, branch `bench/rebuild`. **Verifier:** go-tdx-guest with Intel PCS collateral
(`verifier.txt`).

**Platform:** `tacra-hwcheck-2610061615`, c3-standard-4, Intel TDX, us-central1-a.

**What ran:**
- `hwrun` in the guest made ten TD quotes through the group's platform package: five Freshness Kinds × Enrollment and
  Retrieval.
- `rrpverify` on the Mac played the RRP. It took the honest token, then one attack per changed input, each mounted by
  the conduit:
  - Target;
  - RRP identifier;
  - CSR or CEKpub;
  - freshness element;
  - a root that is not Intel's;
  - MRTD off by one byte in the reference values;
  - a timestamp an hour outside the window.

**Result: 82 of 82 as expected** (`rrpverify-tdx.json`).
- All ten honest quotes pass, and each attack is refused 10 of 10.
- The reference values are affirming, and the one-byte MRTD change makes them not affirming.
- Both stale timestamps are refused.

**Cloud:** the VM was deleted (`vm-deleted.txt`). Checked again afterwards: 0 instances and 0 disks.
