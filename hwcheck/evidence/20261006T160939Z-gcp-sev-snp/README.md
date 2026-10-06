# The substitution attacks on real GCP SEV-SNP Evidence, the rebuilt bench (06.10.2026, 16:09Z)

**Code:**
- `code-rev.txt`: branch `bench/rebuild`, the group's main `0d858d0` with our work ported;
- `veraison-revs.txt`: the two Veraison builds.

**Platform:** `tacra-hwcheck-2610061609`, n2d-standard-2, AMD Milan SEV-SNP, us-central1-c.

**What ran:**
- In the guest, `hwrun` produced ten Evidence tokens with the group's platform package: five Freshness Kinds ×
  Enrollment and Retrieval, over Handles minted on the RRP side (`handles.json`).
- On the Mac, `rrpverify` played the RRP. For each token, as delivered and with the certificate table normalised to
  PEM, it checked the honest token and then one attack per changed input. Who attacks is the conduit, which can hand
  the RRP any token and any inputs. Each attack changes exactly one thing:
  - the Target (substitution);
  - the RRP identifier (redirection to another RRP);
  - the CSR or CEKpub (key substitution);
  - the freshness element (replay or stale freshness);
  - the trust anchor, ASK instead of ARK (a wrong root);
  - the launch MEASUREMENT, off by one byte in the reference values (an unapproved launch);
  - a timestamp an hour outside the window.

**Result, with our Veraison fixes** (DER certificate table, SIGNER_INFO; not upstream): **162 of 162 as expected**
(`rrpverify-veraison-fixed.json`).
- Every honest token passes, and each of the 20 tokens for each attack is refused.
- The reference values are affirming, and the one-byte change makes them not affirming.
- Both timestamps out of the window are refused.

**The same suite against the SIG's Veraison as it is: 60 of 142 not as expected** (`rrpverify-veraison-fork.json`).
- Honest tokens as delivered fail, and the attacks come out "inconclusive" rather than refused: the host writes the
  certificate table in DER and that Veraison expects PEM.
- This reproduces our finding of 28.09 on the rebuilt code. The fix exists only in our branch.

**Cloud:** the VM was deleted (`vm-deleted.txt`). Checked again afterwards: 0 instances and 0 disks.

**What this run covers in the attack catalogue (`bench/02-S1-INVENTORY.md`):**
- rows 1 (key substitution: now with a hardware check of its own), 3, 6, 8, and the root of trust;
- row 10 in the form of reference values.

The conduit attacks that need a second RRP running (rows 4, 5, 11) come with S4.
