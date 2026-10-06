# e2e on GCP TDX, Passport: refused on an MRTD outside the bench's reference values (06.10.2026, 18:30Z)

**Kept as evidence: the run did not pass, and the reason is documented below.**

**Result:** 0 of 10 Targets. The TDX verifier appraised every quote as `contraindicated`. Its log
(`bench-logs/tdx-verifier.log`) gives the reason: MRTD `f21e6b48743fe14c…e5d3` matches no reference value. The CA and
Vault gateways refused with 403, as their policy requires. The VM was deleted and the deletion checked
(`vm-deleted.txt`).

**Why:**
- The bench then admitted only MRTD `c1ee9c16e3afc506…`, the firmware the morning TDX VMs had
  (`20261006T155929Z-gcp-tdx-e2e-passport`).
- This VM got Google's other TDX firmware build. Its MRTD is endorsed by Google's signed VMLaunchEndorsement
  (2026-07-31, SVN 2), checked today in `20261006T183422Z-gce-tdx-endorsements`.
- The demo-bank run of 28.09 had approved both builds. The rebuilt bench lost the second one in the port: our gap, not
  the group's code.

**What it shows:** a launch measurement that the policy does not name is refused end to end, through the Passport
flow, with no credential issued.

**What was done:** `bench.sh` now admits both endorsed MRTDs. The run is repeated in the next evidence directory.

Veraison is not involved: TDX goes to the bench's TDX verifier. `code-revs.txt` names the deployed Veraison all the
same.
