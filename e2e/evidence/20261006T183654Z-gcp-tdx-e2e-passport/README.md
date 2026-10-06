# e2e on GCP TDX, Passport, after admitting both endorsed TDX firmware builds (06.10.2026, 18:36Z)

This repeats `20261006T183028Z-gcp-tdx-e2e-passport`, which was refused because the bench admitted only one of Google's
two TDX firmware builds. The fix is `bench.sh` at `c64519c`; both MRTDs were checked against Google's signed
endorsements in `20261006T183422Z-gce-tdx-endorsements`.

- RATS model: Passport (`rats-model.txt`).
- Machine: c3-standard-4 (`machine-type.txt`).
- Verifier: the bench's TDX verifier (go-tdx-guest, Intel's embedded root). Veraison is not involved for TDX;
  `code-revs.txt` names it all the same.
- The VM was deleted and the deletion checked (`vm-deleted.txt`). Afterwards the project had 0 instances and 0 disks.

**Result:** 10 of 10 Targets. The credential was acquired and admitted by the relying party (`results.json`).
- This VM got the newer firmware, MRTD `f21e6b48743fe14c…`. The TDX verifier appraised all 10 quotes as `affirming`
  (`bench-logs/tdx-verifier.log`).
- Compared Target by Target with the morning `20261006T155929Z` (MRTD `c1ee9c16…`): 0 differ
  (`compare-with-155929Z.txt`).
