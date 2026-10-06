# e2e on GCP TDX, Background Check (06.10.2026, 18:48Z)

The same run as `20261006T183654Z-gcp-tdx-e2e-passport`, with the bench in the Background Check model
(`rats-model.txt`). TDX goes to the bench's TDX verifier (go-tdx-guest, Intel's embedded root), not to Veraison. The
bench admits both of Google's endorsed TDX firmware builds (`c64519c`, `20261006T183422Z-gce-tdx-endorsements`). The
VM was deleted and the deletion checked (`vm-deleted.txt`); afterwards the project had 0 instances and 0 disks.

**The model took effect.** The TDX verifier's log (`bench-logs/tdx-verifier.log`) names who asked for each session:
5 `ca-gateway` and 5 `vault-gateway`. Under Passport it was `est-server`.

**Result:** 10 of 10 Targets. The credential was acquired and admitted by the relying party (`results.json`).
- The TDX verifier appraised 10 quotes, all `affirming`, on MRTD `f21e6b48743fe14c…`.
- Compared Target by Target with the Passport run: 0 differ (`compare-with-183654Z-passport.txt`).
