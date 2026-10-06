# The substitution attacks on real GCP TDX Evidence, rerun (06.10.2026, 18:59Z)

This repeats `20261006T161501Z-gcp-tdx` on a new VM, during the full rerun on the new SEV-SNP Verifier.
- TDX quotes are checked in process with go-tdx-guest against Intel's collateral. Veraison is not involved, so the
  Veraison change does not touch this suite. It is rerun so that the whole matrix comes from one sitting.
- Code: `code-rev.txt`.
- Platform: c3-standard-4, us-central1-a.
- The VM had MRTD `c1ee9c16e3afc506…`, Google's older endorsed TDX firmware (`*/meta.json`). The e2e VMs of 18:36Z and
  18:48Z had the newer one, so Google hands out both (`e2e/evidence/20261006T183422Z-gce-tdx-endorsements`).

**Result:** 82 of 82 as expected (`rrpverify-tdx.json`). The same checks with the same outcomes as the morning,
check by check (`compare-with-161501Z.txt`).

**Cloud:** the VM was deleted (`vm-deleted.txt`). Checked again afterwards: 0 instances and 0 disks.
