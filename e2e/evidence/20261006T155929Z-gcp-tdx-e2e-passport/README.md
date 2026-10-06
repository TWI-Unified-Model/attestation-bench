# TACRA over EST end to end on GCP Intel TDX, the rebuilt bench (06.10.2026, 15:59–16:01Z)

**Code:** as in `code-revs.txt`, the same as the SEV-SNP run of 15:54Z:
- branch `bench/rebuild` (the group's main `0d858d0` with our work ported);
- globalsign-est `tacra/deployed-rrp`;
- Veraison `cd2afab`.

RATS model: Passport.

**Platform:**
- `tacra-e2e-2610061559`: c3-standard-4, Intel TDX, us-central1-a, kernel `7.0.0-1011-gcp`;
- configfs-tsm `report`.

**Run:** the same ten Targets as on SEV-SNP: five Freshness Kinds × Enrollment (x509) and Retrieval (api-key).

**Result: 10 of 10.** Every credential was acquired on the first attempt and admitted by the relying party (200).
- The first acquisition took 2180 ms, while the TDX verifier fetched Intel's collateral. It keeps a PCS document for at
  most an hour (`0c4b573`).
- The others took 526–641 ms.

**Verifier:**
- The bench's TDX verifier (Veraison has no TDX scheme), using the embedded Intel root.
- 10 sessions, opened by the EST server with its own binding value (Passport).
- MRTD `c1ee9c16e3afc506…` in all ten. That is the firmware build in the bench's approved list
  (`bench.sh` `TDX_MRTDS`), so the known risk of another Google TDX build did not occur in this run
  (`bench-logs/tdx-verifier.log`).

**Cloud:** the VM was deleted (`vm-deleted.txt`). Checked again independently: 0 instances, 0 disks.

**Not proved here:** attacks. They follow on the rebuilt bench.
