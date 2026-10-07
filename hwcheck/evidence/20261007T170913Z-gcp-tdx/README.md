# Attacks on Google Cloud TDX, with the guest's clock recorded and the pre-play check (2026-10-07, 17:09Z)

Plan 08, R3: `RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=gcp-tdx`, at `98a0ed3`. The first TDX attack run
whose checks also go through the bench's deployed TDX verifier (`rrpverify-service.json`), as the SEV-SNP runs' go
through the deployed Veraison.

**Verdict** (`verdict.txt`): VERDICT PASS: 132 checks: the honest Evidence passed, every attack refused for its own
reason; exposure, the guest's clock: https://db-time.tacra.example accepted Evidence 291 s old or more (max_age 120 s);
https://ledger-time.tacra.example accepted Evidence 291 s old or more (max_age 120 s)

Compared check by check with `20261007T060345Z-gcp-tdx`: 82 checks in process (go-tdx-guest, Intel's collateral),
0 differ; the 50 checks through the deployed TDX verifier are new, all as expected.

**The guest's clock** (`clock.txt`): `tdx: Guest detected`; clocksource `tsc`, the only one besides `acpi_pm` (no
`kvm-clock` is offered to this TD); chrony synchronised to 169.254.169.254, Google's metadata server, without
authentication (`chronyc authdata`, mode `-`). Against this machine's clock, the RRP's (`clock-offset.txt`): +1.288 s,
within 1.444 s.

**The pre-play** (`preplay/`, `preplay.json`): with chrony stopped, the TD's clock set 300 s ahead, absent-timestamp
Evidence made for db-time and ledger-time, and the clock put back. At once both RRPs refused it (409, freshness); when
their clock reached the timestamp both took it, Evidence 291 s old with `max_age` 120 s: a certificate issued, a
secret released ([../../docs/limits.md](../../../docs/limits.md), "Time"). TDX keeps the host from rescaling or
rewinding the TD's TSC after launch; the date still comes from outside the TD.

The VM was deleted and the deletion checked (`vm-deleted.txt`).
