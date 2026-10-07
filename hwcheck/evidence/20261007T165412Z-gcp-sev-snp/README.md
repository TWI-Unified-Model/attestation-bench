# Attacks on Google Cloud SEV-SNP, with the guest's clock recorded and the pre-play check (2026-10-07, 16:54Z)

Plan 08, R3: `RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=gcp-snp`, at `98a0ed3`, the bench set up at that
commit: its platform rule requires AMD's mitigation bits, and the bench's pack waives Milan's bit 4.

**Verdict** (`verdict.txt`): VERDICT PASS: 212 checks: the honest Evidence passed, every attack refused for its own
reason; exposure, the guest's clock: https://db-time.tacra.example accepted Evidence 295 s old or more (max_age 120 s);
https://ledger-time.tacra.example accepted Evidence 295 s old or more (max_age 120 s)

Compared check by check with `20261007T134801Z-gcp-sev-snp`: 162 (v0.15.0 build), 162 (DER fixes) and 50 (the
deployed Veraison) checks, 0 differ.

**The guest's clock** (`clock.txt`): clocksource `tsc`, after `kvm-clock` early in boot; `SEV: Status: SEV SEV-ES
SEV-SNP`, without SecureTSC; chrony synchronised to 169.254.169.254, Google's metadata server, without authentication
(`chronyc authdata`, mode `-`). Against this machine's clock, the RRP's (`clock-offset.txt`): +1.183 s, within
1.331 s.

**The pre-play** (`preplay/`, `preplay.json`): with chrony stopped, the guest's clock set 300 s ahead
(`preplay/clock-ahead.txt`), absent-timestamp Evidence made for an Enrollment at db-time and a Retrieval at
ledger-time, and the clock put back. Presented through the EST server at once, both RRPs refused it (409, freshness:
the timestamp outside [now-2m0s, now+5s]). Presented again when their clock reached the timestamp, both took it: a
certificate issued, a secret released, for Evidence 295 s old with `max_age` 120 s. An exposure of absent-timestamp
freshness, which rests on the guest's clock ([../../docs/limits.md](../../../docs/limits.md), "Time"). The gateways' log
lines of both acceptances, in the bench's own logs, name the platform rule's waiver of Milan's bit 4 (`LAUNCH_MIT_VECTOR
0xb`); runs from `preplay.py`'s next version keep those lines (`rrp_log`).

The VM was deleted and the deletion checked (`vm-deleted.txt`).
