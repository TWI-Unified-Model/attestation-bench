# Attacks on AWS SEV-SNP, with the guest's clock recorded and the pre-play check (2026-10-07, 17:02Z)

Plan 08, R3: `RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=aws-snp`, at `98a0ed3`, the bench set up at that
commit: its platform rule requires AMD's mitigation bits, and the bench's pack waives Milan's bit 4.

**Verdict** (`verdict.txt`): VERDICT PASS: 212 checks: the honest Evidence passed, every attack refused for its own
reason; exposure, the guest's clock: https://db-time.tacra.example accepted Evidence 293 s old or more (max_age 120 s);
https://ledger-time.tacra.example accepted Evidence 293 s old or more (max_age 120 s)

Compared check by check with `20261007T134512Z-aws-sev-snp`: 162 (v0.15.0 build), 122 (DER fixes) and 50 (the
deployed Veraison) checks, 0 differ.

**The guest's clock** (`clock.txt`): clocksource `tsc`, after `kvm-clock` early in boot; `SEV: Status: SEV SEV-ES
SEV-SNP`, without SecureTSC; chrony synchronised to 169.254.169.123, the Amazon Time Sync Service, with Ubuntu's pool
servers as unselected sources, none authenticated (`chronyc authdata`, mode `-`). Against this machine's clock, the
RRP's (`clock-offset.txt`): +0.423 s, within 0.417 s.

**The pre-play** (`preplay/`, `preplay.json`): with chrony stopped, the guest's clock set 300 s ahead, absent-timestamp
Evidence made for db-time and ledger-time, and the clock put back. At once both RRPs refused it (409, freshness); when
their clock reached the timestamp both took it, Evidence 293 s old with `max_age` 120 s: a certificate issued, a
secret released ([../../docs/limits.md](../../../docs/limits.md), "Time"). The gateways' log lines of both acceptances,
in the bench's own logs, name the waiver of Milan's bit 4 (`LAUNCH_MIT_VECTOR 0x10f`).

The instance was terminated, its key pair and security group deleted, and the deletions checked (`vm-deleted.txt`).
