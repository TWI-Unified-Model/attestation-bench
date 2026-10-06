# Mutual TLS on the bench with Veraison on go-sev-guest v0.15.0 (06.10.2026, 18:26Z)

The same check as `20261006T155403Z-bench-mtls-rebuild`, after Veraison was rebuilt at `2d18260` (go-sev-guest
v0.15.0 with AMD's roots for VCEK and VLEK; see `hwcheck/evidence/20261006T181314Z-veraison-go-sev-guest-v0.15.0`).

- Code: `code-rev.txt`. Verifier: `veraison-build.txt`, read from the deployed binaries.
- RATS model: Passport (`bench.sh config` with `RATS_MODEL=passport`), the TWI SIG decision of 06.10.
- Check: `e2e/scripts/bench-mtls-check.py`, N23. No hardware.

**Result:** 40 of 40 as expected (`run.log`, `mtls.json`).

Compared check by check with the 15:54Z run using `e2e/scripts/compare-mtls.py`: the same 40 checks, 0 differ
(`compare-with-155403Z.txt`).
- The comparison is keyed by channel, caller and TLS version, because each channel is tried at TLS 1.3 and at
  TLS 1.2.
- A first, inline comparison keyed only by channel and caller had merged those pairs into 32 checks. It was replaced
  by the script, which refuses duplicate keys.
