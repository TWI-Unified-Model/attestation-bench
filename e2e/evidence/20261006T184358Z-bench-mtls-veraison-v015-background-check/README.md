# Mutual TLS on the bench, Background Check, Veraison on go-sev-guest v0.15.0 (06.10.2026, 18:43Z)

The check of `20261006T182600Z-bench-mtls-veraison-v015` with the bench switched to the Background Check model
(`bench.sh config` with `RATS_MODEL=background-check`, no RRP-identifier omission; both endorsed TDX MRTDs admitted).
Verifier: `veraison-build.txt`. Check: `e2e/scripts/bench-mtls-check.py` (N23); no hardware.

**Result:** 40 of 40 as expected (`run.log`, `mtls.json`); the same 40 checks (keyed by channel, caller and TLS version, `e2e/scripts/compare-mtls.py`) with the same outcomes as under Passport
(`compare-with-182600Z-passport.txt`).
