# hwcheck on GCP TDX (2026-10-06, 22:50Z): gate 5

Gate 5 of the attestation-bench plan: the S5 run again, from a bench set up from zero with `make setup` and run
with `make attacks PLATFORM=...` on the user's own cloud settings (`scripts/lib.sh`).

**Results** (the last line of each `rrpverify-*.txt`):

- `rrpverify-tdx.txt`: 82 checks, 0 not as expected; written /Users/serhiinikolaichuk/dev/attestation-bench/hwcheck/evidence/20261006T225040Z-gcp-tdx/rrpverify-tdx.json

**Compared check by check with S5 `20261006T185936Z-gcp-tdx`:**

- `compare-tdx-with-20261006T185936Z.txt`: 82 checks before, 82 after, 0 differ
- The VM was deleted and the deletion checked: == tacra-hwcheck-2610062250 is gone (`vm-deleted.txt`).
- Code: `code-rev.txt` (0c82e2f6182a).
