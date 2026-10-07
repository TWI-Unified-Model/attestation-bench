# hwcheck on GCP TDX (2026-10-07, 01:37Z): gate 7

Gate 7 of the attestation-bench plan: every command in the docs run as they write it, at the release's code. The command: `RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=gcp-tdx`. Code: attestation-bench `83dea653cf72`.

**Verdict** (`verdict.txt`):

- rrpverify-tdx: 82 checks, 0 not as expected
- VERDICT PASS: 82 checks: the honest Evidence passed, every attack refused for its own reason

**Compared check by check with gate 5's `20261006T225040Z-gcp-tdx`:**

- `compare-tdx-with-20261006T225040Z.txt`: 82 checks before, 82 after, 0 differ
- The VM was deleted and the deletion checked: `tacra-hwcheck-2610070137 is gone at 2026-10-07T01:39:58Z` (`vm-deleted.txt`), 148 s after the run started.
