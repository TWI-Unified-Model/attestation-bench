# #20 redirection on GCP TDX (2026-10-07, 01:46Z): gate 7

Gate 7 of the attestation-bench plan: every command in the docs run as they write it, at the release's code. The command: `RUNS_DIR="$PWD/hwcheck/evidence" make redirect PLATFORM=gcp-tdx`. Code: attestation-bench `83dea653cf72`.

The bench ran both passes in Background Check, with and without the RRP identifier in the binding (`with-rrp-id/`, `no-rrp-id/`), and was put back in Passport afterwards.

**VERDICT PASS: with the RRP identifier, ca2 refused all 5 Freshness Kinds; without it, all but present-nonce** (`verdict.txt`).

- Compared case by case with gate 5's `20261006T225943Z-gcp-tdx-redirect` (outcome, status, reason): 20 cases before, 20 after, 0 differ (`compare-with-20261006T225943Z.txt`).
- The binding recomputed from the reports, character by character (`recompute-binding.txt`): tdx: 0 not as expected.
- The VM was deleted and the deletion checked: `tacra-redir-2610070146 is gone at 2026-10-07T01:49:22Z` (`vm-deleted.txt`), 185 s after the run started.
