# Mutual TLS in the trust zone, Background Check, the EST library without the mock TEE (2026-10-07)

Plan 09, step N7: `RATS_MODEL=background-check make config`, `make stop start`, then
`RUNS_DIR="$PWD/e2e/evidence" make check-mtls`, at `e1bcdcf`, with the EST server built from EST patches 0001-0011.
Every channel between the components, tried with every kind of caller.

**Verdict** (`verdict.txt`): VERDICT PASS: 40 of 40 checks as expected: only the allowed components, over TLS 1.3

Each of the 40 checks (channel, caller, TLS version, expected and actual answer) is the same as in
`20261007T151147Z-bench-mtls-background-check`, the run of step N4; Veraison's binaries are the same too
(`veraison-build.txt`). `make test-live` passed after this run, in this model: the EST wire format, 14 checks, and 23
committed attack runs appraised again by the live verifiers, 1150 checks.
