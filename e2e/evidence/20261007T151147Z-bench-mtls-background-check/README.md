# Mutual TLS in the trust zone, Background Check, the EST server without a mock CA (2026-10-07)

Plan 09, step N4: `RATS_MODEL=background-check make config`, `make stop start`, then
`RUNS_DIR="$PWD/e2e/evidence" make check-mtls`, at `220e75c`, with the EST server built from EST patches 0001-0010
(no mock CA, the configuration read strictly), which started with the Background Check configuration. Every channel
between the components, tried with every kind of caller.

**Verdict** (`verdict.txt`): VERDICT PASS: 40 of 40 checks as expected: only the allowed components, over TLS 1.3

Each of the 40 checks (channel, caller, TLS version, expected and actual answer) is the same as in
`20261007T142050Z-bench-mtls-background-check`, the run of step N2.

Veraison's binaries are those of the N2 run (`veraison-build.txt`, the same SHA-256): Veraison patch 0008 changes
tests only.
