# Mutual TLS in the trust zone, Passport, the EST library without the mock TEE (2026-10-07)

Plan 09, step N7: `RUNS_DIR="$PWD/e2e/evidence" make check-mtls` in Passport, at `e1bcdcf`, after `make setup` rebuilt
the EST server from EST patches 0001-0011 (patch 0011 takes the proof of concept's mock TEE and mock attested CA out
of the EST library). Every channel between the components, tried with every kind of caller.

**Verdict** (`verdict.txt`): VERDICT PASS: 40 of 40 checks as expected: only the allowed components, over TLS 1.3

Each of the 40 checks (channel, caller, TLS version, expected and actual answer) is the same as in
`20261007T151127Z-bench-mtls-passport`, the run of step N4; Veraison's binaries are the same too
(`veraison-build.txt`). `make test-live` passed after this run, in this model: the EST wire format, 14 checks, and 23
committed attack runs appraised again by the live verifiers, 1150 checks.
