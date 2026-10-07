# Mutual TLS in the trust zone, Background Check, with no stand-in (2026-10-07)

Plan 09, step N2: `RUNS_DIR="$PWD/e2e/evidence" make check-mtls` in Background Check, at `355156d`, after the software stand-in's
verifier left the trust zone. Every channel between the components, tried with every kind of caller.

**Verdict** (`verdict.txt`): VERDICT PASS: 40 of 40 checks as expected: only the allowed components, over TLS 1.3

The checks of 6 October were 47: the seven of the stand-in's verifier's channel are gone with it
(`20261006T222549Z-bench-mtls`, `20261006T223444Z-bench-mtls`).
