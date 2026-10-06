# Mutual TLS between the components (N23), passport (2026-10-06, 22:25Z): gate 5

Gate 5 of the attestation-bench plan: the S5 check again, on a bench set up from zero with `make setup`, run with
`make check-mtls` (RATS model `passport`, `rats-model.txt`).

**Result:** 47 of 47 checks as expected (`mtls.json`).

- Compared check by check with S5 `20261006T182600Z-bench-mtls-veraison-v015` (`compare-with-20261006T182600Z.txt`): 40 checks before, 47 after, 7 differ.
  - 7 checks are new: the channel to the software stand-in's verifier (sim-verifier), which S5 did not have.
  - 0 of the checks S5 had differ.
