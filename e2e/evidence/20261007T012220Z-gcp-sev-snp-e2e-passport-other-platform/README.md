# e2e on GCP SEV-SNP, Passport, Targets of another platform (2026-10-07, 01:22Z): gate 7

Gate 7 of the attestation-bench plan: every command in the docs run as they write it, at the release's code. The command: `RUNS_DIR="$PWD/e2e/evidence" OTHER_PLATFORM=1 make demo PLATFORM=gcp-snp`. Code: attestation-bench `83dea653cf72`.

**VERDICT PASS: 1 of 1 Targets refused, no credential issued, each with 'none of the verifiers this RRP takes for the Target'** (`verdict.txt`).

The Target takes another platform's verifier alone (`packs/tacra-bench/pack.json`), so the RRP must refuse this platform's genuine Evidence (tacra-est N24). The refusal, from `results.json`: `RRP ca: attestation: ear: not signed by the verifier's key: none of the verifiers this RRP takes for the Target (tdx) signed it`. Before this `make` command existed, the same refusal came from the reference implementation's client on 1 October 2026 (`e2e/RESULTS-mutual-tls-verifier-choice.md`).

- Machine: `n2d-standard-2` (`machine-type.txt`).
- The VM was deleted and the deletion checked: `tacra-e2e-2610070122 is gone at 2026-10-07T01:25:08Z` (`vm-deleted.txt`), 168 s after the run started.
