# The #20 redirection experiment on GCP SEV-SNP, rerun on Veraison with go-sev-guest v0.15.0 (06.10.2026, 19:05Z)

This repeats `20261006T173518Z-gcp-snp-redirect` (see its README and `bench/05-S4-REDIRECTION-2026-10-06.md`). The only
change is the Verifier the gateways ask: Veraison `2d18260`, go-sev-guest v0.15.0 with AMD's roots (`veraison-build.txt`,
read from the deployed binaries). Background Check; both passes as before (with the RRP identifier in the binding, and
without it on both CAs). The guest: n2d-standard-2, AMD Milan, reports signed with the VCEK (20 of 20, `*/redir/*/meta.json`).
The VM was deleted and the deletion checked (`vm-deleted.txt`); afterwards 0 instances and 0 disks.

**Result** (`results.jsonl`; `compare-with-173518Z.txt`, `hwcheck/scripts/compare-redirect.py`): **the same 20 cases
with the same outcomes, HTTP statuses and refusal reasons as the morning, 0 differ.**

| | present-nonce | present-epoch | absent-epoch | absent-timestamp | absent-none |
|---|---|---|---|---|---|
| with RRP id, ca2 | refused | refused | refused | refused | refused |
| no RRP id, ca2 | refused | **ISSUED** | **ISSUED** | **ISSUED** | **ISSUED** |

ca1 issued in every case.

**Character-level recompute** (`recompute-binding.txt`, `hwcheck/scripts/recompute-binding.py`, no Go): for all 10
Enrollment cases, REPORT_DATA equals SHA-512 of the binding input with ca1's identifier in the with-rrp-id pass and
with no identifier in the no-rrp-id pass, and matches no other candidate; hwrun's recorded binding value agrees.
