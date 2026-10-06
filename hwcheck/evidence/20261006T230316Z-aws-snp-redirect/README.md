# #20 redirection on AWS SEV-SNP (VLEK) (2026-10-06, 23:03Z): gate 5

Gate 5 of the attestation-bench plan: the S5 run again, from a bench set up from zero with `make setup` and run
with `make redirect PLATFORM=...` on the user's own cloud settings (`scripts/lib.sh`). The bench ran in
Background Check, with and without the RRP identifier in the binding (`with-rrp-id/`, `no-rrp-id/`).

- Compared case by case with S5 `20261006T191420Z-aws-snp-redirect` (outcome, status, reason): 20 cases before, 20 after, 0 differ (`compare-with-20261006T191420Z.txt`).
- The binding recomputed from the reports, character by character (`recompute-binding.txt`): sev-snp: 0 not as expected.
- The VM was deleted and the deletion checked: instance i-0618399b01a0e5f4d terminated; security group deleted; key pair deleted (`vm-deleted.txt`).
- Code: `code-rev.txt` (0c82e2f6182a).
