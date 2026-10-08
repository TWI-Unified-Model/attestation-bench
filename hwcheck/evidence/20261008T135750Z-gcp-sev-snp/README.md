# Attacks on Google Cloud SEV-SNP, the first run after the conduit's drills changed the pack (2026-10-08, 13:57Z)

`RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=gcp-snp`, at `6bf2b37`, with the attest-* wire as proposed for
the EST draft (EST patch 0014).

**Verdict** (`verdict.txt`): VERDICT FAIL: the pre-play check not as expected: the Evidence made with the guest's
clock ahead was not presented

**What failed, and why.** The guest made the pre-play's Evidence (`preplay-stdout.txt`), but the pre-play presented
none of it: `preplay.txt` holds its one line, "https://ledger-lepoch.tacra.example: 2 identities or credential groups
in the policy; the check needs one". The pre-play took the Credential Hint of each request as the Target's one
identity or credential group, and stopped when there was more than one. The conduit's drills on the Retrieval
container (`af909f4`) gave each Secret Vault Target a second group, the pack's `other_groups`, and no attack run had
been made since. The four attest-initiate exchanges of the pre-play's preparation reached the EST server; no second
leg did. Fixed in `hwcheck/scripts/preplay.py`: the pre-play sends the Credential Hint the workload sends
(`packs/tacra-bench`, `workload.hint`) and checks that it is one of the Target's. The AWS SEV-SNP and GCP TDX attack
runs of the same batch failed the same way and are not kept; the three were made again after the fix.

**Everything else as expected.** `rrpverify-platform`: 50 checks, 0 not as expected; `rrpverify-service`: 50, 0;
Veraison v0.15: 162, 0. The two builds the bench compares with are reported, not judged.

The VM was deleted and the deletion checked (`vm-deleted.txt`).
