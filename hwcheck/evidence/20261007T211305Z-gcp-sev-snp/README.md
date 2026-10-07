# Attacks on Google Cloud SEV-SNP, the first run of the pre-play with the clock moved both ways (2026-10-07, 21:13Z)

`RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=gcp-snp`, at `758b0ff`: the pre-play makes Evidence of every
Freshness Kind with the guest's clock 300 s ahead, with the Handles the live RRPs minted for it, and absent-timestamp
Evidence with the clock 300 s behind; it offers each at once, then absent-timestamp's at its window's edges.

**Verdict** (`verdict.txt`): VERDICT FAIL: the pre-play check not as expected: ahead enroll-present-epoch: not taken
at once (403 Target, Credential Type or Freshness Kind differ from the attest-initiate)

**What failed, and why.** The 403 came from the EST server itself, before any RRP was asked: its words are the EST
backend's own refusal (`internal/tacra/backend.go`, `correlate`; `preplay.json`). The server kept one attest-initiate
session per Handle. The pre-play asked attest-initiate for db-epoch and then for
ledger-epoch before offering either's Evidence; both answered the same Handle, the deployment's epoch, so the second
session replaced the first, and db-epoch's Enrollment was refused as not belonging to it. ledger-epoch's Retrieval,
whose session was the one kept, was taken. Two workloads asking for two Targets' present-epoch at once would meet the
same refusal. Fixed in EST patch 0012 (`third_party/globalsign-est/patches/0012-…`): a session per Target, Credential
Type and kind under each Handle; its test, `internal/tacra/session_test.go`, fails on the old behaviour.

**Everything else as expected.** The substitution attacks: 262 checks, 0 not as expected. The pre-play: present-nonce
(both modes), absent-epoch and absent-none (both modes) and present-epoch for the Retrieval, made with the clock
300 s ahead, taken at once; absent-timestamp refused at once, taken 285 s or more after the Evidence was made and
still 406 s or more after it, refused 410 s or more after it (`max_age` 120 s, `clock_skew` 5 s); made with the clock
300 s behind, refused at once and 410 s or more after it. The ages are from the end of the guest's step, so each is
the least the Evidence's age can have been.

The VM was deleted and the deletion checked (`vm-deleted.txt`).
