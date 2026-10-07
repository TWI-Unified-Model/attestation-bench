# hwcheck on Google Cloud SEV-SNP, BENCH_CHAOS_SSH=1 (2026-10-07, 13:48Z)

Plan R5. The command: `BENCH_CHAOS_SSH=1 RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=gcp-snp`, at `e5d2d88`.

`run-ssh.stderr`:
- 13:49:50Z `try 1 of 3 failed, exit 255: gcloud` (`Connection ... closed by remote host`): the VM broke the starting call after the workload had started. The call made again started nothing: each line of the workload's output is in `hwrun-stdout.txt` once.
- 13:50:15Z `a call to the VM failed; asking again`: a call asking for the output and the status, broken by the VM (gcloud's calls take a few seconds each, so one fell in the 15-second window); the next went through, and the whole output came back.

**Verdict** (`verdict.txt`):

- rrpverify-service: 50 checks, 0 not as expected
- rrpverify-veraison-fixed: 162 checks, 0 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-fork: 142 checks, 60 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-v015: 162 checks, 0 not as expected
- VERDICT PASS: 212 checks: the honest Evidence passed, every attack refused for its own reason

**Compared check by check with `20261007T055700Z-gcp-sev-snp` (the release's last run, from a fresh clone): all four result files identical (`rrpverify-service`, `-veraison-fixed`, `-fork`, `-v015`).**

The VM was deleted and the deletion checked: `== tacra-hwcheck-2610071348 is gone at 2026-10-07T13:52:45Z` (`vm-deleted.txt`).
