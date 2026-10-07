# hwcheck on AWS SEV-SNP (VLEK), BENCH_CHAOS_SSH=1 (2026-10-07, 13:45Z)

Plan R5. The command: `BENCH_CHAOS_SSH=1 RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=aws-snp`, at `e5d2d88` (`docs/troubleshooting.md`).

`run-ssh.stderr`:
- 13:46:23Z `try 1 of 3 failed, exit 255: ssh` (`Connection ... closed by remote host`): the VM broke the starting call after the workload had started. The call made again started nothing: each line of the workload's output is in `hwrun-stdout.txt` once.
- 13:46:46Z, 13:46:50Z, 13:46:53Z `a call to the VM failed; asking again`: three calls asking for the output and the status, each broken by the VM; the next ones went through, and the whole output came back.

**Verdict** (`verdict.txt`):

- rrpverify-service: 50 checks, 0 not as expected
- rrpverify-veraison-fixed: 122 checks, 120 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-fork: 122 checks, 120 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-v015: 162 checks, 0 not as expected
- VERDICT PASS: 212 checks: the honest Evidence passed, every attack refused for its own reason

**Compared check by check with `20261007T060138Z-aws-sev-snp` (the release's last run, from a fresh clone): all four result files identical (`rrpverify-service`, `-veraison-fixed`, `-fork`, `-v015`).**

The VM was deleted and the deletion checked: `instance i-0a188d4aa89d696e3: terminated at 2026-10-07T13:47:54Z` (`vm-deleted.txt`).
