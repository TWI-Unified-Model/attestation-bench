# hwcheck on AWS SEV-SNP (VLEK), BENCH_CHAOS_SSH=1, first form (2026-10-07, 13:30Z)

Plan R5. The command: `BENCH_CHAOS_SSH=1 RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=aws-snp`, at `033c88f`: the VM kills the bench's sshd session of the call that starts the workload a second after the workload started, and every sshd session of the bench's user from the workload's 20th second to its 35th.

`run-ssh.stderr`:
- 13:31:29Z `try 1 of 3 failed, exit 255: ssh`: the starting call's answer was lost after the VM had started the workload. The call was made again and started nothing: every line of the workload's output is in `hwrun-stdout.txt` once.
- 13:31:48Z and 13:31:59Z: two copies of the results back (`scp`) broken; the third went through.

The workload ended within ten seconds, before the 20th second, so no call asking for its status fell in the window. `c973f3a` holds the status back to the 40th second; the next AWS run shows those calls broken.

**Verdict** (`verdict.txt`):

- rrpverify-service: 50 checks, 0 not as expected
- rrpverify-veraison-fixed: 122 checks, 120 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-fork: 122 checks, 120 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-v015: 162 checks, 0 not as expected
- VERDICT PASS: 212 checks: the honest Evidence passed, every attack refused for its own reason

**Compared check by check with `20261007T060138Z-aws-sev-snp` (the release's last run, from a fresh clone): all four result files identical (`rrpverify-service`, `-veraison-fixed`, `-fork`, `-v015`).**

The VM was deleted and the deletion checked: `instance i-02f39522cd5d5906f: terminated at 2026-10-07T13:32:58Z` (`vm-deleted.txt`).
