# hwcheck on AWS SEV-SNP (VLEK), no call broken (2026-10-07, 13:24Z)

Plan R5, at `5eb6dba`. The same attempt as on Google Cloud: kill, from this machine, the `ssh` process of a call in flight to the VM once it had been alive 0.3 s. It killed nothing in the time it had: the workload started at 13:26:09Z and the instance was terminated at 13:27:01Z, and no such process was found in between. So this run had no broken call and shows only that the detached workload runs as before. That miss is why the bench got `BENCH_CHAOS_SSH=1` (`033c88f`), which breaks the sessions from the VM's side.

**Verdict** (`verdict.txt`):

- rrpverify-service: 50 checks, 0 not as expected
- rrpverify-veraison-fixed: 122 checks, 120 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-fork: 122 checks, 120 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-v015: 162 checks, 0 not as expected
- VERDICT PASS: 212 checks: the honest Evidence passed, every attack refused for its own reason

**Compared check by check with `20261007T060138Z-aws-sev-snp` (the release's last run, from a fresh clone): all four result files identical (`rrpverify-service`, `-veraison-fixed`, `-fork`, `-v015`).**

The VM was deleted and the deletion checked: `instance i-02feb5869ee406294: terminated at 2026-10-07T13:27:01Z` (`vm-deleted.txt`).
