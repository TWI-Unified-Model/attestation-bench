# hwcheck on Google Cloud SEV-SNP, two calls to the VM killed (2026-10-07, 13:19Z)

Plan R5: a broken SSH session must not end a hardware run. The command: `RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=gcp-snp`, at `5eb6dba` (`code-rev.txt`), the first run with the workload detached from the SSH session (`bench_guest_run`, `scripts/lib.sh`).

While the workload ran in the guest (from 13:20:52Z), the client of the call in flight to the VM was killed on this machine twice, 20 s apart: the `gcloud compute ssh` process at 13:21:12Z and again at 13:21:33Z. `run-ssh.stderr` records both: `a call to the VM failed; asking again`. The workload ran on, the bench asked again, and its whole output came back (`hwrun-stdout.txt`). Both kills hit gcloud itself, possibly before its SSH session was up; the runs `20261007T134512Z-aws-sev-snp` and `20261007T134801Z-gcp-sev-snp` break established sessions from the VM's side.

**Verdict** (`verdict.txt`):

- rrpverify-service: 50 checks, 0 not as expected
- rrpverify-veraison-fixed: 162 checks, 0 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-fork: 142 checks, 60 not as expected (a build the bench compares with: reported, not judged)
- rrpverify-veraison-v015: 162 checks, 0 not as expected
- VERDICT PASS: 212 checks: the honest Evidence passed, every attack refused for its own reason

**Compared check by check with `20261007T055700Z-gcp-sev-snp` (the release's last run, from a fresh clone): all four result files identical (`rrpverify-service`, `-veraison-fixed`, `-fork`, `-v015`).**

The VM was deleted and the deletion checked: `== tacra-hwcheck-2610071319 is gone at 2026-10-07T13:23:52Z` (`vm-deleted.txt`).
