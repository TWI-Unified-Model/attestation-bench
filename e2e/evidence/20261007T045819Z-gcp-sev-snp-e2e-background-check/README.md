# A run the network stopped, after the bench had served it

`make demo PLATFORM=gcp-snp` in Background Check, 7 October 2026, at `6e9e98f` (`code-revs.txt`). Not sealed and not
judged: the run ended early, and `make report` lists it as stopped.

The SSH session that ran the workload in the guest broke: `ssh.stderr` has the read from the VM timing out. The run
then stopped before it copied the guest's results and the trust zone's logs, and the VM was deleted
(`vm-deleted.txt`). The trust zone's own logs, on the bench machine, show the guest had been served: between
05:00:10 and 05:00:16 UTC the CA gateway enrolled the five `db-*` Targets and the Vault gateway released the five
`ledger-*` ones, each after asking Veraison, as Background Check does. The workload's output never reached the bench
(`e2e-attester-stdout.txt` is empty), so this directory cannot show it.

The same run, made again on the same code: `e2e/evidence/20261007T052602Z-gcp-sev-snp-e2e-background-check`, `VERDICT PASS: all 10 Targets`.
