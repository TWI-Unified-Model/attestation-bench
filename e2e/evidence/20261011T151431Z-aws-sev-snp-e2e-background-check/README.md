# A host's fault, kept: AWS SEV-SNP, Background Check, 11 October 2026 15:14Z

Every one of the 10 Targets failed before any message of the protocol was sent: the guest could not produce Evidence.
The configfs-tsm report request returned, for its `auxblob` (the host's certificate table, which an AWS guest's report needs
for the VLEK chain), `read /sys/kernel/config/tsm/report/entryNNN/auxblob: invalid argument` (results.json, every Target;
e2e-attester-stdout.txt). The instance was `i-049fc76cff9638af8` (instance.txt): the same AMI, instance type and zone as the
runs around it, `ami-09519cc56eb20524a`, `c6a.large`, `us-east-2a`, with the same kernel `7.0.0-1014-aws`.

It is the first such outcome in the evidence this repository holds. The run was made again on a fresh instance
(`i-0fa5d28d33fc589c6`) with the same committed trees, 16:15Z, and came out as the others: 10 of 10 Targets
([20261011T161559Z-aws-sev-snp-e2e-background-check](../20261011T161559Z-aws-sev-snp-e2e-background-check)). The AWS
Passport runs of 15:06Z and 15:50Z, on other instances, had no such trouble.

Nothing about the protocol or the trees under test is in this run; it is kept because a bench that hides its own faults,
or its hosts', cannot be trusted with a protocol's. What a run does not prove in general: docs/limits.md.
