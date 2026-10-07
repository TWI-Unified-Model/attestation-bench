# Running on real hardware

The three experiments of [getting-started.md](../getting-started.md) run on real confidential hardware in your own
cloud account, with the same commands and one setting:

```bash
make demo     PLATFORM=gcp-snp
make attacks  PLATFORM=gcp-tdx
make redirect PLATFORM=aws-snp
```

Each command creates one confidential VM, builds the programs for it, copies them in, runs, copies the results back,
deletes the VM, checks that it is gone, and writes a run directory under `~/.attestation-bench/runs/`. The trust zone
stays on your machine, so the bench must be running (`make status`). In `demo` the workload in the VM reaches it
through an SSH reverse tunnel, with TLS end to end over it; in `attacks` and `redirect` the VM only produces the
reports, and every check runs on your machine.

| Platform | Page | Machine | What signs the report |
|---|---|---|---|
| `gcp-snp` | [gcp-snp.md](gcp-snp.md) | Google Cloud `n2d-standard-2`, AMD Milan | the chip's VCEK |
| `gcp-tdx` | [gcp-tdx.md](gcp-tdx.md) | Google Cloud `c3-standard-4`, Intel TDX | the TD's Quoting Enclave, certified by Intel |
| `aws-snp` | [aws-snp.md](aws-snp.md) | AWS EC2 `c6a.large`, AMD Milan | a VLEK, AMD's key for the cloud provider |

## Which cloud account

The bench keeps no cloud credentials. It uses the account your cloud's own CLI is signed in to, and asks first
(`scripts/lib.sh`):

| Setting | Default | Meaning |
|---|---|---|
| `GCP_PROJECT` | `gcloud config get-value project` | the Google Cloud project the VMs go into |
| `GCP_ZONE` | `us-central1-c` | where the reference runs ran both SEV-SNP and TDX |
| `AWS_REGION` | `us-east-2` | where the reference runs ran SEV-SNP |
| `AWS_AZ` | zone `a` of `AWS_REGION` | the availability zone |

Every hardware command first says where it will create the VM, for example
`== Google Cloud: project my-project, zone us-central1-c`, and stops before creating anything if the CLI is missing,
not signed in, or the project does not exist.

```bash
GCP_PROJECT=my-project make demo PLATFORM=gcp-snp
AWS_REGION=us-east-2 make attacks PLATFORM=aws-snp
```

## Cost and time

Each run keeps one small VM, billed by the cloud at that machine's price for as long as it exists. In the fourteen
hardware runs of `make demo`, `attacks` and `redirect` on 7 October 2026 (under `e2e/evidence/` and
`hwcheck/evidence/`), a run took between 108 and 272 seconds from its start to the VM's deletion: the start is in
the run directory's name, the time the VM was found gone in its `vm-deleted.txt`. Nothing else is left running.

## Cleanup

Every run deletes its VM, and on AWS its throwaway key pair and security group, and records that in `vm-deleted.txt`,
with the time the VM was found gone. If a run is interrupted (a closed terminal, a lost network), check both clouds
by hand:

```bash
make cloud-check
```

It lists what is left of the bench in `GCP_PROJECT` and `AWS_REGION` (VMs, disks, firewall rules, key pairs, security
groups), and ends with `cloud-check: nothing left`. Anything it lists, delete in the cloud's console or CLI.

## Reading the results

A hardware run directory holds what a local one does, plus what came back from the VM: the kernel it ran
(`kernel.txt`), the machine type, the reports, and the deletion record. [../results.md](../results.md) explains each
file.
