# AWS EC2, AMD SEV-SNP

```bash
make demo     PLATFORM=aws-snp
make attacks  PLATFORM=aws-snp
make redirect PLATFORM=aws-snp
```

## What you need

- An AWS account with the `aws` CLI signed in (`aws configure`, or `aws sso login`).
- A **default VPC** with a default subnet in the availability zone (`us-east-2a` by default): the scripts launch the
  instance there.
- Quota for 2 vCPUs of on-demand standard instances in the region (`us-east-2` by default); AWS counts this quota in
  vCPUs.
- Outbound HTTPS to `checkip.amazonaws.com`: the run admits SSH only from your machine's public address, which it
  looks up there.

## What a run creates

- One instance: `c6a.large` with `AmdSevSnp=enabled`, Ubuntu 24.04 LTS (the AMI that Canonical's public SSM parameter
  names), instance metadata requiring tokens (IMDSv2), tagged `purpose=tacra-*`.
- A throwaway key pair.
- A security group that admits SSH from your address only.

All three are deleted at the end, and the run checks each is gone (`vm-deleted.txt`).

The reports are signed by a **VLEK**: on AWS, AMD signs the cloud provider's key, not each chip's. Checking a VLEK
needs AMD's VLEK roots, which go-sev-guest v0.15.0 does not use by default; the bench's Veraison build gives it AMD's
roots for both VCEK and VLEK (`third_party/veraison-services`).

## What each experiment checks, and what to expect

| Command | Result in the reference runs |
|---|---|
| `make demo` | 10 of 10, Veraison `affirming` ten times ([Passport](../../e2e/evidence/20261006T223210Z-aws-sev-snp-e2e-passport), [Background Check](../../e2e/evidence/20261006T224133Z-aws-sev-snp-e2e-background-check)) |
| `make attacks` | all ten reports VLEK-signed; `v015` 162 checks, the deployed Veraison 50, 0 not as expected; `fork` and `fixed` 122 checks, 120 not as expected, because without AMD's VLEK roots they cannot check the reports at all ([run](../../hwcheck/evidence/20261006T225323Z-aws-sev-snp)) |
| `make redirect` | 20 of 20 cases as in [getting-started.md](../getting-started.md), step 9 ([run](../../hwcheck/evidence/20261006T230316Z-aws-snp-redirect)) |

## Note

AWS signs no endorsement of this launch measurement. The approved value is the measurement of AWS's published EC2
SEV-SNP firmware, release 20260814, for a c6a.large's two vCPUs; `make trust-check` computes it again from that
binary. A rebuild of the firmware from AWS's source did not give the published binary, so the value rests on AWS's
binary, not on a reproduced build: see [../../trust/README.md](../../trust/README.md) and
[../limits.md](../limits.md).
