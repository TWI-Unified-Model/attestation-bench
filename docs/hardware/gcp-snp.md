# Google Cloud, AMD SEV-SNP

```bash
make demo     PLATFORM=gcp-snp
make attacks  PLATFORM=gcp-snp
make redirect PLATFORM=gcp-snp
```

## What you need

- A Google Cloud project with billing and the Compute Engine API enabled.
- The `gcloud` CLI, signed in (`gcloud auth login`), with the project set (`gcloud config set project <id>`) or given
  as `GCP_PROJECT`.
- Quota for 2 N2D vCPUs in the zone's region (`us-central1` by default).
- Nothing more for the login. The guest takes the ssh key of the account that runs the bench,
  `~/.ssh/google_compute_engine`, made if missing, in its own metadata, with OS Login off and project-wide keys
  blocked. The scripts run the workload with `sudo`, which that user has on a fresh Ubuntu guest.

`make doctor` checks that `gcloud` and `ssh` are installed.

## What a run creates

One VM: `n2d-standard-2`, minimum CPU platform AMD Milan, confidential compute type `SEV_SNP`, maintenance policy
`TERMINATE`, Ubuntu 24.04 LTS (image family `ubuntu-2404-lts-amd64`), a 20 GB disk, the bench's ssh key in its
metadata, labelled
`purpose=tacra-e2e`, `tacra-hwcheck` or `tacra-redir`. Its reports are signed by the chip's VCEK. It is deleted at the
end and the deletion is checked.

## What each experiment checks, and what to expect

| Command | Checks | Result (7 October 2026) |
|---|---|---|
| `make demo` | the ten Targets end to end, through the EST server, with Veraison appraising each report | 10 of 10, Veraison `affirming` ten times; the RRPs admit the host only under the bench's named waiver of AMD-SB-3034's bit 4, which the verdict names, and a bank's rule refuses it ([../limits.md](../limits.md)) ([Passport](../../e2e/evidence/20261007T174229Z-gcp-sev-snp-e2e-passport), [Background Check](../../e2e/evidence/20261007T173058Z-gcp-sev-snp-e2e-background-check)) |
| `make attacks` | the honest reports and one changed input at a time, with Veraison's SEV-SNP appraisal in three builds, then through the deployed Veraison | 262 checks, 0 not as expected: the builds below, and 50 of the platform rule; the pre-play: with the guest's clock 300 s ahead, the four other kinds taken at once and absent-timestamp from 295 s to 420 s after it was made; with it behind, refused ([run](../../hwcheck/evidence/20261007T212531Z-gcp-sev-snp)) |
| `make redirect` | one Evidence offered to two Credential Authorities, with and without the RRP identifier | 20 of 20 cases as in [getting-started.md](../getting-started.md), step 9 ([run](../../hwcheck/evidence/20261007T182724Z-gcp-snp-redirect)); with the conduit's 20 rewrites as [attacks.md](../attacks.md), section 2, says, in Background Check ([run](../../hwcheck/evidence/20261007T204444Z-gcp-snp-redirect)) and in Passport ([run](../../hwcheck/evidence/20261007T205826Z-gcp-snp-redirect-passport)) |

`make attacks` appraises the same reports with three builds of Veraison's SEV-SNP scheme, to show what each fix
changes (`third_party/veraison-services`):

| Build | Result |
|---|---|
| `v015`: our patches on go-sev-guest v0.15.0, with AMD's roots | 162 checks, 0 not as expected |
| `fixed`: the DER and signer-info fixes on the group's fork | 162 checks, 0 not as expected |
| `fork`: the group's fork as it is | 142 checks, 60 not as expected: it refuses the reports' DER certificate table, which `fixed` and `v015` read |
| the deployed Veraison, as an RRP asks it | 50 checks, 0 not as expected |

"Not as expected" on the fork is the finding these runs record, not a failure of the run.

## Notes

- Google Cloud signs a launch endorsement for its SEV-SNP firmware; the approved launch's endorsement was checked
  against Google's pinned root ([../../trust/README.md](../../trust/README.md)).
- `CAS_OUTSIDE=1 make demo PLATFORM=gcp-snp` runs the CAS Client on your machine instead of inside the VM, the
  configuration where the conduit is entirely outside the guest.
