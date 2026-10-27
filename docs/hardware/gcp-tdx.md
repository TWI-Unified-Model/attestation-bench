# Google Cloud, Intel TDX

```bash
make demo     PLATFORM=gcp-tdx
make attacks  PLATFORM=gcp-tdx
make redirect PLATFORM=gcp-tdx
```

## What you need

As for [gcp-snp.md](gcp-snp.md), with quota for 4 C3 vCPUs instead of N2D: a Google Cloud project with billing and
the Compute Engine API, `gcloud` signed in with the project set (or `GCP_PROJECT`), and the same login: the bench's
ssh key in the guest's metadata.

## What a run creates

One VM: `c3-standard-4`, confidential compute type `TDX`, maintenance policy `TERMINATE`, Ubuntu 24.04 LTS, a 20 GB
disk, the bench's ssh key in its metadata, labelled `purpose=tacra-*`. The guest's TD quote is signed by its Quoting Enclave and certified by
Intel (the PCK chain). It is deleted at the end and the deletion is checked.

## The TDX verifier

The group's Veraison has no TDX scheme, so TDX quotes are appraised by the bench's own verifier, `tdx-verifier`
(`rrp/cmd`): go-tdx-guest checks the quote against Intel's collateral, then the verifier checks the launch (MRTD) against
the approved list and signs an EAR, with the same session interface as Veraison.

Google runs more than one build of its TDX firmware, and a new VM may get any of them. Both builds met so far are
approved, each on Google's signed launch endorsement ([../../trust/README.md](../../trust/README.md)). A VM that
starts on a build not on the list is refused (`contraindicated`), as policy requires: approve the new build only after
its endorsement checks out.

## What each experiment checks, and what to expect

| Command | Result (7 October 2026) |
|---|---|
| `make demo` | 10 of 10, the TDX verifier `affirming` ten times, firmware build `f21e6b48…` ([Passport](../../e2e/evidence/20261007T174534Z-gcp-tdx-e2e-passport), [Background Check](../../e2e/evidence/20261007T173412Z-gcp-tdx-e2e-background-check)) |
| `make attacks` | 162 checks, 0 not as expected: 82 in process, 50 through the deployed TDX verifier, 30 of the platform rule; the pre-play: with the guest's clock 300 s ahead, the four other kinds taken at once and absent-timestamp from 295 s to 420 s after it was made; with it behind, refused ([run](../../hwcheck/evidence/20261007T214424Z-gcp-tdx)) |
| `make redirect` | 20 of 20 cases as in [getting-started.md](../getting-started.md), step 9: `ca1` issued in every case, so the binding it recomputed matched the TD quote each time ([run](../../hwcheck/evidence/20261007T183127Z-gcp-tdx-redirect)); with the conduit's 20 rewrites as [attacks.md](../attacks.md), section 2, says, in Background Check ([run](../../hwcheck/evidence/20261007T204937Z-gcp-tdx-redirect)) and in Passport ([run](../../hwcheck/evidence/20261007T210314Z-gcp-tdx-redirect-passport)) |
