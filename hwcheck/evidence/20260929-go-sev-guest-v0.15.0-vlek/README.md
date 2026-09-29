# go-sev-guest v0.15.0 rejects VLEK-signed reports (AWS) when the caller passes no trusted roots

Found on 29 September 2026 while re-running hwcheck with the code of PR 1 (`platform/` at 2d1a4c3, which moves
go-sev-guest from v0.14.2-0.20251119154202-af1c107a648f to the v0.15.0 release).

## What we saw

The AWS SEV-SNP run `20260929T184109Z-aws-sev-snp` failed RRP verification: 120 of 122 checks not as expected, with
both Veraison builds, all with "VLEK could not be verified by any trusted roots. Last error: root of trust missing
intermediate certificate authority certificate for key VLEK". The GCP SEV-SNP and GCP TDX runs of the same code were
as expected.

## The Evidence is not the cause

`cross-check/MATRIX.txt`: the same rrpverify (Veraison with the DER and signer-info fixes), built once with each
go-sev-guest version, on the AWS Evidence of 28 September (the old plug-in) and of 29 September (PR 1):

| Evidence | verifier with v0.14.2-0.20251119154202-af1c107a648f | verifier with v0.15.0 |
|---|---|---|
| 28 September (old plug-in) | 162 checks, 0 not as expected | 122 checks, 120 not as expected |
| 29 September (PR 1 plug-in) | 162 checks, 0 not as expected | 122 checks, 120 not as expected |

The 29 September Evidence carries the whole chain: VLEK (CN `SEV-VLEK`), issued by `SEV-VLEK-Milan` (the ASVK, in
the table's ASK slot), issued by `ARK-Milan`.

## Cause

go-sev-guest commit 726e291c52 (9 June 2026, "fix(verify): enforce public key pinning to prevent attestation
bypass"), released in v0.15.0. When `verify.Options.TrustedRoots` is empty, `verify.SnpAttestation` no longer builds
the root of trust from the certificates that arrive with the Evidence; it uses `trust.GetDefaultRootCerts`. The
change closes a real gap: before it, the ASK and ARK were decoded from the incoming chain and checked for metadata
only. But `trust.DefaultRootCerts` is filled only from the VCEK bundles (`AskArkMilanVcekBytes`,
`AskArkGenoaVcekBytes`, `AskArkTurinVcekBytes`), so it holds an ASK and no ASVK, and every VLEK-signed report is
refused. go-sev-guest main of 25 September is unchanged; we found no issue or pull request about it.

## Who is affected

- veraison-services `scheme/sevsnp/scheme.go` builds `verify.Options` without `TrustedRoots` (lines 687-692 in
  TWI-Unified-Model/veraison-services f997c52) and calls `verify.SnpAttestation`. Veraison pins
  v0.14.2-0.20251119154202-af1c107a648f (the fork, and veraison/services main 8e348c7 of 28 September), so a deployed
  Veraison accepts AWS Evidence today and will refuse it after moving to v0.15.0 unless it passes trusted roots.
- TWI tacra: no module imports `go-sev-guest/verify`. `platform` uses only `trust.AskArk*Bytes` and
  `kds.ParseProductCertChain` to complete the chain. PR 1's version change does not touch any verification in the
  repository.
- hwcheck: one Go module requires both the plug-in and Veraison, so the plug-in's v0.15.0 became the version the
  verifier links. The `-at-veraison-pin` results in `20260929T184109Z-aws-sev-snp` are built with Veraison's own
  version (`verification-builds/` there); they are the ones that correspond to a deployed Veraison.

## Workaround, tested

`hwcheck/vlekcheck` calls `verify.SnpAttestation` on each report three ways: (a) no `TrustedRoots`, as Veraison
does; (b) the Milan VLEK chain (ASVK and ARK) as `TrustedRoots`; (c) both Milan chains. Ten AWS and ten GCP reports
from the PR 1 plug-in (`vlekcheck-*.txt`):

| Evidence | go-sev-guest | (a) no trusted roots | (b) VLEK chain | (c) VCEK and VLEK chains |
|---|---|---|---|---|
| AWS, VLEK | v0.14.2-0.20251119154202-af1c107a648f | 10 accepted | 10 accepted | 10 accepted |
| AWS, VLEK | v0.15.0 | 10 refused | 10 accepted | 10 accepted |
| GCP, VCEK | v0.14.2-0.20251119154202-af1c107a648f | 10 accepted | 10 refused | 10 accepted |
| GCP, VCEK | v0.15.0 | 10 accepted | 10 refused | 10 accepted |

A verifier on v0.15.0 has to pass both chains for each product line:

```go
vcek := &trust.AMDRootCerts{ProductLine: "Milan"}
vlek := &trust.AMDRootCerts{ProductLine: "Milan"}
_ = vcek.FromKDSCertBytes(trust.AskArkMilanVcekBytes)
_ = vlek.FromKDSCertBytes(trust.AskArkMilanVlekBytes)
opts.TrustedRoots = map[string][]*trust.AMDRootCerts{"Milan": {vcek, vlek}} // and Genoa, Turin
```

## Not reported upstream

The candidates are google/go-sev-guest (add the ASVK to the default roots, or document that VLEK needs
`TrustedRoots`) and veraison/services (pass `TrustedRoots` before moving to v0.15.0). As with findings 1-3 in
`hwcheck/RESULTS.md`, reporting is for the SIG to decide.
