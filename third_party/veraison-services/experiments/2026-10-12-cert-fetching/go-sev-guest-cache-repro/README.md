# go-sev-guest: the product-chain cache is keyed by product line alone

Standalone reproduction (go-sev-guest only; the two real Milan reports and their leaf certificates are inside
`cache_test.go` as base64: the GCP VCEK report of 7 Oct 2026 and the AWS VLEK report of 6 Oct 2026, from the
fixtures of veraison/services#488 and #490). `trust.GetProductChainContext` caches `productLineCertCache[productLine]`
while the URL it fetches depends on the signer (`vcek/v1/<line>/cert_chain` vs `vlek/v1/<line>/cert_chain`): the first
request for a product line decides what every later request for that line gets, whatever its signer.

Runs of 12 October 2026 (`gsg-cache-repro-<version>.txt`):

| go-sev-guest | SnpAttestation, fetching on, leaf alone | GetAttestationFromReport |
|---|---|---|
| v0.14.2-0.20251119154202-af1c107a648f (veraison/services' pin) | the second kind fails: "trusted root must have ASVK certificate for VLEK chain" / "…ASK certificate for VCEK chain", nothing fetched for it | the VCEK report after a VLEK one gets the VLEK chain's intermediate (SEV-VLEK-Milan) |
| v0.15.0 | verification uses the embedded defaults (726e291), but the chain filled in carries the wrong intermediate | same |
| main 9c5dffc (verification no longer fetches the chain, 888c4d1) | skipped by the test | same |

Filed as google/go-sev-guest#209 on 12 October 2026 (21:01:58Z); the module as published: https://gist.github.com/nikolaichuk7/995b2f4f0cb5d0fe0efc84f9d1149c96.
