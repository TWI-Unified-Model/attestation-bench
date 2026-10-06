# Veraison on go-sev-guest v0.15.0, with AMD's roots for VCEK and VLEK (06.10.2026, 18:13–18:24 UTC)

Local only. Nothing pushed. No VM in this step: it re-verifies today's saved hardware Evidence.

## Which go-sev-guest the group's code uses (checked 06.10 through the GitHub API)

| Code | go-sev-guest |
|---|---|
| TACRA main `0d858d0`, `platform/go.mod` (our merged PR #8) | v0.15.0 |
| The group's Veraison fork, TWI-Unified-Model/veraison-services main `f997c52` | v0.14.2-0.20251119154202-af1c107a648f |
| Upstream veraison/services main `c6161f4` (05.10.2026) | v0.14.2-0.20251119154202-af1c107a648f |
| Our bench Veraison until today (`cd2afab` + `675fe11`) | v0.14.2-0.20251119154202-af1c107a648f |

So the bench verifier was on the **same** go-sev-guest as the group's Veraison. v0.15.0 is the latest release, and the
group's platform package already uses it. This step builds the verifier on v0.15.0 too, so the results hold on both.

## The finding

- **v0.15.0, no `Options.TrustedRoots`:** `verify.decodeCerts` uses `trust.GetDefaultRootCerts(productLine)`
  (`verify/verify.go:490-503`). Its Milan, Genoa and Turin entries are built from the VCEK bundles only
  (`verify/trust/trust.go:422-443`), so they hold no ASVK. Every VLEK report therefore fails at `verify.go:414-415`:
  "root of trust missing intermediate certificate authority certificate for key VLEK". AWS shared tenancy signs with a
  VLEK.
- **v0.14.2-pre (no `TrustedRoots`):** took the ASK/ASVK and ARK from the Evidence's chain (`verify.go:525-539`).
  - It cross-checked the ARK, and the ASK, against the embedded SEV-format AMD keys (`verify.go:191-206`, `148-160`).
  - The ASVK had no SEV-format key to compare with (`verify.go:185`). It had to verify up to that pinned ARK.

  So VLEK worked, anchored at AMD's ARK.
- **Consequence:** when Veraison (upstream or the group's fork) moves to v0.15.0 as it stands, AWS Evidence is refused.

## The change (veraison-services branch `hw/go-sev-guest-v0.15.0`, commit `2d18260`, from `675fe11`)

- `go.mod`: go-sev-guest v0.15.0. No other module changed; `go mod verify` passed. The go.sum hash equals the tacra
  platform's.
- `scheme/sevsnp/scheme.go`: `validateReportIntegrity` passes `TrustedRoots` built once from the six chains go-sev-guest
  embeds (VCEK and VLEK for Milan, Genoa, Turin; one root per AMD KDS chain, the library's own `RootOfTrustToOptions`
  idiom).
  - The Turin VLEK chain is trimmed first (google/go-sev-guest#206).
  - Veraison's own check that the Evidence's ARK equals the provisioned trust anchor is unchanged.
  - v0.15.0 does not write to the roots it is given (a search of `verify/*.go` finds no assignment to a root's
    certificates or to `TrustedRoots`), so one shared map is safe.
- `scheme/sevsnp/scheme_vlek_test.go`, with a real VLEK report as test data:
  - the source is `20261006T174402Z-aws-snp-redirect/with-rrp-id/redir/enroll-absent-none/evidence.tsm.cbor`, sha256
    `55e6cca0…67b0`, CHIP_ID zero;
  - `Test_amdRoots` checks the roots;
  - `Test_ValidateEvidenceIntegrity_VLEK` covers the honest report, another nonce, and one bit of MEASUREMENT changed.

## Checks, in order (files here)

1. `01-test-before-fix.txt`: the new test on v0.15.0 **without** the change fails with the `verify.go:415` error. The
   nonce check still works.
2. `02-test-deployed-pin-v0.14.2-pre.txt`: the same test on the old pin, no change: passes.
3. `03-test-after-fix.txt`: the whole sevsnp package on v0.15.0 with the change: all tests pass, including the changed
   MEASUREMENT, which is refused by the report signature check.
4. `07-amd-bundles.txt` (`hwcheck/scripts/compare-amd-bundles.py`):
   - for each product line, the ARK in the VCEK bundle and in the VLEK bundle is the same DER;
   - the Milan VLEK chain fetched from AMD KDS during today's AWS run equals the embedded one, certificate by
     certificate.
5. `04-build.log`, `05-build-info.txt`: the full `make COMBINED_PLUGINS=1` (as `deployment.sh build`) at `2d18260`,
   with Go 1.27.0.
   - Every service and plugin carries `2d18260`.
   - go-sev-guest v0.15.0 is in vts, management and the sevsnp plugin.
   - `modified=true` is only the protobuf headers that `make` regenerates, byte-identical to the old build's tree.
6. `06-deploy.txt`: the swap and restart, then the deployed build info.
   - The backup is `~/veraison-deployment/backup-20261006-go-sev-guest-v0.14.2-pre/`: 19 files, sha256-verified.
   - The swap followed `_deploy_bins`: stop, install, start.
   - The plugin loaded, and the verification API still takes only client-CA callers.
7. **Offline re-verification of today's saved hardware Evidence**, compared check by check with the morning
   (`hwcheck/scripts/compare-rrpverify.py`):

| Evidence | Mode, Veraison | Result | Same as morning, per check |
|---|---|---|---|
| AWS SEV-SNP (VLEK) `20261006T161751Z` | service: deployed, now v0.15.0 + AMD roots | 50 checks, 0 not as expected | 0 differ |
| GCP SEV-SNP (VCEK) `20261006T160939Z` | service: deployed, now v0.15.0 + AMD roots | 50, 0 | 0 differ |
| AWS SEV-SNP | in-process `fixed` (old code, v0.15.0), the control | 122 checks, 120 not as expected | 0 differ (the morning's result reproduced) |
| AWS SEV-SNP | in-process `v015` (the change) | **162, 0** | — |
| GCP SEV-SNP | in-process `fixed` / `v015` | 162, 0 / 162, 0 | 0 differ / 0 differ |
| AWS `v015` vs GCP `v015` | in-process | the same 162 checks, the same outcomes | 0 differ |

`binaries.sha256` lists the two rrpverify builds used. They were built from this tree with `go.patched.mod` and
`go.v015.mod` and kept outside git.

## What this step does not show
- No new hardware run. The e2e, attack and #20 runs on the new verifier follow, each in its own evidence directory.
- TDX is not affected: the bench's TDX verifier uses go-tdx-guest, and Veraison has no TDX scheme.
- Revocation (CRL) is still not checked, as before (`CheckRevocations: false`, AMD KDS rate limits).
