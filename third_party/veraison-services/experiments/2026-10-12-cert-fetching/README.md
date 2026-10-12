# Certificate fetching instead of roots: the proposal on veraison/services#490, measured

12 October 2026. On PR veraison/services#490 (the chain verified up to AMD's roots held by the
scheme) the reviewer proposed, instead, a separate configuration for AWS that turns go-sev-guest's
certificate fetching on (`DisableCertFetching: false`), since `fillInAttestation` fills the missing
ASK/ASVK and ARK from AMD's KDS. These three experiments measure that proposal on Veraison `main`
(b1cd67e, the PR's base) with the single change `DisableCertFetching: true` → `false` in
`scheme/sevsnp/scheme.go`, against two real reports already in the PR's fixtures:

| fixture | sha256 | report |
|---|---|---|
| `sevsnp-aws-vlek-tsm-report.cbor` | `55e6cca06e137b690ed1ab29486448bd8286887f07dfb7e1d18449b6740167b0` | AWS EC2 c6a.large, Milan, VLEK-signed, 6 Oct 2026 |
| `sevsnp-gcp-tsm-report.cbor` | `ddc3306caf7fd898cf38b41c81cf528aa21959e8cbceb55e0e3c5593d939605a` | Google Cloud, Milan, VCEK-signed, 7 Oct 2026 |

The AWS table is cut down to its first entry, the VLEK alone, as the AWS host supplies it; the
GCP table likewise to the VCEK alone (a host that supplies the leaf only). `exp_fetching_test.go`
is the test file as run; it reaches `kdsintf.amd.com` and is not for submission.

## Results

**E1, the flag alone** (`Test_E1_FetchingFlagAlone`, Veraison's pin go-sev-guest
v0.14.2-0.20251119154202-af1c107a648f). The scheme refuses the AWS report before go-sev-guest
runs: `GetTrustAnchorIDs` → `can't read ARK to compose TA ID: empty certificate`;
`ValidateEvidenceIntegrity` → `missing ARK certificate in evidence` (`ErrNoARK`, from
`validateCertChain`). Three places on `main` require the ARK and ASK in the host's table
(`GetTrustAnchorIDs`, `validateCertChain` + the `bytes.Equal` with the trust anchor,
`validateReportIntegrity`'s two `readCert` calls); the flag changes none of them. The DER table
also needs #488 (`readCert` on `main` is PEM-only).

**E2, go-sev-guest alone with the VLEK and fetching on** (`Test_E2_FetchingWithVLEKAlone`, same
pin). `verify.SnpAttestation` fetches `https://kdsintf.amd.com/vlek/v1/Milan/cert_chain` (4611
bytes) once and verifies the report; a second verification in the same process makes no KDS call
(the product-chain cache, `trust.GetProductChainContext`). So the fetching half works on the pin,
after the scheme's three checks are rewritten, and with a KDS round trip per process per product
line.

**E3, both kinds through one process** (`Test_E3_ProductChainCacheAcrossSigners`, same pin).
go-sev-guest's product-chain cache is keyed by product line alone (`productLineCertCache[productLine]`)
while the KDS path differs by signer (`vcek/v1/…` vs `vlek/v1/…`). A VCEK report verified first,
then the VLEK report: `trusted root must have ASVK certificate for VLEK chain`, no KDS call. The
other order: `trusted root must have ASK certificate for VCEK chain`. Each kind alone, fresh cache:
verified. The cache lives for the process; a Verifier that sees both AWS (VLEK) and a VCEK host that
supplies the leaf alone, on the same product line, fails the second kind until restart. Same keying
in go-sev-guest `main` (9c5dffc, 7 Oct 2026).

**On go-sev-guest v0.15.0** (`run-go-sev-guest-v0.15.0.txt`, the same tests with the module
upgraded): the VLEK report is refused with fetching on, even in a fresh cache: `VLEK could not be
verified by any trusted roots. Last error: root of trust missing intermediate certificate authority
certificate for key VLEK`. v0.15.0 (commit 726e291, "enforce public key pinning to prevent
attestation bypass", PR #190) takes the roots from `trust.GetDefaultRootCerts(productLine)` when
none are given and ignores the chain's intermediates; the defaults are built from the VCEK bundles
only, so they hold no ASVK. With v0.15.0 the only way to verify a VLEK report is `TrustedRoots`
carrying an ASVK, which is what #490 supplies. The VCEK report still verifies (defaults hold the
ASK).

Google's own position, go-sev-guest issue #134 (deeglaze, 29 Sep 2024): "The certificate info is
provided by the VMM operator, and AWS expects users to already add the ASVK … and ARK to their own
trust anchors. The VLEK in the buffer is all that AWS provides, and it should be sufficient."

## Reproduce

```
git -C ~/dev/vs-main worktree add --detach /tmp/vs-exp b1cd67e
cp sevsnp-aws-vlek-tsm-report.cbor sevsnp-gcp-tsm-report.cbor /tmp/vs-exp/scheme/sevsnp/test/evidence/
cp exp_fetching_test.go /tmp/vs-exp/scheme/sevsnp/
sed -i '' 's/DisableCertFetching: true,/DisableCertFetching: false,/' /tmp/vs-exp/scheme/sevsnp/scheme.go
cd /tmp/vs-exp && go test ./scheme/sevsnp/ -run 'Test_E1_|Test_E2_|Test_E3_' -v -count=1
go get github.com/google/go-sev-guest@v0.15.0 && go test ./scheme/sevsnp/ -run 'Test_E3_' -v -count=1
```
