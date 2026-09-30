# TACRA on real hardware: the binding through the SIG's own components (28 September 2026)

Private to the TWI SIG (this repository is private). Nothing here is published elsewhere.

## What was built on the SIG's code

- `platform/sevsnp.go`, `platform/tdx.go`: two hardware back-ends for `platform.Plugin`, next to the simulated one.
  Evidence is the Linux configfs-tsm report encoded as the Veraison TSM report
  (`application/vnd.veraison.tsm-report+cbor`, the format the `sevsnp` scheme of veraison-services takes). The
  guest-chosen field (SEV-SNP `REPORT_DATA`, TDX `REPORTDATA`, 64 octets each) is SHA-512 of the binding input of
  draft-novak-lamps-tacra-est, Section 9.1.5: the freshness element, the RRP identifier, the Target and the CSR (or the
  SubjectPublicKeyInfo of the CEK), each with a 32-bit length. The Go code reproduces the draft's Appendix A test
  vector, which the Python reference implementation produced.
- `EvidenceRequest` gains `Target` and `RelyingParty`; `cai.go` passes the Target.
- `hwcheck/cmd/hwrun` (Attester, in the guest): Enrollment and Retrieval in all five Freshness Kinds, with Freshness
  Handles minted by the RRP; then a burst of reports for timing.
- `hwcheck/cmd/rrpverify` (RRP, on another machine): recomputes the binding value from its own records and calls
  `ValidateEvidenceIntegrity` of the Veraison `sevsnp` scheme with that value as the session nonce and AMD's ARK
  (from the AMD KDS) as trust anchor, then `ExtractClaims` and `AppraiseClaims`. Each check is repeated with one input
  changed (Target, RRP identifier, CSR or CEK, freshness element, trust anchor); a refusal counts only if it gives the
  reason the check tests, and only when the honest Evidence passed on the same input. TDX quotes are verified with
  go-tdx-guest against Intel PCS collateral, as veraison-services has no TDX scheme.
- `hwcheck/scripts/{gcp-snp,aws-snp,gcp-tdx}-hwcheck.sh`: create the machine, run, copy back, delete, verify.

The Veraison code is called in-process (the scheme's `Implementation`), not through a deployed Veraison service.

## Runs

| run | cloud, machine | kernel | report signed by | Evidence per call | burst |
|---|---|---|---|---|---|
| `20260928T190538Z-gcp-sev-snp` | GCP n2d-standard-2, AMD Milan | 7.0.0-1011-gcp | VCEK | 8.0-12.9 ms, 5 989 B | 100 reports in 103.0 s: every tenth waited 10.2 s, the rest median 8.1 ms |
| `20260928T191330Z-aws-sev-snp` | AWS c6a.large, us-east-2a | 7.0.0-1013-aws | VLEK, CHIP_ID zero | 7.4-9.1 ms, 2 593 B | 100 reports in 0.8 s: median 8.0 ms, max 11.6 ms, no stall |
| `20260928T193434Z-gcp-tdx` | GCP c3-standard-4, Intel TDX | 7.0.0-1011-gcp | TDX quote v4 (Quoting Enclave) | 39.1-42.0 ms, 4 966 B | 30 quotes: median 39.3 ms, max 41.8 ms, no stall |
| `20260928T201434Z-aws-sev-snp` | AWS c6a.large, us-east-2a | 7.0.0-1013-aws | VLEK, the plug-in appending the Milan ASVK and ARK | 7.9-9.1 ms, 5 963 B | 100 reports: median 8.3 ms, max 12.3 ms, no stall |

Every machine was deleted by the script and the deletion checked (`vm-deleted.txt`). The first TDX run
(`20260928T192839Z-gcp-tdx`) produced no Evidence: an edit had corrupted the script's run line (`NOTE.txt` there).

Later the same day (commit `bb8b97a`) the Evidence of `20260928T190538Z-gcp-sev-snp` and of the second AWS run,
`20260928T201434Z-aws-sev-snp`, was also verified by a deployed Veraison (a native deployment of veraison-services
`hw/tacra-verifier` with its own EAR signing key, provisioned with the ARK-Milan trust anchor and reference values for
both launches): `rrpverify-service.json` in each run, 50 checks each, 10 honest Evidence affirming with the EAR's
eat_nonce equal to the binding value and 40 changed inputs contraindicated, all as expected.

## What the host puts in the certificate table (raw configfs-tsm `auxblob`)

| host | entries | encoding |
|---|---|---|
| GCP | VCEK, ASK, ARK | DER |
| AWS | VLEK only | DER |
| Veraison's own sample (`scheme/sevsnp/test/evidence`) | ARK, ASK, VCEK | PEM |

## Verification outcomes

`fork` = TWI-Unified-Model/veraison-services f997c52 as it is. `fixed` = the same with the two local fixes below.
"As delivered" is the token exactly as the guest produced it; "PEM" re-encodes the (unsigned) certificate table;
"chain completed" adds the ASK/ASVK and ARK the host left out, from the RRP's own trust store.

| run | build | as delivered | PEM | chain completed | appraisal |
|---|---|---|---|---|---|
| GCP SEV-SNP | fork | 10 of 10 honest refused: "evidence Trust Anchor (ARK) doesn't match the provisioned one" | 10 of 10 pass; 50 of 50 changed inputs refused for the tested reason | (nothing missing) | 10 affirming; 10 not affirming with MEASUREMENT one byte off |
| GCP SEV-SNP | fixed | 10 of 10 pass; 50 of 50 refused for the tested reason | same | (nothing missing) | 20 affirming; 20 not affirming |
| AWS SEV-SNP | fork | 10 of 10 refused: "missing ARK certificate in evidence" | same refusal | 10 of 10 pass; 50 of 50 refused for the tested reason | claim extraction fails: "invalid signer info: 4" |
| AWS SEV-SNP | fixed | same refusal as fork | same refusal | same as fork | 10 affirming; 10 not affirming |
| GCP TDX | go-tdx-guest v0.3.1 (no Veraison TDX scheme) | 10 of 10 pass; 50 of 50 changed inputs refused for the tested reason (REPORTDATA; a root that is not Intel's) | (no table) | (no table) | 10 affirming; 10 not affirming with MRTD one byte off (hwcheck's own comparison) |

"Changed inputs" are, per Evidence: another Target, the other RRP's identifier, a CSR or CEK one bit off, another
freshness element, and a trust anchor that is a genuine AMD certificate but not the ARK. Reference values for the
appraisal are taken from the first Evidence of the same launch (trust on first use): this shows that the scheme's
matching works on real reports, not that the launch measurement is the expected one.

## 29 September: the same checks on the code of PR 1

PR 1 (branch `serhii/platform-sevsnp-tdx`, commit 2d1a4c3) puts the two back-ends on TWI main 67ea03e. Its
`platform/` is the one here except for `go.mod`: go-sev-guest v0.15.0, a release, instead of
v0.14.2-0.20251119154202-af1c107a648f (`evidence/20260929-pr1-tested-tree.patch` is the whole difference of the
tested tree).

| run | cloud, machine | report signed by | Evidence per call | burst | RRP verification |
|---|---|---|---|---|---|
| `20260929T183950Z-gcp-sev-snp` | GCP n2d-standard-2, AMD Milan, 7.0.0-1011-gcp | VCEK | 8.5-11.7 ms, 5 989 B | 100 reports: median 8.1 ms, every tenth waited 10.2 s | fixed: 162 checks, 0 not as expected; fork: 142, 60 (finding 1) |
| `20260929T184031Z-gcp-tdx` | GCP c3-standard-4, Intel TDX, 7.0.0-1011-gcp | TDX quote | 39.0-42.1 ms, 4 966 B | 30 quotes: median 39.1 ms, max 40.3 ms | 82 checks, 0 not as expected |
| `20260929T184109Z-aws-sev-snp` | AWS c6a.large, us-east-2a, 7.0.0-1013-aws | VLEK (the same one, 5330c95b...) | 7.3-8.3 ms, 5 963 B | 100 reports: median 7.9 ms, max 9.7 ms | with Veraison's own go-sev-guest: fixed 162, 0; fork 122, 60 (finding 1). With v0.15.0 in the verifier: 122, 120 (finding 4) |

The SEV-SNP run on GCP lost its scripted copy-back and delete to an API timeout; the output was copied from the
still-running VM, checked file by file against the VM, and the VM deleted by hand (`RECOVERY.txt` there). All three
machines are deleted, and GCP and AWS were checked empty afterwards.

## Findings (none reported upstream yet)

1. **veraison-services `sevsnp` refuses Evidence from Google Cloud.** The GCP host writes DER certificates in the
   table; `ValidateEvidenceIntegrity` compares the table's ARK bytes with the PEM trust anchor, and `readCert` reads
   PEM only. Fix (local branch `hw/der-cert-table`, commit 516bf94 on the fork): `readCert` returns DER for either
   encoding and the trust-anchor comparison is made on DER. Its test rewrites the scheme's own sample report as DER;
   on the unfixed code it fails with the ARK mismatch, with the fix it passes, and a wrong nonce and a wrong trust
   anchor are still refused. Upstream veraison/services main has the same code.
2. **veraison-services `sevsnp` refuses Evidence from AWS.** The AWS host table carries only the VLEK;
   `validateCertChain` requires the ARK and ASK in the Evidence, and certificate fetching is disabled. Not fixed:
   completing the chain from the RRP's trust store works (table above); whether the scheme should take the ASK/ASVK
   and ARK from provisioned trust anchors or endorsements is a design question for Veraison.
3. **go-gen-ref reads SIGNER_INFO as a number, not a bit field.** `ReportToComid` (used by `ExtractClaims`) compares
   the whole word with 0 and 1, so a VLEK-signed report (0x4) fails with "invalid signer info: 4", a VCEK report with
   MASK_CHIP_KEY (0x2) fails, and one with AUTHOR_KEY_EN (0x1) is classed as signed by a CSP key. Fix (local, on
   v1.2.3, which the fork uses, and on main): take SIGNING_KEY from `abi.ParseSignerInfo`. Its test fails on 4 of 7
   cases before the fix and passes after.
4. **go-sev-guest v0.15.0 refuses every VLEK-signed report (AWS) when the caller passes no trusted roots**, as the
   Veraison `sevsnp` scheme does. Its public-key pinning fix (726e291c52) takes the roots from built-in defaults,
   which hold the VCEK chains only. Veraison pins the version before it, so a deployed Veraison is not affected until
   it moves. Passing both chains as `TrustedRoots` works on both versions (tested on ten AWS and ten GCP reports).
   Details: `evidence/20260929-go-sev-guest-v0.15.0-vlek/README.md`.

## Measurements

- A configfs-tsm report through the plug-in takes 7.4-12.9 ms on both clouds (SEV-SNP); a TDX quote takes
  38.8-42.0 ms on GCP, with no stall in 40 consecutive quotes.
- Google Cloud throttles guest requests: in 100 consecutive reports, reports 0, 10, 20, ... waited 10.2 s, about one
  report per second sustained; the same pattern as our ioctl measurements of 22 and 26 September. AWS showed no
  stall in 110 consecutive reports. A Handle lifetime shorter than about a minute can expire on GCP while the
  Attester waits (the Linux driver retries for up to 60 s).
- Evidence is 5 989 octets on GCP (report and three DER certificates) and 2 593 on AWS (report and VLEK).
- The AWS VLEK is the one we captured in us-east-2 on 11 September (SubjectPublicKeyInfo SHA-256 5330c95b...).
- Integrity validation in Veraison takes 0.8-3.5 ms per Evidence on a laptop. TDX quote verification takes about
  0.6 s for the first quote (Intel PCS collateral and revocation lists fetched) and 1-3 ms afterwards from a cache.

## What this does not show

- No EST or CAAPI transport: Evidence went from the guest to the RRP by file copy. The next step is Sudarshan's EST
  server with this verifier in place of the mock one.
- Apart from the two service runs of `bb8b97a` (above), no deployed Veraison service, no CoRIM provisioning, no EAR
  signing: the scheme is called in-process. TDX
  Evidence is verified outside Veraison.
- Reference values are trust on first use. Independent ones (for GCP, Google's signed launch endorsements of the
  firmware) are not used yet.
- Azure (the paravisor owns REPORT_DATA; the vTPM path) is not run.

## Questions for the SIG

1. Evidence format on hardware: the TSM report (what Veraison takes) or the plug-in interface's COSE_Sign1 EAT.
2. Where the RRP identifier the Attester binds comes from (configuration, or the Initiate response).
3. CAAPI `EnrollCredentialRequest` and `RetrieveCredentialRequest` carry no freshness element: absent-timestamp on
   SEV-SNP and TDX needs one (EST carries it in `handle`).
4. Sudarshan's branch binds `server_id`; the revised draft (fa4cd72) binds the RRP identifier.
5. Findings 1-4: report upstream (Veraison, go-gen-ref, go-sev-guest) from the SIG, or from us with the SIG's
   agreement.
