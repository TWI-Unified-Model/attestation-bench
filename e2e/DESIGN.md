# TACRA over EST end to end, with no stand-ins (design, 28 September 2026)

Private to the TWI SIG. Builds on the SIG's PoC (CAI, CAAPI, platform plug-in interface, the GlobalSign EST fork with
`attest-*` resources) and on the revised EST profile (draft-novak-lamps-tacra-est, fa4cd72). Nothing here is pushed.

## Goal

One path any developer can rerun with one command: the workload in a real confidential VM → CAI + hardware plug-in →
CAAPI → EST client → EST server → a deployed Veraison → a Credential Authority built on step-ca, or a Secret Vault built
on HashiCorp Vault → back to the workload → the workload authenticates to an ordinary mTLS service with what it got.
On GCP SEV-SNP, AWS SEV-SNP and GCP TDX; all five Freshness Kinds; Enrollment and Retrieval; and, for every input the
binding covers, a request with that input changed is refused by the RRP for that reason.

Done means: every combination passes end to end up to the mTLS service accepting the certificate; every changed-input
request is refused with the expected status and reason; everything is reproducible by one script; evidence is in git;
cloud machines are deleted and the deletion checked.

## Topology (first runs)

- Server side on the Mac (native builds, no Docker): Veraison (provisioning, verification, VTS), the EST server, the two
  RRP gateways with step-ca and Vault behind them, and the mTLS service.
- The confidential VM runs the workload, the CAI with the plug-in, and the CAAPI server that is the EST client. It
  reaches the EST server through an SSH reverse tunnel, over TLS end to end (the tunnel only carries TCP).
- Later: the same server side on one ordinary cloud VM, reachable by confidential VMs in GCP and AWS.

## Components and what each must do

| Component | Base | Work |
|---|---|---|
| Workload + CAI | SIG `cai/` | unchanged, except passing the freshness element and Evidence profile (below) |
| Plug-in | `platform/sevsnp.go`, `platform/tdx.go` | done; ran on the three platforms on 28.09 |
| CAAPI server = EST client | new `cmd/caapi-est` | implements the CAAPI service with the EST client's `attest-*` methods; completes `attest-initiate` locally for absent kinds when configured |
| CAAPI messages | `proto/caapi/v1` | add, as optional fields: `freshness_element` and `evidence_profile` on Enroll/Retrieve, `cek_pub` on Retrieve, `rrp_id` on the Initiate response (proposals for the SIG) |
| EST server | GlobalSign EST fork, the group's master (`6f80871`, 11 October 2026) | a TACRA backend for `AttestationCA`: per-Target policy (mode, Freshness Kind, RRP, algorithms, `expires_in`/`max_age`), Handles obtained from the RRP (never minted), second-leg correlation, Evidence to Veraison, Attestation Results and request to the RRP; `rrp_id` instead of `server_id`; 8-octet timestamp in `handle` for absent-timestamp |
| Verifier | veraison-services, branch `hw/tacra-verifier` (DER fix, SIGNER_INFO fix) | deployed natively; challenge-response sessions with nonce = binding value; EAR signed by Veraison; ARK trust anchors and reference values provisioned as CoRIM |
| TDX verifier | go-tdx-guest | Veraison has no TDX scheme: a small verifier with the same session interface that signs its results, until a Veraison TDX scheme exists |
| CA gateway (RRP) | new `rrp/ca`, step-ca behind it | mints and tracks Handles; verifies the EAR (Veraison key, affirming, nonce = binding value it recomputes with its own `rrp_id`); PoP; name policy per Target; asks step-ca to sign (JWK provisioner token held by the gateway); short validity |
| Vault gateway (RRP) | new `rrp/vault`, HashiCorp Vault behind it | same checks with CEKpub; `group_id` from the Attestation Results; reads the group's secret from Vault KV; seals it with HPKE `mode_auth` (X25519, HKDF-SHA256, AES-256-GCM) under the gateway's static key, `rrp_id` and `handle` in `info`, the draft's associated data |
| mTLS service (RUP) | new `rup/` | accepts only certificates from the step-ca root, logs who came in |
| Runner | extends `hwcheck/scripts` | one script per platform: machine up, tunnel, run, collect, machine down, checks |

## Why Passport mode first

The draft illustrates Passport mode and the SIG's PoC implements it. The EST server opens the Veraison session with the
binding value it computes from the request and the Target's `rrp_id` (a conduit convenience: a wrong value only makes
Veraison refuse), and the RRP accepts only an EAR whose nonce equals the value it recomputes itself.

Background Check (TACRA Goal 6; TWI CAM C) is a setting of each gateway, `rats_model: background-check`, and of the
EST backend's entry for that RRP: the EST server then forwards the Evidence and its media type in the second leg
instead of an EAR, and the gateway opens the session itself, with the binding value it recomputed as the nonce, at the
verifier configured for the Evidence's TSM provider (`rrp/internal/gateway/appraise.go`). It verifies the EAR as in
Passport. A gateway in one model refuses a second leg of the other (400). For the Attester nothing differs. Tested
with a fake verifier (`appraise_test.go`, the EST backend's `backend_test.go`); not yet run on the bench.

## Open points to settle with the SIG

1. CAAPI fields above (freshness element, Evidence profile, CEKpub, `rrp_id`).
2. Evidence format on hardware: the TSM report Veraison takes, beside the PoC's COSE_Sign1 EAT.
3. The bundle: the PoC's ECDH-P256 container has no origin authentication; the revised draft makes HPKE `mode_auth`
   mandatory to implement.
4. `server_id` → `rrp_id`, and whether the CAI holds it (the TODO for 29.09).
5. Upstream reports for the three verifier findings (hwcheck/RESULTS.md).

## Later, with the SIG's agreement

An issuance provenance record per credential, registered in a SCITT transparency service with the receipt attached;
revocation by measurement or TCB through that log; location claims from attestation (TWI requirements 7 and 15).
