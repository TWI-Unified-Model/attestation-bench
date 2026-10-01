# Mutual TLS between the components, and each Target's verifiers (1 October 2026)

These are tacra-est N23 and N24, from its `10-REQUIREMENTS-MATRIX`:

- **N23:** "No mutual authentication on the channels between EST server, Verifier, CA and Vault" (DR-D04, EST-034;
  X9 asks CA-RA communications to be mutually authenticated, KMIP TLS mutual authentication).
- **N24:** "The Evidence selects the Verifier, and the Relying Party fetches the Verifier's key at start instead of
  holding it" (DR-B08; CVE-2026-92792, OpenNHP, where the verifier was "selected from attacker-supplied evidence").

## The code (our branches, not pushed)

| repository | commit | what |
|---|---|---|
| twi-tacra | `b65281c` | the change itself, in detail below |
| twi-tacra | `63169f2` | the Target is part of the Vault's credential group (tacra-est N2) |
| globalsign-est | `1b31748` | the TACRA backend asks only the verifiers the RRP takes, the one for the Evidence's provider; it presents its client certificate to the RRPs and the verifiers, over TLS 1.3; with the TACRA backend the EST server's own listener takes TLS 1.3 only |
| veraison-services | `675fe11` (branch `tacra/verification-client-ca`) | the verification API takes an optional `client-ca`: callers must present a certificate of it, over TLS 1.3, and each session's caller is logged |

What `b65281c` changes:

- **`rrp/internal/mtls`.** TLS 1.3 on server and client, and the check of the caller's identity.
- **The gateways.** They take the protocol from the EST server's certificate alone, and their public material (the
  Vault's origin keys) from any caller of the bench's root. Each verifier is named in their configuration, with its
  EAR key as a provisioned file. Each Target names the verifiers it takes; a result signed by another verifier is
  refused. In Background Check the TSM provider picks only among the Target's verifiers, and there is no default
  verifier for other Evidence.
- **The TDX verifier.** It takes the EST server and the gateways, logs who asked, and prints its EAR key for the
  operator to provision.
- **`bench.sh config`.** It issues the client certificates and sets mutual TLS on Veraison, Vault and step-ca (below).

## The bench

`bench.sh config` issues a client certificate under the bench's TLS root for each of the EST server, the two gateways
and the operator, named `<name>.bench.tacra.example`. It also:

- writes Veraison's and the TDX verifier's EAR keys as files;
- sets Veraison's `verification.client-ca`;
- makes HashiCorp Vault's listener require a client certificate, at TLS 1.3;
- puts step-ca on TLS 1.3.

step-ca checks client certificates against its own roots, so the CA gateway presents none there; its provisioner's
one-time token, signed with the key it holds, authenticates it for each certificate.

The bench gives two more Targets for N24: `db-snp-only` takes Veraison alone, `db-tdx-only` the TDX verifier alone.

## Evidence (`e2e/evidence/`)

`e2e/scripts/bench-mtls-check.py` calls every channel as each kind of caller: the right component, another component
of the same root, a certificate of a foreign CA with the right name, no certificate, and TLS 1.2.

| run | what | result |
|---|---|---|
| `20261001T210405Z-bench-mtls-check` | the first check | 39 of 40: step-ca refused the CA gateway's certificate (README); the gateway no longer presents one there |
| `20261001T210451Z-bench-mtls-check` | after the fix | 40 of 40 |
| `20261001T210804Z-bench-mtls-check` | at `b65281c`, the bench of the hardware runs | 40 of 40 |
| `20261001T211540Z-bench-mtls-check` | the bench in Background Check | 40 of 40 |
| `20261001T211232Z-gcp-tdx-e2e-passport` | the SIG's workload, GCP TDX, passport | 10 of 10; the gateways and the TDX verifier logged every call from `est-server.bench.tacra.example` |
| `20261001T211841Z-gcp-sev-snp-e2e-background-check` | the SIG's workload, GCP SEV-SNP, Background Check | 10 of 10; Veraison logged 5 sessions for `ca-gateway.bench.tacra.example` and 5 for `vault-gateway.bench.tacra.example` |

The reference implementation's client ran on the same bench, with the N24 cases (tacra-est `5503853`,
`interop/RESULTS-twi-est-server.md`):

- **On SEV-SNP in passport.** `db-tdx-only` refused a genuine result that Veraison signed: "none of the verifiers this
  RRP takes for the Target (tdx) signed it".
- **On TDX in Background Check.** `db-snp-only` refused before asking any verifier: "none of the verifiers this RRP
  takes for the Target (veraison) appraises Evidence of provider "tdx_guest"".
- **Each Target of its own platform issued.**

At 21:21:37Z the project had no instance and no disk.

## What this does not show

- **Veraison and step-ca keep no list of callers.** Veraison takes any certificate of the bench's root, and step-ca
  authenticates the CA gateway by its token.
- **The keys in software.** The infrastructure identities' keys are files; an HSM is N5.
- **The CAI's channel to the CAS Client in the guest** is plain gRPC: the CAS is untrusted by design (tacra-est G30).
