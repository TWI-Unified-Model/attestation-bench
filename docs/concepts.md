# Concepts

What TACRA is for, who takes part, and the few ideas the bench tests. Definitions follow the architecture draft,
[draft-novak-rats-tacra](https://datatracker.ietf.org/doc/draft-novak-rats-tacra/) (section numbers below are those of
its version -01), and its EST profile,
[draft-novak-lamps-tacra-est](https://github.com/TheBankster/lamps-tacra-est). Where the bench chooses something the
drafts leave open, this page says so.

## The problem

Servers authenticate their clients with credentials they already understand: a client certificate, an API key. Their
policies stay the same for years. Remote attestation can prove what a workload runs, but a server that is not built
for it cannot use that proof.

TACRA puts attestation where credentials are **issued**, not where they are used (draft section 1). The workload, in a
confidential VM, proves itself to the party that issues or releases its credential. That party gives it an ordinary
credential, which the server accepts as it always has. The server needs no change at all.

## Who takes part

| Party | In the drafts | In the bench |
|---|---|---|
| **Attester** | the workload whose platform produces Evidence | `e2e-attester` (the e2e runs), `payments` (the Demo Bank), `hwrun` (the attack suite), each with the CAI and a platform plug-in |
| **Target** | "the RATS-unaware Relying Party for which the Attester seeks credentials" (section 2) | a URL naming it, e.g. `https://db-nonce.tacra.example` |
| **RATS-Unaware Relying Party (RUP)** | the server that authenticates the workload with the credential | `rup`, an ordinary mTLS service (Demo Bank: a PostgreSQL ledger and a fraud-scoring API) |
| **RATS Relying Party (RRP)** | a Credential Authority or a Secret Vault that "takes on the role of RATS Relying Party" (section 1) | the CA gateway in front of step-ca, the Vault gateway in front of HashiCorp Vault |
| **Verifier** | appraises Evidence and signs Attestation Results | Veraison (SEV-SNP), the bench's TDX verifier, the stand-in TEE's verifier |
| **Credential Acquisition System (CAS)** | the existing mechanism the workload uses to get credentials: a CAS Client and a CAS Server (section 2) | EST: `caapi-est` (the CAS Client) and the GlobalSign EST server with TACRA's `attest-*` resources |

The CAS sits between the Attester and the RRP and is **not trusted** (section 7.2): the bench treats it, the network
and the cloud as possibly hostile. Every security property must hold when they misbehave, which is what
`make attacks` checks.

## Two modes

- **Enrollment**: the workload gets a new proof-of-possession credential. Its CAI makes a key pair (the CSK) inside the
  TEE and sends a CSR; the Credential Authority issues a certificate for it. In the bench: an X.509 certificate from
  step-ca.
- **Retrieval**: the workload gets an existing secret. Its CAI makes an encryption key pair (the CEK) inside the TEE
  and sends CEKpub; the Secret Vault releases the secret sealed to it. In the bench: an API key from HashiCorp Vault,
  in a signed container (below).

## Evidence and the binding

The workload's hardware signs a report of what was launched (the launch measurement) and 64 octets the guest chooses.
TACRA fills those 64 octets with a **binding value**: SHA-512 over the request's four parts, each preceded by its
length (`platform/binding.go`, after the EST profile's "Binding Input"):

```
binding_input = len32(freshness element) || freshness element
             || len32(Target)            || Target
             || len32(RRP identifier)    || RRP identifier
             || len32(subject)           || subject          (the DER CSR, or the DER SubjectPublicKeyInfo of CEKpub)
binding value = SHA-512(binding_input)
```

The value goes into `REPORT_DATA` on AMD SEV-SNP, `REPORTDATA` in an Intel TDX quote, and `report_data` in the
software stand-in's report. The RRP computes the value itself from what it received and accepts the Evidence only if
it matches. Changing any of the four parts on the way, a different Target, another RRP, another key, an old freshness
value, makes the values differ, and the RRP refuses.

**The RRP identifier** is the bench's name for the RRP's identity in the binding (`rrp_id` in the configuration).
Whether it belongs in the binding is the open question of
[TACRA issue #20](https://github.com/TheBankster/rats-tacra/issues/20); `make redirect` measures what it prevents.

## Freshness Kinds

How the RRP knows the Evidence is recent. Five kinds (draft section 2.1):

| Kind | Freshness element | What it rests on |
|---|---|---|
| `present-nonce` | a single-use nonce the RRP returned for this exchange | the RRP minted it and accepts it once |
| `present-epoch` | the current epoch marker the RRP returned | the RRP's epoch; the workload retries if it moved |
| `absent-epoch` | an epoch identifier the workload already holds | an epoch the RRP also knows |
| `absent-timestamp` | 8 octets of time from the workload's trusted clock | the RRP's window around its own clock |
| `absent-none` | nothing | no freshness claim at all |

"Present" kinds get their freshness element from the RRP in a first round trip (Initiate-Credential-Acquisition);
"absent" kinds need no round trip. Each Target in a pack names its kind.

## Passport and Background Check

Two ways to get Evidence appraised (RFC 9334). The draft requires both, "indistinguishably from the PoV of the
Attester" (Goal 6, section 3).

- **Passport**: the EST server sends the Evidence to the verifier and forwards the signed result to the RRP.
- **Background Check**: the EST server forwards the Evidence; the RRP sends it to the verifier itself.

In both, the RRP accepts only a result it can check itself: the verifier's signature, with the verifier's key given to
the RRP as a file and never fetched from the verifier at run time (requirement N24 of tacra-est's requirements
matrix); the verdict
`affirming`; and the session's nonce, which must equal the binding value the RRP computed. The bench runs either model
with one setting: `RATS_MODEL=passport` or `background-check` ([getting-started.md](getting-started.md), step 11).

## Attestation Results

The verifier's signed result is an **EAR** (EAT Attestation Result): a JWT signed with ES256 that names the verdict
per platform ("submodule": `SEVSNP`, `TDX`, or `SIM` for the stand-in), the trustworthiness claims behind it, and the
nonce. The RRP's checks are in `rrp/internal/ear`.

## The signed container

A released secret travels to the workload sealed to its CEK and signed by the Vault: HPKE in base mode with an
ML-KEM-768 + P-256 hybrid key encapsulation (`MLKEM768-P256+HKDF-SHA256+AES-256-GCM`) and an ECDSA P-256 signature over
it, which the workload checks against the Vault's key it holds for that RRP identifier (`bundle/`). Only the TEE that
generated the CEK can open it, and only the Vault could have made it.

## The software stand-in TEE

So that everything can run on a laptop, the bench has a stand-in for the hardware: `platform.SimTEE` signs its
reports with a P-256 key from a file (`~/.attestation-bench/secrets/sim-tee-ak.jwk`), and `sim-verifier` appraises
them like the real verifiers. It gives **no isolation and no security**: anyone with the file can produce its
reports. The RRPs accept its results only because the bench's configuration says `allow_simulated_tee`; without that
setting, which no real deployment has, every gateway refuses submodule `SIM`.

## Glossary

| Term | Meaning |
|---|---|
| CAI | Credential Acquisition Interface: the library the workload calls to get a credential (draft section 6) |
| CAAPI | Credential Acquisition API: the calls between the CAI and the CAS Client (draft section 5) |
| CEK, CSK | the keys made inside the TEE: the Credential Encryption Key (Retrieval) and the Credential Signing Key (Enrollment) |
| CoRIM | the reference values and trust anchors given to Veraison: here AMD's ARK and the approved SEV-SNP launches (`trust/`) |
| EAR | the verifier's signed result (above) |
| Freshness Handle | the freshness element an RRP returns for a present kind |
| Launch measurement | the hash of the launched firmware and initial state, signed by the hardware: `MEASUREMENT` (SEV-SNP), `MRTD` (TDX) |
| Pack | a bank's Targets, RRPs and policy as data (`packs/`) |
| RRP identifier | the RRP's identity in the binding (above) |
| VCEK, VLEK | the AMD keys that sign SEV-SNP reports: per chip (VCEK, Google Cloud) or per cloud provider (VLEK, AWS) |
