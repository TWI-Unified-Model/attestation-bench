# The signed container and Background Check, end to end on GCP SEV-SNP and GCP TDX (1 October 2026)

This is item A2 of our `15-BEFORE-COMMUNITY.md`: the TWI end-to-end run on the container of tacra-est decision 4. It
also covers the TWI half of A5, Background Check (TACRA Goal 6).

## The container

The container is `hpke-base-signed`, defined in `bundle/signed.go`, byte for byte with the reference
implementation: HPKE base mode with MLKEM768-P256, HKDF-SHA256 and AES-256-GCM, and the Secret Vault's ECDSA P-256
signature over the sealed bundle. It replaces `hpke-auth` because HPKE-bis removes the Auth modes, and the
post-quantum KEMs have no AuthEncap.

Each run below goes the whole way: the SIG's CAI with the hardware plug-in, in a confidential VM; the CAS Client
(`caapi-est`) in the same VM; and the bench on this machine (`e2e/scripts/bench.sh`), reached through an SSH reverse
tunnel.

## The code

| repository | commit | what |
|---|---|---|
| twi-tacra | `8896599` | CAAPI `ENCRYPTION_ALGORITHM_MLKEM768_P256`; the SEV-SNP and TDX plug-ins generate an MLKEM768-P256 CEK, whose CEKpub is the 1249-octet encapsulation key itself (the binding subject and what the Vault receives); the CAI opens the signed container under the Vault signature key it holds for the RRP its Evidence bound, and takes only items with key-block attributes, not exportable, not shared, valid at most 3600 s; the Vault gateway seals the signed container (`sign_key`, published beside the KEM keys), and under the bank profile only that; `caapi-est` prefers MLKEM768-P256 when attest-initiate lists the signed suite; `bench.sh` gives the ledger Targets the signed suite alone, and `RATS_MODEL=background-check` |
| twi-tacra | `e8528c4` | `veraison-local.sh`: a start from cold returned 1 and stopped `bench.sh start` after Veraison |
| twi-tacra | `f370844` | the bench's group carries key-block attributes (purpose authenticate, algorithm opaque-bearer, 3600 s) |
| twi-tacra | `bfe694c` | the Vault gateway logs each release's container and KEM, and refuses a CEK form the Target does not accept; a gateway in Background Check logs the verifier it asks |
| twi-tacra | `a5f7ec5` | Background Check in the gateways (earlier today) |
| globalsign-est | `8069fa6` | Background Check in the TACRA backend: the Evidence goes to the RRP |
| veraison-services | `cd2afab5270a` | as on 28 September |

## The bench

Every listener is on 127.0.0.1 of this machine:

- Veraison: the four services;
- step-ca, a local build;
- HashiCorp Vault v2.1.1;
- the TDX verifier;
- the Credential Authority gateway and the Secret Vault gateway;
- the EST server;
- the RATS-unaware mTLS service.

**Targets.** Ten, five per mode:

- five Enrollment Targets (`db-*`), each issuing an x509 certificate through step-ca;
- five Retrieval Targets (`ledger-*`), each releasing an API key from Vault in the signed container.

Within each mode there is one Target per Freshness Kind: present-nonce, present-epoch, absent-epoch, absent-timestamp
and absent-none.

**What makes a Target pass.** The workload must get its credential, then present it to the mTLS service: the
certificate as its TLS client certificate, the API key in a header. The service must answer 200.

**The RATS model.** It is a setting of the whole bench (`bench.sh config`):

- passport: the EST server asks the verifiers;
- background-check: the CA and Vault gateways ask them.

## Runs (`e2e/evidence/`)

**Platforms.** GCP SEV-SNP is an n2d-standard-2 (AMD Milan) in us-central1-c; GCP TDX is a c3-standard-4 in
us-central1-a. Both run kernel 7.0.0-1011-gcp.

**Deletion.** The script deleted each VM (`vm-deleted.txt`). At 19:16:50Z the project had no instance and no disk.

**The table.** The median times are per acquisition, from Initiate to the credential.

| run | platform | RATS model | code | Targets admitted | median x509 / API key |
|---|---|---|---|---|---|
| `20261001T184850Z-gcp-sev-snp-e2e-passport` | SEV-SNP | passport | `e8528c4` | 5 of 10: every ledger Target refused by the CAI (below) | 577 ms / - |
| `20261001T185249Z-gcp-sev-snp-e2e-passport` | SEV-SNP | passport | `f370844` | 10 of 10 | 488 / 510 ms |
| `20261001T185551Z-gcp-tdx-e2e-passport` | TDX | passport | `f370844` | 10 of 10 | 555 / 535 ms |
| `20261001T185854Z-gcp-sev-snp-e2e-background-check` | SEV-SNP | background-check | `f370844` | 10 of 10 | 578 / 536 ms |
| `20261001T190203Z-gcp-tdx-e2e-background-check` | TDX | background-check | `f370844` | 10 of 10 | 557 / 534 ms |
| `20261001T190541Z-gcp-sev-snp-e2e-background-check` | SEV-SNP | background-check | `bfe694c` | 10 of 10 | 533 / 523 ms |
| `20261001T190838Z-gcp-tdx-e2e-background-check` | TDX | background-check | `bfe694c` | 10 of 10 | 528 / 558 ms |
| `20261001T191106Z-gcp-sev-snp-e2e-passport` | SEV-SNP | passport | `bfe694c` | 10 of 10 | 585 / 570 ms |
| `20261001T191408Z-gcp-tdx-e2e-passport` | TDX | passport | `bfe694c` | 10 of 10 | 557 / 561 ms |

### The first run: the CAI's item policy at work

The Vault gateway released the five bundles in the signed container (its log: five `released:` lines). The CAI
then did three things:

1. it checked each bundle's signature under the Vault key it holds;
2. it checked the associated data;
3. it decrypted the bundle with its CEK.

Then it refused every bundle: `bundle: an item has no key-block attributes (purpose, algorithm, exportable)`. The
bench's group had none.

`bundle.CheckItems`, the source of that message, runs only on the signed path, after the bundle has been opened. The
bench's group has carried the attributes since `f370844`.

### What the logs of the last four runs show (code `bfe694c`)

- **The container.** Every Retrieval was released as `container=hpke-base-signed kem=MLKEM768-P256`: 5 of 5 in each
  run (`bench-logs/vault-gateway.log`).
- **Background Check.** In both runs each gateway, the CA's and the Vault's, asked a verifier itself, 5 times each
  (`background-check: this RRP asks …`):
  - SEV-SNP Evidence went to Veraison (`https://localhost:8443`);
  - TDX Evidence went to the TDX verifier (`https://localhost:8453`), routed by the TSM provider `tdx_guest`.
- **Passport.** Neither gateway asked any verifier: the EST server did.

### The earlier four runs (code `f370844`)

The gateways did not yet log the container or whom they asked. Two things still tell the models apart in those
runs. A gateway answers 400 to a second leg of the other model (`rrp/internal/gateway/appraise_test.go`). The bench's
configuration was switched between the two pairs (`rats-model.txt` in each run).

## What these runs do not show

- **A deployment.** The bench is one machine, every listener on loopback. The demo bank of 28 September is the
  deployed shape: `20260928T212732Z-demo-bank`, on the hpke-auth container and the code of then.
- **The bank profile on the gateways.** The gateways ran without `profile: bank`. The ledger Targets nonetheless
  accept the signed suite alone, so the gateway refuses any other CEK form at them (`bfe694c`).
- **The CAI as the SIG's sidecar.** The e2e attester links the CAI directly.
- **Simulated Evidence.** The simulated plug-in keeps ECDH and RSA CEKs: its EAT `cnf` claim has no ML-KEM form.
- **The TDX event log.** The bench's TDX verifier checks MRTD. It can also compare raw RTMR values, but the bench
  sets none. It does not appraise the event log, as the reference implementation does (C1).
