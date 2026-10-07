# acme-bank: TACRA end to end on real hardware

acme-bank is a fictional bank made with `make bank-new`: its own Targets, RRP identifiers and names, on the Demo Bank's machinery. Its names, accounts and amounts are made up. Every server of the bank ran in the cloud; the operator's machine only built the programs, created the VMs and collected this evidence.

The bank: `acme-bank`, from its pack `packs/acme-bank/pack.json` (SHA-256 `65090252a08379d4…`).

## Machines

```
demobank-trust-2610070219 internal 10.128.0.44 external 35.193.17.116
demobank-core-2610070219 internal 10.128.0.45 external 136.116.85.16
```

Trust zone: Veraison (sevsnp scheme, reference values for the approved launches), step-ca, Vault, the Credential Authority and Secret Vault gateways, the TDX verifier, the EST server (the only port workloads reach). Core: the ledger (PostgreSQL; the payment service's role logs in only by a client certificate from the bank's workload CA) and the fraud-scoring service (pre-shared API key). The payment service holds no credential of its own.

Configuration: written by the bench's own program, `scripts/trustzone.py`, from `packs/acme-bank/pack.json` and the approved launches, as on the bench: mutual TLS between the components (tacra-est N23), the verifiers' EAR keys given to the gateways as files (N24), the API key released in the signed container (MLKEM768-P256, signed by the Vault). RATS model: passport.

## Code

```
attestation-bench 52ba142c944c-dirty
globalsign-est/src upstream 04ffa468b167 + 6 patch(es), tree b08ded935cf2: tested tree
veraison-services/src upstream f997c5275c30 + 4 patch(es), tree a742260c3d8b: tested tree
go-gen-ref/src upstream aa3740de6b00 + 1 patch(es), tree 5bedeba1cc44: tested tree
step-ca v0.30.2, step v0.30.2 (built from their release modules); vault 2.1.1, go 1.27.0 (official releases, SHA-256 checked on the VM against scripts/versions.env)
```

## Runs

| run | expected | verdict | what happened |
|---|---|---|---|
| `20261007T022715Z-gcp-snp` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 1 committed |

### 20261007T022715Z-gcp-snp

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-2
name: demobank-pay-070227-gcp-snp
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 9.7 | sev-snp |
| TACRA: ledger certificate | yes | 74.5 | [payments.workload.acme-bank.example] serial 0900e18a39fd98e64007e97fc4ba0f81 until 2026-10-07T03:28:58Z |
| TACRA: fraud-service API key | yes | 54.2 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 6.3 | approve FRD-2A92B3C3AB86 |
| ledger: transfer | yes | 20.1 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-07T02:28:58Z",
 "balance_after": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "balance_before": {
  "ACC-1001": "5000.00",
  "ACC-2002": "1000.00"
 },
 "certificate": {
  "not_after": "2026-10-07T03:28:58Z",
  "serial_hex": "0900e18a39fd98e64007e97fc4ba0f81"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-2A92B3C3AB86",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "11967626455658717289707855899145146241",
  "client_cn": "payments.workload.acme-bank.example",
  "tls": "TLSv1.3"
 },
 "to": "ACC-2002",
 "transfer_id": 1
}
```

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP affirming {'hardware': 2, 'runtime-opaque': 2}
veraison: SEVSNP affirming {'hardware': 2, 'runtime-opaque': 2}
ca-gateway: 2026/10/07 02:28:58 enrolled: target=https://ledger-db.acme-bank.example kind=present-nonce hint="payments.workload.acme-bank.example" caller=[est-server.trust.acme-bank.example]
vault-gateway: 2026/10/07 02:28:58 released: target=https://fraud-api.acme-bank.example kind=present-nonce group=674bfe75d47bde58 container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.acme-bank.example]
postgresql: 2026-10-07 02:28:58.581 UTC [4720] payments@bank 10.128.0.47(53122) LOG:  connection authenticated: identity="CN=payments.workload.acme-bank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-07 02:28:58.581 UTC [4720] payments@bank 10.128.0.47(53122) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/07 02:28:58 score FRD-2A92B3C3AB86: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-070227-gcp-snp is gone at 2026-10-07T02:29:57Z

## Reference values: Google's signed firmware endorsements

Each approved GCP launch measurement was checked with `rrp/cmd/gce-endorsement` (google/gce-tcb-verifier) against Google's signed VMLaunchEndorsement, verified to the pinned root GCE-cc-tcb-root (SHA-256 e876bc69…f18c, fetched from https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt).

| technology | measurement | endorsed | firmware built | SVN | launch | note |
|---|---|---|---|---|---|---|
| sev-snp | `7a89cceaaba0bbdd…` | no |  |  |  | Google publishes no endorsement for this measurement; approved at start on an earlier run's observation (trust on first use) |
| sev-snp | `ccdc5cf01ba25526…` | yes | 2026-07-24T08:29:40Z | 2 | 2 vCPUs | approved at start |
| tdx | `c1ee9c16e3afc506…` | yes | 2026-05-21T23:52:45Z | 2 |  | approved at start |
| tdx | `f21e6b48743fe14c…` | yes | 2026-07-31T09:52:02Z | 2 |  | approved at start |

## Ledger audit

```
(not taken)
```

## Teardown

```
GCP instances labelled purpose=demo-bank: 0
GCP instances in the project, any purpose: 0
GCP firewall rules demobank-*: 0
AWS us-east-2 instances tagged purpose=demo-bank, not terminated: 0
AWS us-east-2 key pairs demobank-*: 0
AWS us-east-2 security groups demobank-*: 0
```

## Notes

- Provisioning, not the protocol: the fraud service's API key was handed from the core VM to the trust zone by piping it through the operator's console (`gcloud compute ssh ... | gcloud compute ssh ...`), on each provisioning, never written to the console's disk; the file on the trust zone was deleted after loading into Vault. Every payment then got the key only through TACRA.
- step-ca logs the one-time token of each signing request; `demo-bank.sh` redacts the tokens in `trust-logs/step-ca.log` (single-use and expired) before the per-run `sha256sums.txt` is computed.
- `TLS handshake error from 127.0.0.1` lines in the fraud service's log are the start script's port checks.

## Limits of this demonstration

- GCP reference values are Google-endorsed (above); the AWS launch measurement is still the value observed in an earlier run (trust on first use): Google does not endorse AWS firmware, and AWS's own firmware measurements were not computed here.
- Approving a newly endorsed firmware is an operator step (`demo-bank.sh approve`); the verifier does not yet consult the endorsements by itself.
- The TDX path uses our own verifier (go-tdx-guest against Intel PCS); Veraison in the SIG's fork has no TDX scheme.
- The trust zone runs in a SEV-SNP confidential VM, but in this demonstration it does not attest itself to anyone.
- Vault runs with a single unseal key on the trust-zone disk; a bank would use an HSM or cloud KMS auto-unseal.

