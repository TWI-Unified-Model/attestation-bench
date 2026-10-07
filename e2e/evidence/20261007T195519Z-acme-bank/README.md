# acme-bank: TACRA end to end on real hardware

acme-bank is a fictional bank made with `make bank-new`: its own Targets, RRP identifiers and names, on the Demo Bank's machinery. Its names, accounts and amounts are made up. Every server of the bank ran in the cloud; the operator's machine only built the programs, created the VMs and collected this evidence.

The bank: `acme-bank`, from its pack `packs/acme-bank/pack.json` (SHA-256 `65090252a08379d4…`).

## Machines

```
demobank-trust-2610071955 internal 10.128.0.22 external 34.66.17.190
demobank-core-2610071955 internal 10.128.0.23 external 35.253.163.108
```

Trust zone: Veraison (sevsnp scheme, reference values for the approved launches), step-ca, Vault, the Credential Authority and Secret Vault gateways, the TDX verifier, the EST server (the only port workloads reach). Core: the ledger (PostgreSQL; the payment service's role logs in only by a client certificate from the bank's workload CA) and the fraud-scoring service (pre-shared API key). The payment service holds no credential of its own.

Configuration: written by the bench's own program, `scripts/trustzone.py`, from `packs/acme-bank/pack.json` and the approved launches, as on the bench: mutual TLS between the components (tacra-est N23), the verifiers' EAR keys given to the gateways as files (N24), the API key released in the signed container (MLKEM768-P256, signed by the Vault). RATS model: passport.

## Code

```
attestation-bench 6e7762471054
globalsign-est/src upstream 04ffa468b167 + 11 patch(es), tree 3628224cb698: tested tree
veraison-services/src upstream f997c5275c30 + 8 patch(es), tree e7a04b43faf9: tested tree
go-gen-ref/src upstream aa3740de6b00 + 3 patch(es), tree 5f74ee0c1309: tested tree
step-ca v0.30.2, step v0.30.2 (built from their release modules); vault 2.1.1, go 1.27.0 (official releases, SHA-256 checked on the VM against scripts/versions.env)
```

## Runs

| run | expected | verdict | what happened |
|---|---|---|---|
| `20261007T200406Z-gcp-tdx` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 1 committed |
| `20261007T200627Z-gcp-snp` | payment | PASS: genuine hardware evidence, refused by the bank's platform rule: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set in LAUNCH_MIT_VECTOR 0xb | TACRA: ledger certificate: 403 RRP ca: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025 |

### 20261007T200406Z-gcp-tdx

```
confidentialInstanceConfig:
  confidentialInstanceType: TDX
cpuPlatform: Intel Sapphire Rapids
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/c3-standard-4
name: demobank-pay-072004-gcp-tdx
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 44.2 | tdx |
| TACRA: ledger certificate | yes | 668.2 | [payments.workload.acme-bank.example] serial b07cf74c0ac1d29d96494cdc1fd70e7c until 2026-10-07T21:05:12Z |
| TACRA: fraud-service API key | yes | 62.8 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 5.6 | approve FRD-E84CB479D6F4 |
| ledger: transfer | yes | 17.1 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-07T20:05:12Z",
 "balance_after": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "balance_before": {
  "ACC-1001": "5000.00",
  "ACC-2002": "1000.00"
 },
 "certificate": {
  "not_after": "2026-10-07T21:05:12Z",
  "serial_hex": "b07cf74c0ac1d29d96494cdc1fd70e7c"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-E84CB479D6F4",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "234592987848445132689020763837732163196",
  "client_cn": "payments.workload.acme-bank.example",
  "tls": "TLSv1.3"
 },
 "to": "ACC-2002",
 "transfer_id": 1
}
```

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
ca-gateway: 2026/10/07 20:05:12 enrolled: target=https://ledger-db.acme-bank.example kind=present-nonce hint="payments.workload.acme-bank.example" caller=[est-server.trust.acme-bank.example]
vault-gateway: 2026/10/07 20:05:12 released: target=https://fraud-api.acme-bank.example kind=present-nonce group=f4638a8b4ddcb953 container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.acme-bank.example]
tdx-verifier: 2026/10/07 20:05:12 appraisal: affirming, MRTD f21e6b48743fe14c…
tdx-verifier: 2026/10/07 20:05:12 appraisal: affirming, MRTD f21e6b48743fe14c…
postgresql: 2026-10-07 20:05:12.630 UTC [4742] payments@bank 10.128.0.26(57604) LOG:  connection authenticated: identity="CN=payments.workload.acme-bank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-07 20:05:12.630 UTC [4742] payments@bank 10.128.0.26(57604) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/07 20:05:12 score FRD-E84CB479D6F4: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-072004-gcp-tdx is gone at 2026-10-07T20:06:17Z

### 20261007T200627Z-gcp-snp

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-2
name: demobank-pay-072006-gcp-snp
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 10.4 | sev-snp |
| TACRA: ledger certificate | no | 257.0 | — cai: EnrollCredential: 403 RRP ca: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set in LAUNCH_MIT_VECTOR 0xb |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP affirming {'hardware': 2, 'runtime-opaque': 2}
ca-gateway: 2026/10/07 20:08:08 enroll refused: target=https://ledger-db.acme-bank.example kind=present-nonce caller=[est-server.trust.acme-bank.example]: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set
```

Deleted after the run: demobank-pay-072006-gcp-snp is gone at 2026-10-07T20:09:15Z

## Reference values: Google's signed firmware endorsements

Each approved GCP launch measurement was checked with `rrp/cmd/gce-endorsement` (google/gce-tcb-verifier) against Google's signed VMLaunchEndorsement, verified to the pinned root GCE-cc-tcb-root (SHA-256 e876bc69…f18c, fetched from https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt).

| technology | measurement | endorsed | firmware built | SVN | launch | note |
|---|---|---|---|---|---|---|
| sev-snp | `7a89cceaaba0bbdd…` | no |  |  |  | Google publishes no endorsement for this measurement; approved at start as the measurement of its provider's published firmware, measured again from that firmware at start (refvals/initial-firmware.txt) |
| sev-snp | `ccdc5cf01ba25526…` | yes | 2026-07-24T08:29:40Z | 2 | 2 vCPUs | approved at start |
| tdx | `c1ee9c16e3afc506…` | yes | 2026-05-21T23:52:45Z | 2 |  | approved at start |
| tdx | `f21e6b48743fe14c…` | yes | 2026-07-31T09:52:02Z | 2 |  | approved at start |

## Ledger audit

```
id    |          holder           | currency | balance 
----------+---------------------------+----------+---------
 ACC-1001 | Demo customer (fictional) | USD      | 4874.50
 ACC-2002 | Demo merchant (fictional) | USD      | 1125.50
(2 rows)

 id | from_account | to_account | amount |    fraud_ref     | tee |              client_cn              |           client_cert_serial            |          client_cert_issuer           | db_user  |          created_at           
----+--------------+------------+--------+------------------+-----+-------------------------------------+-----------------------------------------+---------------------------------------+----------+-------------------------------
  1 | ACC-1001     | ACC-2002   | 125.50 | FRD-E84CB479D6F4 | tdx | payments.workload.acme-bank.example | 234592987848445132689020763837732163196 | Demo Bank workload CA Intermediate CA | payments | 2026-10-07 20:05:12.632272+00
(1 row)

--- ledger log: connections
2026-10-07 20:03:40.929 UTC [4528] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 20:03:41.437 UTC [4531] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 20:03:41.438 UTC [4531] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 20:03:41.438 UTC [4531] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 20:03:41.954 UTC [4534] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 20:03:41.955 UTC [4534] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 20:03:41.955 UTC [4534] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 20:03:42.468 UTC [4537] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 20:03:42.469 UTC [4537] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 20:03:42.469 UTC [4537] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 20:03:42.550 UTC [4543] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 20:03:42.551 UTC [4543] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 20:03:42.551 UTC [4543] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 20:03:42.622 UTC [4547] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 20:03:42.623 UTC [4547] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 20:03:42.623 UTC [4547] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-10-07 20:03:42.691 UTC [4550] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 20:03:42.692 UTC [4550] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 20:03:42.692 UTC [4550] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-10-07 20:03:42.756 UTC [4551] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 20:03:42.757 UTC [4551] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 20:03:42.757 UTC [4551] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
2026-10-07 20:03:42.904 UTC [4557] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 20:03:42.905 UTC [4557] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 20:03:42.905 UTC [4557] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 20:03:42.918 UTC [4564] [unknown]@[unknown] 127.0.0.1(38822) LOG:  connection received: host=127.0.0.1 port=38822
2026-10-07 20:03:42.987 UTC [4570] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 20:03:42.988 UTC [4570] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 20:03:42.988 UTC [4570] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 20:05:12.625 UTC [4742] [unknown]@[unknown] 10.128.0.26(57604) LOG:  connection received: host=10.128.0.26 port=57604
2026-10-07 20:05:12.630 UTC [4742] payments@bank 10.128.0.26(57604) LOG:  connection authenticated: identity="CN=payments.workload.acme-bank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-07 20:05:12.630 UTC [4742] payments@bank 10.128.0.26(57604) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-07 20:09:28.001 UTC [5001] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 20:09:28.003 UTC [5001] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 20:09:28.003 UTC [5001] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
--- fraud service log
2026/10/07 20:03:42 fraud-api listening on :8444
2026/10/07 20:03:42 http: TLS handshake error from 127.0.0.1:35932: EOF
2026/10/07 20:05:12 score FRD-E84CB479D6F4: ACC-1001 -> ACC-2002 12550 cents: approve (0)
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

- GCP reference values are Google-endorsed (above). AWS signs no endorsement of its launch: the approved AWS measurement is that of AWS's published EC2 SEV-SNP firmware, measured again at start when refvals/initial-firmware.txt says so (above); a rebuild of that firmware from AWS's source did not give the published binary (trust/README.md), so the value rests on AWS's binary, not on a build of the bench's own.
- Approving a newly endorsed firmware is an operator step (`demo-bank.sh approve`); the verifier does not yet consult the endorsements by itself.
- The TDX path uses our own verifier (go-tdx-guest against Intel PCS); Veraison in the SIG's fork has no TDX scheme.
- The trust zone runs in a SEV-SNP confidential VM, but in this demonstration it does not attest itself to anyone.
- Vault runs with a single unseal key on the trust-zone disk; a bank would use an HSM or cloud KMS auto-unseal.

