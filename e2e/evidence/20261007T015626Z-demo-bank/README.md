# Demo Bank: TACRA end to end on real hardware

Demo Bank is fictional: its names, accounts and amounts are made up. Every server of the bank ran in the cloud; the operator's machine only built the programs, created the VMs and collected this evidence.

The bank: `demo-bank`, from its pack `packs/demo-bank/pack.json` (SHA-256 `028ebe899230c18c…`).

## Machines

```
demobank-trust-2610070156 internal 10.128.0.38 external 107.178.208.241
demobank-core-2610070156 internal 10.128.0.39 external 34.45.129.41
```

Trust zone: Veraison (sevsnp scheme, reference values for the approved launches), step-ca, Vault, the Credential Authority and Secret Vault gateways, the TDX verifier, the EST server (the only port workloads reach). Core: the ledger (PostgreSQL; the payment service's role logs in only by a client certificate from the bank's workload CA) and the fraud-scoring service (pre-shared API key). The payment service holds no credential of its own.

Configuration: written by the bench's own program, `scripts/trustzone.py`, from `packs/demo-bank/pack.json` and the approved launches, as on the bench: mutual TLS between the components (tacra-est N23), the verifiers' EAR keys given to the gateways as files (N24), the API key released in the signed container (MLKEM768-P256, signed by the Vault). RATS model: background-check.

## Code

```
attestation-bench 297cf662bbfd
globalsign-est/src upstream 04ffa468b167 + 6 patch(es), tree b08ded935cf2: tested tree
veraison-services/src upstream f997c5275c30 + 4 patch(es), tree a742260c3d8b: tested tree
go-gen-ref/src upstream aa3740de6b00 + 1 patch(es), tree 5bedeba1cc44: tested tree
step-ca v0.30.2, step v0.30.2 (built from their release modules); vault 2.1.1, go 1.27.0 (official releases, SHA-256 checked on the VM against scripts/versions.env)
```

## Runs

| run | expected | verdict | what happened |
|---|---|---|---|
| `20261007T020346Z-gcp-snp` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 1 committed |
| `20261007T020706Z-gcp-tdx` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 2 committed |
| `20261007T020923Z-aws-snp` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 3 committed |
| `20261007T021130Z-ordinary` | refusal | PASS: no attestation, no credential; the ledger and the fraud service refused it | attestation plug-in and CAI: no attestation provider; ledger: login without a certificate: FATAL: connection requires a valid client certificate; fraud service: call without the key: HTTP 403: not admitted |
| `20261007T021337Z-unapproved` | refusal | PASS: genuine hardware evidence, unapproved launch: no credential issued | TACRA: ledger certificate: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

### 20261007T020346Z-gcp-snp

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-2
name: demobank-pay-070203-gcp-snp
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 10.7 | sev-snp |
| TACRA: ledger certificate | yes | 81.1 | [payments.workload.demobank.example] serial 2757cadafa04b134ebdabf8de0754cee until 2026-10-07T03:05:56Z |
| TACRA: fraud-service API key | yes | 68.9 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 7.8 | approve FRD-82E799D3D1A6 |
| ledger: transfer | yes | 28.2 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-07T02:05:56Z",
 "balance_after": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "balance_before": {
  "ACC-1001": "5000.00",
  "ACC-2002": "1000.00"
 },
 "certificate": {
  "not_after": "2026-10-07T03:05:56Z",
  "serial_hex": "2757cadafa04b134ebdabf8de0754cee"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-82E799D3D1A6",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "52295736058160539787689853486823197934",
  "client_cn": "payments.workload.demobank.example",
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
ca-gateway: 2026/10/07 02:05:56 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint="payments.workload.demobank.example" caller=[est-server.trust.demobank.example]
vault-gateway: 2026/10/07 02:05:56 released: target=https://fraud-api.demobank.example kind=present-nonce group=c8a15fefec31d8ce container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.demobank.example]
postgresql: 2026-10-07 02:05:56.945 UTC [4721] payments@bank 10.128.0.40(44446) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-07 02:05:56.945 UTC [4721] payments@bank 10.128.0.40(44446) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/07 02:05:56 score FRD-82E799D3D1A6: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-070203-gcp-snp is gone at 2026-10-07T02:06:58Z

### 20261007T020706Z-gcp-tdx

```
confidentialInstanceConfig:
  confidentialInstanceType: TDX
cpuPlatform: Intel Sapphire Rapids
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/c3-standard-4
name: demobank-pay-070207-gcp-tdx
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 41.7 | tdx |
| TACRA: ledger certificate | yes | 632.3 | [payments.workload.demobank.example] serial f5342bac32ed396e63806307cf44ab62 until 2026-10-07T03:08:12Z |
| TACRA: fraud-service API key | yes | 58.1 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 5.4 | approve FRD-80ECE906367F |
| ledger: transfer | yes | 19.7 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-07T02:08:12Z",
 "balance_after": {
  "ACC-1001": "4749.00",
  "ACC-2002": "1251.00"
 },
 "balance_before": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "certificate": {
  "not_after": "2026-10-07T03:08:12Z",
  "serial_hex": "f5342bac32ed396e63806307cf44ab62"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-80ECE906367F",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "325931744190566146494927743119608032098",
  "client_cn": "payments.workload.demobank.example",
  "tls": "TLSv1.3"
 },
 "to": "ACC-2002",
 "transfer_id": 2
}
```

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
ca-gateway: 2026/10/07 02:08:12 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint="payments.workload.demobank.example" caller=[est-server.trust.demobank.example]
vault-gateway: 2026/10/07 02:08:12 released: target=https://fraud-api.demobank.example kind=present-nonce group=48f360b593d60cd2 container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.demobank.example]
tdx-verifier: 2026/10/07 02:08:12 appraisal: affirming, MRTD f21e6b48743fe14c…
tdx-verifier: 2026/10/07 02:08:12 appraisal: affirming, MRTD f21e6b48743fe14c…
postgresql: 2026-10-07 02:08:12.545 UTC [4855] payments@bank 10.128.0.41(55134) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-07 02:08:12.546 UTC [4855] payments@bank 10.128.0.41(55134) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/07 02:08:12 score FRD-80ECE906367F: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-070207-gcp-tdx is gone at 2026-10-07T02:09:15Z

### 20261007T020923Z-aws-snp

```
us-east-2 us-east-2a i-066e83f33e1aef689 ami-09519cc56eb20524a c6a.large
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 9.5 | sev-snp |
| TACRA: ledger certificate | yes | 295.4 | [payments.workload.demobank.example] serial 989bd649df7187da802f2788c3642af5 until 2026-10-07T03:10:35Z |
| TACRA: fraud-service API key | yes | 267.7 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 70.2 | approve FRD-2056C4E5107C |
| ledger: transfer | yes | 346.7 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-07T02:10:36Z",
 "balance_after": {
  "ACC-1001": "4623.50",
  "ACC-2002": "1376.50"
 },
 "balance_before": {
  "ACC-1001": "4749.00",
  "ACC-2002": "1251.00"
 },
 "certificate": {
  "not_after": "2026-10-07T03:10:35Z",
  "serial_hex": "989bd649df7187da802f2788c3642af5"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-2056C4E5107C",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "202851807660843563320446712856386480885",
  "client_cn": "payments.workload.demobank.example",
  "tls": "TLSv1.3"
 },
 "to": "ACC-2002",
 "transfer_id": 3
}
```

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP affirming {'hardware': 2, 'runtime-opaque': 2}
veraison: SEVSNP affirming {'hardware': 2, 'runtime-opaque': 2}
ca-gateway: 2026/10/07 02:10:35 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint="payments.workload.demobank.example" caller=[est-server.trust.demobank.example]
vault-gateway: 2026/10/07 02:10:35 released: target=https://fraud-api.demobank.example kind=present-nonce group=5dfb3935e5ffdbcb container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.demobank.example]
postgresql: 2026-10-07 02:10:36.137 UTC [4988] payments@bank 18.118.207.136(38382) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-07 02:10:36.137 UTC [4988] payments@bank 18.118.207.136(38382) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/07 02:10:36 score FRD-2056C4E5107C: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: instance i-066e83f33e1aef689: terminated at 2026-10-07T02:11:13Z; security group sg-0de351d4dd7c3377a deleted; key pair demobank-pay-020923-aws-snp deleted; GCP firewall rule demobank-aws-020923 deleted

### 20261007T021130Z-ordinary

```
cpuPlatform: Intel Broadwell
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/e2-small
name: demobank-pay-070211-ordinary
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | no | 0.3 | sev-snp — no attestation from this machine: platform: configfs-tsm report: could not create report entry in configfs: mkdir /sys/kernel/config/tsm/report/entry1505880533: no such device or address |
| ledger: login without a certificate | yes | 11.3 | refused as expected: failed to connect to `user=payments database=bank`: 10.128.0.39:5432 (core.demobank.internal): server error: FATAL: connection requires a valid client certificate (SQLSTATE 28000) |
| fraud service: call without the key | yes | 4.5 | refused as expected: HTTP 403: not admitted |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
postgresql: 2026-10-07 02:12:29.305 UTC [5116] payments@bank 10.128.0.42(44258) FATAL:  connection requires a valid client certificate
fraud-api: 2026/10/07 02:12:29 score refused from 10.128.0.42:38332: wrong or missing API key
```

Deleted after the run: demobank-pay-070211-ordinary is gone at 2026-10-07T02:13:29Z

### 20261007T021337Z-unapproved

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-4
name: demobank-pay-070213-unapproved
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 9.7 | sev-snp |
| TACRA: ledger certificate | no | 38.6 | — cai: EnrollCredential: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP contraindicated {'hardware': 32, 'runtime-opaque': 96}
ca-gateway: 2026/10/07 02:15:24 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce caller=[est-server.trust.demobank.example]: attestation: ear: not affirming: SEVSNP is "contraindicated"
```

Deleted after the run: demobank-pay-070213-unapproved is gone at 2026-10-07T02:16:24Z

## Reference values: Google's signed firmware endorsements

Each approved GCP launch measurement was checked with `rrp/cmd/gce-endorsement` (google/gce-tcb-verifier) against Google's signed VMLaunchEndorsement, verified to the pinned root GCE-cc-tcb-root (SHA-256 e876bc69…f18c, fetched from https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt).

| technology | measurement | endorsed | firmware built | SVN | launch | note |
|---|---|---|---|---|---|---|
| sev-snp | `7a89cceaaba0bbdd…` | no |  |  |  | Google publishes no endorsement for this measurement; approved at start on an earlier run's observation (trust on first use) |
| sev-snp | `ccdc5cf01ba25526…` | yes | 2026-07-24T08:29:40Z | 2 | 2 vCPUs | approved at start |
| tdx | `c1ee9c16e3afc506…` | yes | 2026-05-21T23:52:45Z | 2 |  | approved at start |
| tdx | `f21e6b48743fe14c…` | yes | 2026-07-31T09:52:02Z | 2 |  | approved at start |
| tdx | `c1ee9c16e3afc506…` | yes | 2026-05-21T23:52:45Z | 2 |  | approved during the run |

Policy change applied on the trust zone:

```
configuration written to /opt/demobank/config (pack demo-bank, RATS model: background-check)
veraison-vts running
veraison-provisioning running
veraison-verification running
veraison-management running
step-ca running
vault running
tdx-verifier running
ca-gateway running
vault-gateway running
est-server running
*:18443 0.0.0.0:22 127.0.0.1:10443 127.0.0.1:50051 127.0.0.1:8200 127.0.0.1:8201 127.0.0.1:8443 127.0.0.1:8453 127.0.0.1:9000 127.0.0.1:9101 127.0.0.1:9102 127.0.0.1:9443 127.0.0.53%lo:53 127.0.0.54:53 [::]:22
```

## Ledger audit

```
id    |          holder           | currency | balance 
----------+---------------------------+----------+---------
 ACC-1001 | Demo customer (fictional) | USD      | 4623.50
 ACC-2002 | Demo merchant (fictional) | USD      | 1376.50
(2 rows)

 id | from_account | to_account | amount |    fraud_ref     |   tee   |             client_cn              |           client_cert_serial            |          client_cert_issuer           | db_user  |          created_at           
----+--------------+------------+--------+------------------+---------+------------------------------------+-----------------------------------------+---------------------------------------+----------+-------------------------------
  1 | ACC-1001     | ACC-2002   | 125.50 | FRD-82E799D3D1A6 | sev-snp | payments.workload.demobank.example | 52295736058160539787689853486823197934  | Demo Bank workload CA Intermediate CA | payments | 2026-10-07 02:05:56.949766+00
  2 | ACC-1001     | ACC-2002   | 125.50 | FRD-80ECE906367F | tdx     | payments.workload.demobank.example | 325931744190566146494927743119608032098 | Demo Bank workload CA Intermediate CA | payments | 2026-10-07 02:08:12.54784+00
  3 | ACC-1001     | ACC-2002   | 125.50 | FRD-2056C4E5107C | sev-snp | payments.workload.demobank.example | 202851807660843563320446712856386480885 | Demo Bank workload CA Intermediate CA | payments | 2026-10-07 02:10:36.158498+00
(3 rows)

--- ledger log: connections
2026-10-07 02:03:13.584 UTC [4504] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 02:03:14.105 UTC [4507] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 02:03:14.107 UTC [4507] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 02:03:14.107 UTC [4507] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 02:03:14.623 UTC [4510] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 02:03:14.625 UTC [4510] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 02:03:14.625 UTC [4510] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 02:03:14.719 UTC [4516] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 02:03:14.720 UTC [4516] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 02:03:14.720 UTC [4516] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 02:03:14.809 UTC [4520] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 02:03:14.810 UTC [4520] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 02:03:14.810 UTC [4520] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-10-07 02:03:14.903 UTC [4523] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 02:03:14.905 UTC [4523] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 02:03:14.905 UTC [4523] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-10-07 02:03:14.993 UTC [4524] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 02:03:14.995 UTC [4524] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 02:03:14.995 UTC [4524] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
2026-10-07 02:03:15.180 UTC [4530] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 02:03:15.181 UTC [4530] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 02:03:15.181 UTC [4530] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 02:03:15.198 UTC [4537] [unknown]@[unknown] 127.0.0.1(59406) LOG:  connection received: host=127.0.0.1 port=59406
2026-10-07 02:03:15.296 UTC [4543] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 02:03:15.298 UTC [4543] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 02:03:15.298 UTC [4543] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 02:05:56.939 UTC [4721] [unknown]@[unknown] 10.128.0.40(44446) LOG:  connection received: host=10.128.0.40 port=44446
2026-10-07 02:05:56.945 UTC [4721] payments@bank 10.128.0.40(44446) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-07 02:05:56.945 UTC [4721] payments@bank 10.128.0.40(44446) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-07 02:08:12.540 UTC [4855] [unknown]@[unknown] 10.128.0.41(55134) LOG:  connection received: host=10.128.0.41 port=55134
2026-10-07 02:08:12.545 UTC [4855] payments@bank 10.128.0.41(55134) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-07 02:08:12.546 UTC [4855] payments@bank 10.128.0.41(55134) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-07 02:10:36.074 UTC [4988] [unknown]@[unknown] 18.118.207.136(38382) LOG:  connection received: host=18.118.207.136 port=38382
2026-10-07 02:10:36.137 UTC [4988] payments@bank 18.118.207.136(38382) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-07 02:10:36.137 UTC [4988] payments@bank 18.118.207.136(38382) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-07 02:12:29.299 UTC [5116] [unknown]@[unknown] 10.128.0.42(44258) LOG:  connection received: host=10.128.0.42 port=44258
2026-10-07 02:12:29.305 UTC [5116] payments@bank 10.128.0.42(44258) FATAL:  connection requires a valid client certificate
2026-10-07 02:17:17.122 UTC [5379] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 02:17:17.123 UTC [5379] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 02:17:17.123 UTC [5379] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
--- fraud service log
2026/10/07 02:03:15 fraud-api listening on :8444
2026/10/07 02:03:15 http: TLS handshake error from 127.0.0.1:32836: EOF
2026/10/07 02:05:56 score FRD-82E799D3D1A6: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/10/07 02:08:12 score FRD-80ECE906367F: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/10/07 02:10:36 score FRD-2056C4E5107C: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/10/07 02:12:29 score refused from 10.128.0.42:38332: wrong or missing API key
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

