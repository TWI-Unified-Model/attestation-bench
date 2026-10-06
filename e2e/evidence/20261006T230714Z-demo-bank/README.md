# Demo Bank: TACRA end to end on real hardware

Demo Bank is fictional: its names, accounts and amounts are made up. Every server of the bank ran in the cloud; the operator's machine only built the programs, created the VMs and collected this evidence.

## Machines

```
demobank-trust-2610062307 internal 10.128.0.15 external 34.45.129.41
demobank-core-2610062307 internal 10.128.15.230 external 136.116.85.16
```

Trust zone: Veraison (sevsnp scheme, reference values for the approved launches), step-ca, Vault, the Credential Authority and Secret Vault gateways, the TDX verifier, the EST server (the only port workloads reach). Core: the ledger (PostgreSQL; the payment service's role logs in only by a client certificate from the bank's workload CA) and the fraud-scoring service (pre-shared API key). The payment service holds no credential of its own.

Configuration: written by the bench's own program, `scripts/trustzone.py`, from `packs/demo-bank` and the approved launches, as on the bench: mutual TLS between the components (tacra-est N23), the verifiers' EAR keys given to the gateways as files (N24), the API key released in the signed container (MLKEM768-P256, signed by the Vault). RATS model: passport.

Attempts that failed before the bank came up (`up/failed-attempts.txt`):

```
The bank came up on the third provisioning of the same two VMs. The first two stopped as follows (lines copied from
the operator's console; the files in up/ hold the third, successful attempt).

1. make bank-up, 23:07Z: the trust VM's install stopped in Veraison's deployment:
     ERROR: jose executable must be installed to use this command.
     !! install failed (1)
   Cause: the rewritten trust.sh no longer installed jose, which Veraison's signing-key step needs.

2. e2e/bank/demo-bank.sh provision, 23:15Z (jose back, the signing keys made): the trust zone's start stopped at the
   CoRIM:
     !! CoRIM not accepted: {"status":"failed","expiry":"2026-10-06T23:15:29Z","failure-reason":"submit endorsement
     returned error: submit endorsements failed: SQL logic error: no such table: tokens (1)"}
   Cause: quick-init-all makes certificates, signing keys, clients, stores in that order; attempt 1 had stopped at the
   keys, so the stores were never made (/root/veraison-deployment/stores/store.sql was 0 bytes).

3. Fix (commit 09e1e5d): the install runs Veraison's steps one by one, each skipped when done. Then
   e2e/bank/demo-bank.sh provision, 23:18Z: Veraison took the CoRIM, all ten services ran (up/trust-start.txt).
```

## Code

```
attestation-bench 171bd8720082
globalsign-est/src upstream 04ffa468b167 + 6 patch(es), tree b08ded935cf2: tested tree
veraison-services/src upstream f997c5275c30 + 4 patch(es), tree a742260c3d8b: tested tree
go-gen-ref/src upstream aa3740de6b00 + 1 patch(es), tree 5bedeba1cc44: tested tree
step-ca v0.30.2, step v0.30.2 (built from their release modules); vault 2.1.1, go 1.27.0 (official releases, SHA-256 checked on the VM against scripts/versions.env)
```

## Runs

| run | expected | verdict | what happened |
|---|---|---|---|
| `20261006T231902Z-gcp-snp` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 1 committed |
| `20261006T232202Z-gcp-tdx` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 2 committed |
| `20261006T232439Z-aws-snp` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 3 committed |
| `20261006T232651Z-ordinary` | refusal | PASS: no attestation, no credential; the ledger and the fraud service refused it | attestation plug-in and CAI: no attestation provider; ledger: login without a certificate: FATAL: connection requires a valid client certificate; fraud service: call without the key: HTTP 403: not admitted |
| `20261006T232917Z-unapproved` | refusal | PASS: genuine hardware evidence, unapproved launch: no credential issued | TACRA: ledger certificate: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

### 20261006T231902Z-gcp-snp

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-2
name: demobank-pay-062319-gcp-snp
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 10.0 | sev-snp |
| TACRA: ledger certificate | yes | 83.8 | [payments.workload.demobank.example] serial 57d41d013b4d02d05273fb963a78c500 until 2026-10-07T00:20:39Z |
| TACRA: fraud-service API key | yes | 58.4 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 6.4 | approve FRD-97D7DEBA7B1F |
| ledger: transfer | yes | 23.4 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-06T23:20:39Z",
 "balance_after": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "balance_before": {
  "ACC-1001": "5000.00",
  "ACC-2002": "1000.00"
 },
 "certificate": {
  "not_after": "2026-10-07T00:20:39Z",
  "serial_hex": "57d41d013b4d02d05273fb963a78c500"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-97D7DEBA7B1F",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "116744190854756448967753099058183980288",
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
ca-gateway: 2026/10/06 23:20:39 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint="payments.workload.demobank.example" caller=[est-server.trust.demobank.example]
vault-gateway: 2026/10/06 23:20:39 released: target=https://fraud-api.demobank.example kind=present-nonce group=c8a15fefec31d8ce container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.demobank.example]
postgresql: 2026-10-06 23:20:39.896 UTC [5920] payments@bank 10.128.15.231(40836) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-06 23:20:39.896 UTC [5920] payments@bank 10.128.15.231(40836) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/06 23:20:39 score FRD-97D7DEBA7B1F: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-062319-gcp-snp is gone

### 20261006T232202Z-gcp-tdx

```
confidentialInstanceConfig:
  confidentialInstanceType: TDX
cpuPlatform: Intel Sapphire Rapids
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/c3-standard-4
name: demobank-pay-062322-gcp-tdx
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 41.3 | tdx |
| TACRA: ledger certificate | yes | 776.1 | [payments.workload.demobank.example] serial 8494abcd921c4dea1aef0267aaf47a84 until 2026-10-07T00:23:16Z |
| TACRA: fraud-service API key | yes | 57.6 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 4.9 | approve FRD-82DE6D4B1C7D |
| ledger: transfer | yes | 20.0 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-06T23:23:17Z",
 "balance_after": {
  "ACC-1001": "4749.00",
  "ACC-2002": "1251.00"
 },
 "balance_before": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "certificate": {
  "not_after": "2026-10-07T00:23:16Z",
  "serial_hex": "8494abcd921c4dea1aef0267aaf47a84"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-82DE6D4B1C7D",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "176230039957706618869720403540329134724",
  "client_cn": "payments.workload.demobank.example",
  "tls": "TLSv1.3"
 },
 "to": "ACC-2002",
 "transfer_id": 2
}
```

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
ca-gateway: 2026/10/06 23:23:16 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint="payments.workload.demobank.example" caller=[est-server.trust.demobank.example]
vault-gateway: 2026/10/06 23:23:17 released: target=https://fraud-api.demobank.example kind=present-nonce group=48f360b593d60cd2 container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.demobank.example]
tdx-verifier: 2026/10/06 23:23:16 appraisal: affirming, MRTD f21e6b48743fe14c…
tdx-verifier: 2026/10/06 23:23:17 appraisal: affirming, MRTD f21e6b48743fe14c…
postgresql: 2026-10-06 23:23:17.049 UTC [6056] payments@bank 10.128.0.16(44944) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-06 23:23:17.049 UTC [6056] payments@bank 10.128.0.16(44944) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/06 23:23:17 score FRD-82DE6D4B1C7D: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-062322-gcp-tdx is gone

### 20261006T232439Z-aws-snp

```
us-east-2 us-east-2a i-028ad4910b990a652 ami-09519cc56eb20524a c6a.large
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 9.7 | sev-snp |
| TACRA: ledger certificate | yes | 216.9 | [payments.workload.demobank.example] serial 1b8f9ae129f6b50bfed1d56c9a595de5 until 2026-10-07T00:25:45Z |
| TACRA: fraud-service API key | yes | 216.0 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 96.9 | approve FRD-732E4100501F |
| ledger: transfer | yes | 531.6 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-06T23:25:46Z",
 "balance_after": {
  "ACC-1001": "4623.50",
  "ACC-2002": "1376.50"
 },
 "balance_before": {
  "ACC-1001": "4749.00",
  "ACC-2002": "1251.00"
 },
 "certificate": {
  "not_after": "2026-10-07T00:25:45Z",
  "serial_hex": "1b8f9ae129f6b50bfed1d56c9a595de5"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-732E4100501F",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "36634795667365873109913520656206093797",
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
ca-gateway: 2026/10/06 23:25:45 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint="payments.workload.demobank.example" caller=[est-server.trust.demobank.example]
vault-gateway: 2026/10/06 23:25:45 released: target=https://fraud-api.demobank.example kind=present-nonce group=5dfb3935e5ffdbcb container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.demobank.example]
postgresql: 2026-10-06 23:25:46.178 UTC [6192] payments@bank 3.145.78.231(40886) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-06 23:25:46.178 UTC [6192] payments@bank 3.145.78.231(40886) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/06 23:25:46 score FRD-732E4100501F: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: instance i-028ad4910b990a652: terminated; security group sg-0c38a34d265a2e594 deleted; key pair demobank-pay-232439-aws-snp deleted; GCP firewall rule demobank-aws-232439 deleted

### 20261006T232651Z-ordinary

```
cpuPlatform: Intel Broadwell
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/e2-small
name: demobank-pay-062326-ordinary
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | no | 0.3 | sev-snp — no attestation from this machine: platform: configfs-tsm report: could not create report entry in configfs: mkdir /sys/kernel/config/tsm/report/entry1904187534: no such device or address |
| ledger: login without a certificate | yes | 12.5 | refused as expected: failed to connect to `user=payments database=bank`: 10.128.15.230:5432 (core.demobank.internal): server error: FATAL: connection requires a valid client certificate (SQLSTATE 28000) |
| fraud service: call without the key | yes | 5.7 | refused as expected: HTTP 403: not admitted |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
postgresql: 2026-10-06 23:27:55.829 UTC [6320] payments@bank 10.128.0.17(51548) FATAL:  connection requires a valid client certificate
fraud-api: 2026/10/06 23:27:55 score refused from 10.128.0.17:33584: wrong or missing API key
```

Deleted after the run: demobank-pay-062326-ordinary is gone

### 20261006T232917Z-unapproved

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-4
name: demobank-pay-062329-unapproved
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 10.8 | sev-snp |
| TACRA: ledger certificate | no | 47.7 | — cai: EnrollCredential: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP contraindicated {'hardware': 32, 'runtime-opaque': 96}
ca-gateway: 2026/10/06 23:30:54 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce caller=[est-server.trust.demobank.example]: attestation: ear: not affirming: SEVSNP is "contraindicated"
```

Deleted after the run: demobank-pay-062329-unapproved is gone

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
id    |          holder           | currency | balance 
----------+---------------------------+----------+---------
 ACC-1001 | Demo customer (fictional) | USD      | 4623.50
 ACC-2002 | Demo merchant (fictional) | USD      | 1376.50
(2 rows)

 id | from_account | to_account | amount |    fraud_ref     |   tee   |             client_cn              |           client_cert_serial            |          client_cert_issuer           | db_user  |          created_at           
----+--------------+------------+--------+------------------+---------+------------------------------------+-----------------------------------------+---------------------------------------+----------+-------------------------------
  1 | ACC-1001     | ACC-2002   | 125.50 | FRD-97D7DEBA7B1F | sev-snp | payments.workload.demobank.example | 116744190854756448967753099058183980288 | Demo Bank workload CA Intermediate CA | payments | 2026-10-06 23:20:39.897834+00
  2 | ACC-1001     | ACC-2002   | 125.50 | FRD-82DE6D4B1C7D | tdx     | payments.workload.demobank.example | 176230039957706618869720403540329134724 | Demo Bank workload CA Intermediate CA | payments | 2026-10-06 23:23:17.051193+00
  3 | ACC-1001     | ACC-2002   | 125.50 | FRD-732E4100501F | sev-snp | payments.workload.demobank.example | 36634795667365873109913520656206093797  | Demo Bank workload CA Intermediate CA | payments | 2026-10-06 23:25:46.209646+00
(3 rows)

--- ledger log: connections
2026-10-06 23:15:17.407 UTC [5015] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-06 23:15:17.408 UTC [5015] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-06 23:15:17.408 UTC [5015] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-06 23:18:24.189 UTC [5708] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-06 23:18:24.700 UTC [5711] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-06 23:18:24.701 UTC [5711] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-06 23:18:24.701 UTC [5711] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-06 23:18:25.221 UTC [5714] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-06 23:18:25.222 UTC [5714] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-06 23:18:25.222 UTC [5714] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-06 23:18:25.737 UTC [5717] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-06 23:18:25.738 UTC [5717] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-06 23:18:25.738 UTC [5717] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-06 23:18:25.831 UTC [5723] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-06 23:18:25.832 UTC [5723] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-06 23:18:25.832 UTC [5723] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-06 23:18:25.911 UTC [5727] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-06 23:18:25.913 UTC [5727] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-06 23:18:25.913 UTC [5727] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-10-06 23:18:26.050 UTC [5733] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-06 23:18:26.051 UTC [5733] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-06 23:18:26.051 UTC [5733] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-06 23:18:26.066 UTC [5737] [unknown]@[unknown] 127.0.0.1(46974) LOG:  connection received: host=127.0.0.1 port=46974
2026-10-06 23:18:26.146 UTC [5743] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-06 23:18:26.147 UTC [5743] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-06 23:18:26.148 UTC [5743] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-06 23:20:39.890 UTC [5920] [unknown]@[unknown] 10.128.15.231(40836) LOG:  connection received: host=10.128.15.231 port=40836
2026-10-06 23:20:39.896 UTC [5920] payments@bank 10.128.15.231(40836) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-06 23:20:39.896 UTC [5920] payments@bank 10.128.15.231(40836) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-06 23:23:17.042 UTC [6056] [unknown]@[unknown] 10.128.0.16(44944) LOG:  connection received: host=10.128.0.16 port=44944
2026-10-06 23:23:17.049 UTC [6056] payments@bank 10.128.0.16(44944) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-06 23:23:17.049 UTC [6056] payments@bank 10.128.0.16(44944) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-06 23:25:46.082 UTC [6192] [unknown]@[unknown] 3.145.78.231(40886) LOG:  connection received: host=3.145.78.231 port=40886
2026-10-06 23:25:46.178 UTC [6192] payments@bank 3.145.78.231(40886) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-06 23:25:46.178 UTC [6192] payments@bank 3.145.78.231(40886) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-06 23:27:55.823 UTC [6320] [unknown]@[unknown] 10.128.0.17(51548) LOG:  connection received: host=10.128.0.17 port=51548
2026-10-06 23:27:55.829 UTC [6320] payments@bank 10.128.0.17(51548) FATAL:  connection requires a valid client certificate
2026-10-06 23:32:20.633 UTC [6581] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-06 23:32:20.634 UTC [6581] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-06 23:32:20.634 UTC [6581] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
--- fraud service log
2026/10/06 23:15:17 fraud-api listening on :8444
2026/10/06 23:15:17 http: TLS handshake error from 127.0.0.1:46296: EOF
2026/10/06 23:18:26 http: TLS handshake error from 127.0.0.1:44054: EOF
2026/10/06 23:20:39 score FRD-97D7DEBA7B1F: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/10/06 23:23:17 score FRD-82DE6D4B1C7D: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/10/06 23:25:46 score FRD-732E4100501F: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/10/06 23:27:55 score refused from 10.128.0.17:33584: wrong or missing API key
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

