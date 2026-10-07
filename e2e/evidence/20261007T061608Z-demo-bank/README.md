# Demo Bank: TACRA end to end on real hardware

Demo Bank is fictional: its names, accounts and amounts are made up. Every server of the bank ran in the cloud; the operator's machine only built the programs, created the VMs and collected this evidence.

The bank: `demo-bank`, from its pack `packs/demo-bank/pack.json` (SHA-256 `028ebe899230c18c…`).

## Machines

```
demobank-trust-2610070616 internal 10.128.15.203 external 35.193.38.242
demobank-core-2610070616 internal 10.128.15.204 external 146.148.65.80
```

Trust zone: Veraison (sevsnp scheme, reference values for the approved launches), step-ca, Vault, the Credential Authority and Secret Vault gateways, the TDX verifier, the EST server (the only port workloads reach). Core: the ledger (PostgreSQL; the payment service's role logs in only by a client certificate from the bank's workload CA) and the fraud-scoring service (pre-shared API key). The payment service holds no credential of its own.

Configuration: written by the bench's own program, `scripts/trustzone.py`, from `packs/demo-bank/pack.json` and the approved launches, as on the bench: mutual TLS between the components (tacra-est N23), the verifiers' EAR keys given to the gateways as files (N24), the API key released in the signed container (MLKEM768-P256, signed by the Vault). RATS model: passport.

## Code

```
attestation-bench 43b4505b3f8e
globalsign-est/src upstream 04ffa468b167 + 6 patch(es), tree b08ded935cf2: tested tree
veraison-services/src upstream f997c5275c30 + 5 patch(es), tree f6b75d098768: tested tree
go-gen-ref/src upstream aa3740de6b00 + 1 patch(es), tree 5bedeba1cc44: tested tree
step-ca v0.30.2, step v0.30.2 (built from their release modules); vault 2.1.1, go 1.27.0 (official releases, SHA-256 checked on the VM against scripts/versions.env)
```

## Runs

| run | expected | verdict | what happened |
|---|---|---|---|
| `20261007T062318Z-gcp-snp` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 1 committed |
| `20261007T062619Z-gcp-tdx` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 2 committed |
| `20261007T062835Z-aws-snp` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 3 committed |
| `20261007T063043Z-ordinary` | refusal | PASS: no attestation, no credential; the ledger and the fraud service refused it | attestation plug-in and CAI: no attestation provider; ledger: login without a certificate: FATAL: connection requires a valid client certificate; fraud service: call without the key: HTTP 403: not admitted |
| `20261007T063307Z-unapproved` | refusal | PASS: genuine hardware evidence, unapproved launch: no credential issued | TACRA: ledger certificate: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

### 20261007T062318Z-gcp-snp

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-2
name: demobank-pay-070623-gcp-snp
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 8.8 | sev-snp |
| TACRA: ledger certificate | yes | 261.2 | [payments.workload.demobank.example] serial c569efd4f625329d35a8210ca37d2698 until 2026-10-07T07:25:10Z |
| TACRA: fraud-service API key | yes | 59.5 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 6.6 | approve FRD-FA95E1F7FBEE |
| ledger: transfer | yes | 20.7 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-07T06:25:10Z",
 "balance_after": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "balance_before": {
  "ACC-1001": "5000.00",
  "ACC-2002": "1000.00"
 },
 "certificate": {
  "not_after": "2026-10-07T07:25:10Z",
  "serial_hex": "c569efd4f625329d35a8210ca37d2698"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-FA95E1F7FBEE",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "262407970708218591326022554072855160472",
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
ca-gateway: 2026/10/07 06:25:10 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint="payments.workload.demobank.example" caller=[est-server.trust.demobank.example]
vault-gateway: 2026/10/07 06:25:10 released: target=https://fraud-api.demobank.example kind=present-nonce group=c8a15fefec31d8ce container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.demobank.example]
postgresql: 2026-10-07 06:25:10.537 UTC [4733] payments@bank 10.128.15.205(44548) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-07 06:25:10.537 UTC [4733] payments@bank 10.128.15.205(44548) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/07 06:25:10 score FRD-FA95E1F7FBEE: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-070623-gcp-snp is gone at 2026-10-07T06:26:10Z

### 20261007T062619Z-gcp-tdx

```
confidentialInstanceConfig:
  confidentialInstanceType: TDX
cpuPlatform: Intel Sapphire Rapids
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/c3-standard-4
name: demobank-pay-070626-gcp-tdx
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 42.1 | tdx |
| TACRA: ledger certificate | yes | 808.7 | [payments.workload.demobank.example] serial 4b88619791b601b36df961531ceeb6d8 until 2026-10-07T07:27:25Z |
| TACRA: fraud-service API key | yes | 57.1 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 4.6 | approve FRD-2C4CE0C415E2 |
| ledger: transfer | yes | 18.9 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-07T06:27:26Z",
 "balance_after": {
  "ACC-1001": "4749.00",
  "ACC-2002": "1251.00"
 },
 "balance_before": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "certificate": {
  "not_after": "2026-10-07T07:27:25Z",
  "serial_hex": "4b88619791b601b36df961531ceeb6d8"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-2C4CE0C415E2",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "100400231458908879846734818097786435288",
  "client_cn": "payments.workload.demobank.example",
  "tls": "TLSv1.3"
 },
 "to": "ACC-2002",
 "transfer_id": 2
}
```

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
ca-gateway: 2026/10/07 06:27:25 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint="payments.workload.demobank.example" caller=[est-server.trust.demobank.example]
vault-gateway: 2026/10/07 06:27:26 released: target=https://fraud-api.demobank.example kind=present-nonce group=48f360b593d60cd2 container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.demobank.example]
tdx-verifier: 2026/10/07 06:27:25 appraisal: affirming, MRTD f21e6b48743fe14c…
tdx-verifier: 2026/10/07 06:27:26 appraisal: affirming, MRTD f21e6b48743fe14c…
postgresql: 2026-10-07 06:27:26.060 UTC [4871] payments@bank 10.128.15.206(51302) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-07 06:27:26.061 UTC [4871] payments@bank 10.128.15.206(51302) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/07 06:27:26 score FRD-2C4CE0C415E2: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-070626-gcp-tdx is gone at 2026-10-07T06:28:27Z

### 20261007T062835Z-aws-snp

```
us-east-2 us-east-2a i-09c3a906320ceb9a9 ami-09519cc56eb20524a c6a.large
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 8.5 | sev-snp |
| TACRA: ledger certificate | yes | 451.2 | [payments.workload.demobank.example] serial 30355b8997ce32de5f33368e7540b2d9 until 2026-10-07T07:29:50Z |
| TACRA: fraud-service API key | yes | 301.4 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 92.5 | approve FRD-77D8431498D7 |
| ledger: transfer | yes | 519.9 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-07T06:29:51Z",
 "balance_after": {
  "ACC-1001": "4623.50",
  "ACC-2002": "1376.50"
 },
 "balance_before": {
  "ACC-1001": "4749.00",
  "ACC-2002": "1251.00"
 },
 "certificate": {
  "not_after": "2026-10-07T07:29:50Z",
  "serial_hex": "30355b8997ce32de5f33368e7540b2d9"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-77D8431498D7",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "64079992131692019942142618190401811161",
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
ca-gateway: 2026/10/07 06:29:50 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint="payments.workload.demobank.example" caller=[est-server.trust.demobank.example]
vault-gateway: 2026/10/07 06:29:50 released: target=https://fraud-api.demobank.example kind=present-nonce group=5dfb3935e5ffdbcb container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.demobank.example]
postgresql: 2026-10-07 06:29:51.158 UTC [5001] payments@bank 18.227.13.220(52692) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-07 06:29:51.158 UTC [5001] payments@bank 18.227.13.220(52692) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/07 06:29:51 score FRD-77D8431498D7: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: instance i-09c3a906320ceb9a9: terminated at 2026-10-07T06:30:28Z; security group sg-0ecf1c7334bec0d3f deleted; key pair demobank-pay-062835-aws-snp deleted; GCP firewall rule demobank-aws-062835 deleted

### 20261007T063043Z-ordinary

```
cpuPlatform: Intel Broadwell
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/e2-small
name: demobank-pay-070630-ordinary
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | no | 0.4 | sev-snp — no attestation from this machine: platform: configfs-tsm report: could not create report entry in configfs: mkdir /sys/kernel/config/tsm/report/entry2481701977: no such device or address |
| ledger: login without a certificate | yes | 11.8 | refused as expected: failed to connect to `user=payments database=bank`: 10.128.15.204:5432 (core.demobank.internal): server error: FATAL: connection requires a valid client certificate (SQLSTATE 28000) |
| fraud service: call without the key | yes | 6.1 | refused as expected: HTTP 403: not admitted |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
postgresql: 2026-10-07 06:31:57.379 UTC [5131] payments@bank 10.128.15.207(36638) FATAL:  connection requires a valid client certificate
fraud-api: 2026/10/07 06:31:57 score refused from 10.128.15.207:44346: wrong or missing API key
```

Deleted after the run: demobank-pay-070630-ordinary is gone at 2026-10-07T06:32:58Z

### 20261007T063307Z-unapproved

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-4
name: demobank-pay-070633-unapproved
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 10.5 | sev-snp |
| TACRA: ledger certificate | no | 40.1 | — cai: EnrollCredential: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP contraindicated {'hardware': 32, 'runtime-opaque': 96}
ca-gateway: 2026/10/07 06:34:42 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce caller=[est-server.trust.demobank.example]: attestation: ear: not affirming: SEVSNP is "contraindicated"
```

Deleted after the run: demobank-pay-070633-unapproved is gone at 2026-10-07T06:35:47Z

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
  1 | ACC-1001     | ACC-2002   | 125.50 | FRD-FA95E1F7FBEE | sev-snp | payments.workload.demobank.example | 262407970708218591326022554072855160472 | Demo Bank workload CA Intermediate CA | payments | 2026-10-07 06:25:10.539612+00
  2 | ACC-1001     | ACC-2002   | 125.50 | FRD-2C4CE0C415E2 | tdx     | payments.workload.demobank.example | 100400231458908879846734818097786435288 | Demo Bank workload CA Intermediate CA | payments | 2026-10-07 06:27:26.062742+00
  3 | ACC-1001     | ACC-2002   | 125.50 | FRD-77D8431498D7 | sev-snp | payments.workload.demobank.example | 64079992131692019942142618190401811161  | Demo Bank workload CA Intermediate CA | payments | 2026-10-07 06:29:51.189523+00
(3 rows)

--- ledger log: connections
2026-10-07 06:22:54.734 UTC [4505] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 06:22:55.251 UTC [4508] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 06:22:55.252 UTC [4508] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 06:22:55.252 UTC [4508] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 06:22:55.767 UTC [4511] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 06:22:55.768 UTC [4511] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 06:22:55.768 UTC [4511] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 06:22:55.863 UTC [4517] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 06:22:55.865 UTC [4517] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 06:22:55.865 UTC [4517] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 06:22:55.948 UTC [4521] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 06:22:55.949 UTC [4521] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 06:22:55.949 UTC [4521] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-10-07 06:22:56.029 UTC [4524] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 06:22:56.030 UTC [4524] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 06:22:56.030 UTC [4524] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-10-07 06:22:56.116 UTC [4525] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 06:22:56.117 UTC [4525] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 06:22:56.117 UTC [4525] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
2026-10-07 06:22:56.284 UTC [4531] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 06:22:56.285 UTC [4531] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 06:22:56.285 UTC [4531] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 06:22:56.302 UTC [4539] [unknown]@[unknown] 127.0.0.1(55546) LOG:  connection received: host=127.0.0.1 port=55546
2026-10-07 06:22:56.379 UTC [4545] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 06:22:56.380 UTC [4545] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 06:22:56.380 UTC [4545] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 06:25:10.532 UTC [4733] [unknown]@[unknown] 10.128.15.205(44548) LOG:  connection received: host=10.128.15.205 port=44548
2026-10-07 06:25:10.537 UTC [4733] payments@bank 10.128.15.205(44548) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-07 06:25:10.537 UTC [4733] payments@bank 10.128.15.205(44548) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-07 06:27:26.054 UTC [4871] [unknown]@[unknown] 10.128.15.206(51302) LOG:  connection received: host=10.128.15.206 port=51302
2026-10-07 06:27:26.060 UTC [4871] payments@bank 10.128.15.206(51302) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-07 06:27:26.061 UTC [4871] payments@bank 10.128.15.206(51302) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-07 06:29:51.064 UTC [5001] [unknown]@[unknown] 18.227.13.220(52692) LOG:  connection received: host=18.227.13.220 port=52692
2026-10-07 06:29:51.158 UTC [5001] payments@bank 18.227.13.220(52692) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-07 06:29:51.158 UTC [5001] payments@bank 18.227.13.220(52692) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-07 06:31:57.373 UTC [5131] [unknown]@[unknown] 10.128.15.207(36638) LOG:  connection received: host=10.128.15.207 port=36638
2026-10-07 06:31:57.379 UTC [5131] payments@bank 10.128.15.207(36638) FATAL:  connection requires a valid client certificate
2026-10-07 06:35:58.221 UTC [5389] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 06:35:58.222 UTC [5389] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 06:35:58.222 UTC [5389] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
--- fraud service log
2026/10/07 06:22:56 fraud-api listening on :8444
2026/10/07 06:22:56 http: TLS handshake error from 127.0.0.1:35032: EOF
2026/10/07 06:25:10 score FRD-FA95E1F7FBEE: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/10/07 06:27:26 score FRD-2C4CE0C415E2: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/10/07 06:29:51 score FRD-77D8431498D7: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/10/07 06:31:57 score refused from 10.128.15.207:44346: wrong or missing API key
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

