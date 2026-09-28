# Demo Bank: TACRA end to end on real hardware

Demo Bank is fictional: its names, accounts and amounts are made up. Every server of the bank ran in the cloud; the operator's machine only built the programs, created the VMs and collected this evidence.

## Machines

```
demobank-trust-2609282127 internal 10.128.0.24 external 34.41.130.86
demobank-core-2609282127 internal 10.128.0.25 external 34.60.85.73
```

Trust zone: Veraison (sevsnp scheme, reference values for the approved launches), step-ca, Vault, the Credential Authority and Secret Vault gateways, the TDX verifier, the EST server (the only port workloads reach). Core: the ledger (PostgreSQL; the payment service's role logs in only by a client certificate from the bank's workload CA) and the fraud-scoring service (pre-shared API key). The payment service holds no credential of its own.

## Code

```
twi-tacra 6ef5810099c5
globalsign-est b2934d169a73
veraison-services cd2afab5270a
go-gen-ref 3c8603164fbd
step-ca v0.30.2, step v0.30.2, vault 2.1.1 (official release, SHA-256 checked on the VM)
during the run (the payment runs used these; see the commits for the changes):
  twi-tacra a3f7d12  deployment fixes (gcc on the trust zone, CoRIM media type, core install/pg_isready), before the first payment
  twi-tacra 261e9bc  tdx-verifier logs the unmatched MRTD (binary sha256 1de0520207eb1cb4f2a3e0af559fa865610eeb71c0f7ed5e970a154a3a291863,
                     deployed at 21:52Z, before the second TDX run); gce-endorsement; approve step (policy change at 21:56Z)
```

## Runs

| run | expected | verdict | what happened |
|---|---|---|---|
| `20260928T214115Z-gcp-snp` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 1 committed |
| `20260928T214504Z-gcp-tdx` | payment | FAIL: no payment | TACRA: ledger certificate: 403 RRP ca: attestation: ear: not affirming: TDX is "contraindicated" (the verifier did not log the MRTD yet) |
| `20260928T215300Z-gcp-tdx` | payment | FAIL: no payment | TACRA: ledger certificate: 403 RRP ca: attestation: ear: not affirming: TDX is "contraindicated" (MRTD f21e6b48743fe14c… not approved yet) |
| `20260928T215716Z-gcp-tdx` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 2 committed |
| `20260928T215940Z-aws-snp` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 3 committed |
| `20260928T220153Z-ordinary` | refusal | PASS: no attestation, no credential; the ledger and the fraud service refused it | attestation plug-in and CAI: no attestation provider; ledger: login without a certificate: FATAL: connection requires a valid client certificate; fraud service: call without the key: HTTP 403: not admitted |
| `20260928T220432Z-unapproved` | refusal | PASS: genuine hardware evidence, unapproved launch: no credential issued | TACRA: ledger certificate: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

The two TDX runs that did not pay met a TDX firmware whose MRTD the bank had not approved: Google runs more than one build of its TDX firmware. The TDX verifier refused it (contraindicated), and so did the CA. The MRTD was then checked against Google's signed endorsement and approved (below), and the third TDX run paid.

### 20260928T214115Z-gcp-snp

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-2
name: demobank-pay-282141-gcp-snp
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 10.2 | sev-snp |
| TACRA: ledger certificate | yes | 73.9 | [payments.workload.demobank.example] serial 4b9ca6eb3bc53a1fceb3a401dd3c69f8 until 2026-09-28T22:43:05Z |
| TACRA: fraud-service API key | yes | 55.3 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 7.4 | approve FRD-DA9DF0F28CC6 |
| ledger: transfer | yes | 27.0 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-09-28T21:43:05Z",
 "balance_after": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "balance_before": {
  "ACC-1001": "5000.00",
  "ACC-2002": "1000.00"
 },
 "certificate": {
  "not_after": "2026-09-28T22:43:05Z",
  "serial_hex": "4b9ca6eb3bc53a1fceb3a401dd3c69f8"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-DA9DF0F28CC6",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "/O=Demo Bank workload CA/CN=Demo Bank workload CA Intermediate ",
  "client_cert_serial": "100505483510910569057168939122081688056",
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
ca-gateway: 2026/09/28 21:43:05 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint=payments.workload.demobank.example
vault-gateway: 2026/09/28 21:43:05 released: target=https://fraud-api.demobank.example kind=present-nonce group=71ba7c4d67a608e2
postgresql: 2026-09-28 21:43:05.495 UTC [7975] payments@bank 10.128.15.232(32996) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-09-28 21:43:05.495 UTC [7975] payments@bank 10.128.15.232(32996) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/09/28 21:43:05 score FRD-DA9DF0F28CC6: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-282141-gcp-snp is gone

### 20260928T214504Z-gcp-tdx

```
confidentialInstanceConfig:
  confidentialInstanceType: TDX
cpuPlatform: Intel Sapphire Rapids
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/c3-standard-4
name: demobank-pay-282145-gcp-tdx
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 49.3 | tdx |
| TACRA: ledger certificate | no | 548.9 | — cai: EnrollCredential: 403 RRP ca: attestation: ear: not affirming: TDX is "contraindicated" |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
ca-gateway: 2026/09/28 21:46:22 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce: attestation: ear: not affirming: TDX is "contraindicated"
tdx-verifier: 2026/09/28 21:46:22 appraisal: contraindicated: MRTD matches no reference value
```

Deleted after the run: demobank-pay-282145-gcp-tdx is gone

### 20260928T215300Z-gcp-tdx

```
confidentialInstanceConfig:
  confidentialInstanceType: TDX
cpuPlatform: Intel Sapphire Rapids
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/c3-standard-4
name: demobank-pay-282153-gcp-tdx
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 42.7 | tdx |
| TACRA: ledger certificate | no | 515.3 | — cai: EnrollCredential: 403 RRP ca: attestation: ear: not affirming: TDX is "contraindicated" |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
ca-gateway: 2026/09/28 21:54:08 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce: attestation: ear: not affirming: TDX is "contraindicated"
tdx-verifier: 2026/09/28 21:54:08 appraisal: contraindicated: MRTD f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3 matches no reference value
```

Deleted after the run: demobank-pay-282153-gcp-tdx is gone

### 20260928T215716Z-gcp-tdx

```
confidentialInstanceConfig:
  confidentialInstanceType: TDX
cpuPlatform: Intel Sapphire Rapids
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/c3-standard-4
name: demobank-pay-282157-gcp-tdx
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 43.3 | tdx |
| TACRA: ledger certificate | yes | 496.7 | [payments.workload.demobank.example] serial 41101f363ec559f5549b56d5058cccf1 until 2026-09-28T22:58:21Z |
| TACRA: fraud-service API key | yes | 59.6 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 5.8 | approve FRD-BB7AA5BB3333 |
| ledger: transfer | yes | 26.8 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-09-28T21:58:21Z",
 "balance_after": {
  "ACC-1001": "4749.00",
  "ACC-2002": "1251.00"
 },
 "balance_before": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "certificate": {
  "not_after": "2026-09-28T22:58:21Z",
  "serial_hex": "41101f363ec559f5549b56d5058cccf1"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-BB7AA5BB3333",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "86483529528201231764414630934768045297",
  "client_cn": "payments.workload.demobank.example",
  "tls": "TLSv1.3"
 },
 "to": "ACC-2002",
 "transfer_id": 2
}
```

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
ca-gateway: 2026/09/28 21:58:21 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint=payments.workload.demobank.example
vault-gateway: 2026/09/28 21:58:21 released: target=https://fraud-api.demobank.example kind=present-nonce group=e0cf239aeac8bd15
tdx-verifier: 2026/09/28 21:58:21 appraisal: affirming, MRTD f21e6b48743fe14c…
tdx-verifier: 2026/09/28 21:58:21 appraisal: affirming, MRTD f21e6b48743fe14c…
postgresql: 2026-09-28 21:58:21.240 UTC [8480] payments@bank 10.128.0.28(54598) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-09-28 21:58:21.241 UTC [8480] payments@bank 10.128.0.28(54598) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/09/28 21:58:21 score FRD-BB7AA5BB3333: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-282157-gcp-tdx is gone

### 20260928T215940Z-aws-snp

```
us-east-2 us-east-2a i-05f715504c0a75ae4 ami-0fa99aa8f97f9e30b c6a.large
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 10.3 | sev-snp |
| TACRA: ledger certificate | yes | 313.1 | [payments.workload.demobank.example] serial 8ec4e65b26dc307d316788795dcfd1e0 until 2026-09-28T23:00:52Z |
| TACRA: fraud-service API key | yes | 296.8 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 100.1 | approve FRD-71233F5C2BAB |
| ledger: transfer | yes | 585.3 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-09-28T22:00:52Z",
 "balance_after": {
  "ACC-1001": "4623.50",
  "ACC-2002": "1376.50"
 },
 "balance_before": {
  "ACC-1001": "4749.00",
  "ACC-2002": "1251.00"
 },
 "certificate": {
  "not_after": "2026-09-28T23:00:52Z",
  "serial_hex": "8ec4e65b26dc307d316788795dcfd1e0"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-71233F5C2BAB",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "189772737761729131886305290792578568672",
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
ca-gateway: 2026/09/28 22:00:52 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint=payments.workload.demobank.example
vault-gateway: 2026/09/28 22:00:52 released: target=https://fraud-api.demobank.example kind=present-nonce group=a69d41968a880513
postgresql: 2026-09-28 22:00:52.593 UTC [8617] payments@bank 18.216.111.184(49872) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-09-28 22:00:52.593 UTC [8617] payments@bank 18.216.111.184(49872) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/09/28 22:00:52 score FRD-71233F5C2BAB: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: instance i-05f715504c0a75ae4: terminated; security group sg-0047241c36bf733ff deleted; key pair demobank-pay-215940-aws-snp deleted; GCP firewall rule demobank-aws-215940 deleted

### 20260928T220153Z-ordinary

```
cpuPlatform: Intel Broadwell
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/e2-small
name: demobank-pay-282201-ordinary
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | no | 0.5 | sev-snp — no attestation from this machine: platform: configfs-tsm report: could not create report entry in configfs: mkdir /sys/kernel/config/tsm/report/entry3724538164: no such device or address |
| ledger: login without a certificate | yes | 12.3 | refused as expected: failed to connect to `user=payments database=bank`: 10.128.0.25:5432 (core.demobank.internal): server error: FATAL: connection requires a valid client certificate (SQLSTATE 28000) |
| fraud service: call without the key | yes | 6.8 | refused as expected: HTTP 403: not admitted |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
postgresql: 2026-09-28 22:03:10.663 UTC [8747] payments@bank 10.128.0.29(60534) FATAL:  connection requires a valid client certificate
fraud-api: 2026/09/28 22:03:10 score refused from 10.128.0.29:33220: wrong or missing API key
```

Deleted after the run: demobank-pay-282201-ordinary is gone

### 20260928T220432Z-unapproved

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-4
name: demobank-pay-282204-unapproved
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 9.8 | sev-snp |
| TACRA: ledger certificate | no | 39.3 | — cai: EnrollCredential: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP contraindicated {'hardware': 32, 'runtime-opaque': 96}
ca-gateway: 2026/09/28 22:06:11 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce: attestation: ear: not affirming: SEVSNP is "contraindicated"
```

Deleted after the run: demobank-pay-282204-unapproved is gone

## Reference values: Google's signed firmware endorsements

Each approved GCP launch measurement was checked with `rrp/cmd/gce-endorsement` (google/gce-tcb-verifier) against Google's signed VMLaunchEndorsement, verified to the pinned root GCE-cc-tcb-root (SHA-256 e876bc69…f18c, fetched from https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt).

| technology | measurement | endorsed | firmware built | SVN | launch | note |
|---|---|---|---|---|---|---|
| sev-snp | `7a89cceaaba0bbdd…` | no |  |  |  | Google publishes no endorsement for this measurement; approved at start on an earlier run's observation (trust on first use) |
| sev-snp | `ccdc5cf01ba25526…` | yes | 2026-07-24T08:29:40Z | 2 | 2 vCPUs | approved at start |
| tdx | `c1ee9c16e3afc506…` | yes | 2026-05-21T23:52:45Z | 2 |  | approved at start |
| tdx | `f21e6b48743fe14c…` | yes | 2026-07-31T09:52:02Z | 2 |  | approved during the run |

Policy change applied on the trust zone:

```
setup done
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

 id | from_account | to_account | amount |    fraud_ref     |   tee   |             client_cn              |           client_cert_serial            |                       client_cert_issuer                        | db_user  |          created_at           
----+--------------+------------+--------+------------------+---------+------------------------------------+-----------------------------------------+-----------------------------------------------------------------+----------+-------------------------------
  1 | ACC-1001     | ACC-2002   | 125.50 | FRD-DA9DF0F28CC6 | sev-snp | payments.workload.demobank.example | 100505483510910569057168939122081688056 | /O=Demo Bank workload CA/CN=Demo Bank workload CA Intermediate  | payments | 2026-09-28 21:43:05.497613+00
  2 | ACC-1001     | ACC-2002   | 125.50 | FRD-BB7AA5BB3333 | tdx     | payments.workload.demobank.example | 86483529528201231764414630934768045297  | Demo Bank workload CA Intermediate CA                           | payments | 2026-09-28 21:58:21.243451+00
  3 | ACC-1001     | ACC-2002   | 125.50 | FRD-71233F5C2BAB | sev-snp | payments.workload.demobank.example | 189772737761729131886305290792578568672 | Demo Bank workload CA Intermediate CA                           | payments | 2026-09-28 22:00:52.626285+00
(3 rows)

--- ledger log: connections
2026-09-28 21:40:45.076 UTC [7766] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-09-28 21:40:45.595 UTC [7769] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-09-28 21:40:45.596 UTC [7769] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-09-28 21:40:45.596 UTC [7769] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-09-28 21:40:46.110 UTC [7772] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-09-28 21:40:46.112 UTC [7772] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-09-28 21:40:46.112 UTC [7772] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-09-28 21:40:46.209 UTC [7778] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-09-28 21:40:46.211 UTC [7778] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-09-28 21:40:46.211 UTC [7778] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-09-28 21:40:46.296 UTC [7782] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-09-28 21:40:46.297 UTC [7782] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-09-28 21:40:46.297 UTC [7782] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-09-28 21:40:46.428 UTC [7788] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-09-28 21:40:46.429 UTC [7788] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-09-28 21:40:46.429 UTC [7788] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-09-28 21:40:46.444 UTC [7793] [unknown]@[unknown] 127.0.0.1(48112) LOG:  connection received: host=127.0.0.1 port=48112
2026-09-28 21:40:46.524 UTC [7798] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-09-28 21:40:46.525 UTC [7798] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-09-28 21:40:46.525 UTC [7798] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-09-28 21:43:05.488 UTC [7975] [unknown]@[unknown] 10.128.15.232(32996) LOG:  connection received: host=10.128.15.232 port=32996
2026-09-28 21:43:05.495 UTC [7975] payments@bank 10.128.15.232(32996) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-09-28 21:43:05.495 UTC [7975] payments@bank 10.128.15.232(32996) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-09-28 21:44:57.099 UTC [8099] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-09-28 21:44:57.101 UTC [8099] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-09-28 21:44:57.101 UTC [8099] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
2026-09-28 21:44:57.208 UTC [8102] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-09-28 21:44:57.209 UTC [8102] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-09-28 21:44:57.209 UTC [8102] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
2026-09-28 21:58:21.232 UTC [8480] [unknown]@[unknown] 10.128.0.28(54598) LOG:  connection received: host=10.128.0.28 port=54598
2026-09-28 21:58:21.240 UTC [8480] payments@bank 10.128.0.28(54598) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-09-28 21:58:21.241 UTC [8480] payments@bank 10.128.0.28(54598) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-09-28 22:00:52.486 UTC [8617] [unknown]@[unknown] 18.216.111.184(49872) LOG:  connection received: host=18.216.111.184 port=49872
2026-09-28 22:00:52.593 UTC [8617] payments@bank 18.216.111.184(49872) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-09-28 22:00:52.593 UTC [8617] payments@bank 18.216.111.184(49872) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-09-28 22:03:10.657 UTC [8747] [unknown]@[unknown] 10.128.0.29(60534) LOG:  connection received: host=10.128.0.29 port=60534
2026-09-28 22:03:10.663 UTC [8747] payments@bank 10.128.0.29(60534) FATAL:  connection requires a valid client certificate
2026-09-28 22:07:52.821 UTC [9000] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-09-28 22:07:52.822 UTC [9000] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-09-28 22:07:52.822 UTC [9000] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
--- fraud service log
2026/09/28 21:37:36 fraud-api listening on :8444
2026/09/28 21:37:36 http: TLS handshake error from 127.0.0.1:32780: EOF
2026/09/28 21:38:51 http: TLS handshake error from 127.0.0.1:36116: EOF
2026/09/28 21:40:46 http: TLS handshake error from 127.0.0.1:35240: EOF
2026/09/28 21:43:05 score FRD-DA9DF0F28CC6: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/09/28 21:58:21 score FRD-BB7AA5BB3333: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/09/28 22:00:52 score FRD-71233F5C2BAB: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/09/28 22:03:10 score refused from 10.128.0.29:33220: wrong or missing API key
```

## Teardown

```
GCP instances labelled purpose=demo-bank: 0
GCP instances in rats-probe: 0
GCP firewall rules demobank-*: 0
AWS us-east-2 instances tagged purpose=demo-bank, not terminated: 0
AWS us-east-2 key pairs demobank-*: 0
AWS us-east-2 security groups demobank-*: 0
GCP disks: 0, GCP addresses: 0, AWS us-east-2 volumes: 0 (checked 2026-09-28T22:09:34Z)
```

## Notes

- Provisioning, not the protocol: the fraud service's API key was handed once from the core VM to the trust zone's Vault by piping it through the operator's console (`gcloud compute ssh ... | gcloud compute ssh ...`), never written to the console's disk; the file on the trust zone was deleted after loading into Vault. Every payment then got the key only through TACRA.
- step-ca logs the one-time token of each signing request; the tokens are redacted in `trust-logs/step-ca.log` (single-use, expired, and the CA no longer exists) and the per-run `sha256sums.txt` were computed after redaction.
- `TLS handshake error from 127.0.0.1` lines in the fraud service's log are the start script's port checks.
- Transfer 1 recorded the issuer with `ssl_issuer_dn()`, which PostgreSQL cuts at 63 bytes; later transfers record the issuer's common name with `ssl_issuer_field('commonName')`.

## Limits of this demonstration

- GCP reference values are Google-endorsed (above); the AWS launch measurement is still the value observed in an earlier run (trust on first use): Google does not endorse AWS firmware, and AWS's own firmware measurements were not computed here.
- Approving a newly endorsed firmware is an operator step (`demo-bank.sh approve`); the verifier does not yet consult the endorsements by itself.
- The TDX path uses our own verifier (go-tdx-guest against Intel PCS); Veraison in the SIG's fork has no TDX scheme.
- The trust zone runs in a SEV-SNP confidential VM, but in this demonstration it does not attest itself to anyone.
- Vault runs with a single unseal key on the trust-zone disk; a bank would use an HSM or cloud KMS auto-unseal.

