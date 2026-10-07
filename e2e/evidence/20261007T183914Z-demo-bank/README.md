# Demo Bank: TACRA end to end on real hardware

Demo Bank is fictional: its names, accounts and amounts are made up. Every server of the bank ran in the cloud; the operator's machine only built the programs, created the VMs and collected this evidence.

The bank: `demo-bank`, from its pack `packs/demo-bank/pack.json` (SHA-256 `028ebe899230c18c…`).

## Machines

```
demobank-trust-2610071839 internal 10.128.15.228 external 35.253.163.108
demobank-core-2610071839 internal 10.128.15.229 external 34.66.17.190
```

Trust zone: Veraison (sevsnp scheme, reference values for the approved launches), step-ca, Vault, the Credential Authority and Secret Vault gateways, the TDX verifier, the EST server (the only port workloads reach). Core: the ledger (PostgreSQL; the payment service's role logs in only by a client certificate from the bank's workload CA) and the fraud-scoring service (pre-shared API key). The payment service holds no credential of its own.

Configuration: written by the bench's own program, `scripts/trustzone.py`, from `packs/demo-bank/pack.json` and the approved launches, as on the bench: mutual TLS between the components (tacra-est N23), the verifiers' EAR keys given to the gateways as files (N24), the API key released in the signed container (MLKEM768-P256, signed by the Vault). RATS model: passport.

## Code

```
attestation-bench be0a45f7f0dd
globalsign-est/src upstream 04ffa468b167 + 11 patch(es), tree 3628224cb698: tested tree
veraison-services/src upstream f997c5275c30 + 8 patch(es), tree e7a04b43faf9: tested tree
go-gen-ref/src upstream aa3740de6b00 + 3 patch(es), tree 5f74ee0c1309: tested tree
step-ca v0.30.2, step v0.30.2 (built from their release modules); vault 2.1.1, go 1.27.0 (official releases, SHA-256 checked on the VM against scripts/versions.env)
```

## Runs

| run | expected | verdict | what happened |
|---|---|---|---|
| `20261007T184709Z-gcp-tdx` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 1 committed |
| `20261007T184927Z-gcp-snp` | payment | PASS: genuine hardware evidence, refused by the bank's platform rule: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set in LAUNCH_MIT_VECTOR 0xb | TACRA: ledger certificate: 403 RRP ca: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025 |
| `20261007T185218Z-aws-snp` | payment | PASS: genuine hardware evidence, refused by the bank's platform rule: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set in LAUNCH_MIT_VECTOR 0xfef | TACRA: ledger certificate: 403 RRP ca: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025 |
| `20261007T185428Z-ordinary` | refusal | PASS: no attestation, no credential; the ledger and the fraud service refused it | attestation plug-in and CAI: no attestation provider; ledger: login without a certificate: FATAL: connection requires a valid client certificate; fraud service: call without the key: HTTP 403: not admitted |
| `20261007T185700Z-unapproved` | refusal | PASS: genuine hardware evidence, unapproved launch: no credential issued | TACRA: ledger certificate: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

### 20261007T184709Z-gcp-tdx

```
confidentialInstanceConfig:
  confidentialInstanceType: TDX
cpuPlatform: Intel Sapphire Rapids
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/c3-standard-4
name: demobank-pay-071847-gcp-tdx
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 41.2 | tdx |
| TACRA: ledger certificate | yes | 723.8 | [payments.workload.demobank.example] serial 1e72aa3b7de9c826abdc3ffb56500803 until 2026-10-07T19:48:14Z |
| TACRA: fraud-service API key | yes | 61.0 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 5.2 | approve FRD-0FABB5882275 |
| ledger: transfer | yes | 18.0 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-07T18:48:14Z",
 "balance_after": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "balance_before": {
  "ACC-1001": "5000.00",
  "ACC-2002": "1000.00"
 },
 "certificate": {
  "not_after": "2026-10-07T19:48:14Z",
  "serial_hex": "1e72aa3b7de9c826abdc3ffb56500803"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-0FABB5882275",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "40472214438482906792629711784142440451",
  "client_cn": "payments.workload.demobank.example",
  "tls": "TLSv1.3"
 },
 "to": "ACC-2002",
 "transfer_id": 1
}
```

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
ca-gateway: 2026/10/07 18:48:14 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint="payments.workload.demobank.example" caller=[est-server.trust.demobank.example]
vault-gateway: 2026/10/07 18:48:14 released: target=https://fraud-api.demobank.example kind=present-nonce group=48f360b593d60cd2 container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.demobank.example]
tdx-verifier: 2026/10/07 18:48:14 appraisal: affirming, MRTD f21e6b48743fe14c…
tdx-verifier: 2026/10/07 18:48:14 appraisal: affirming, MRTD f21e6b48743fe14c…
postgresql: 2026-10-07 18:48:14.217 UTC [4754] payments@bank 10.128.15.231(50366) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-07 18:48:14.217 UTC [4754] payments@bank 10.128.15.231(50366) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/07 18:48:14 score FRD-0FABB5882275: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-071847-gcp-tdx is gone at 2026-10-07T18:49:17Z

### 20261007T184927Z-gcp-snp

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-2
name: demobank-pay-071849-gcp-snp
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 10.1 | sev-snp |
| TACRA: ledger certificate | no | 254.1 | — cai: EnrollCredential: 403 RRP ca: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set in LAUNCH_MIT_VECTOR 0xb |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP affirming {'hardware': 2, 'runtime-opaque': 2}
ca-gateway: 2026/10/07 18:51:04 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce caller=[est-server.trust.demobank.example]: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set i
```

Deleted after the run: demobank-pay-071849-gcp-snp is gone at 2026-10-07T18:52:08Z

### 20261007T185218Z-aws-snp

```
us-east-2 us-east-2a i-02ec3c5337e085eda ami-09519cc56eb20524a c6a.large
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 10.3 | sev-snp |
| TACRA: ledger certificate | no | 444.4 | — cai: EnrollCredential: 403 RRP ca: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set in LAUNCH_MIT_VECTOR 0xfef |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP affirming {'hardware': 2, 'runtime-opaque': 2}
ca-gateway: 2026/10/07 18:53:30 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce caller=[est-server.trust.demobank.example]: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set i
```

Deleted after the run: instance i-02ec3c5337e085eda: terminated at 2026-10-07T18:54:10Z; security group sg-0b5a94b0fd7ded9b0 deleted; key pair demobank-pay-185218-aws-snp deleted; GCP firewall rule demobank-aws-185218 deleted

### 20261007T185428Z-ordinary

```
cpuPlatform: Intel Broadwell
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/e2-small
name: demobank-pay-071854-ordinary
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | no | 0.3 | sev-snp — no attestation from this machine: platform: configfs-tsm report: could not create report entry in configfs: mkdir /sys/kernel/config/tsm/report/entry2164068188: no such device or address |
| ledger: login without a certificate | yes | 12.7 | refused as expected: failed to connect to `user=payments database=bank`: 10.128.15.229:5432 (core.demobank.internal): server error: FATAL: connection requires a valid client certificate (SQLSTATE 28000) |
| fraud service: call without the key | yes | 4.8 | refused as expected: HTTP 403: not admitted |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
postgresql: 2026-10-07 18:55:40.057 UTC [5152] payments@bank 10.128.0.17(45916) FATAL:  connection requires a valid client certificate
fraud-api: 2026/10/07 18:55:40 score refused from 10.128.0.17:52668: wrong or missing API key
```

Deleted after the run: demobank-pay-071854-ordinary is gone at 2026-10-07T18:56:50Z

### 20261007T185700Z-unapproved

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-4
name: demobank-pay-071857-unapproved
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 9.5 | sev-snp |
| TACRA: ledger certificate | no | 43.6 | — cai: EnrollCredential: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP contraindicated {'hardware': 32, 'runtime-opaque': 96}
ca-gateway: 2026/10/07 18:58:38 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce caller=[est-server.trust.demobank.example]: attestation: ear: not affirming: SEVSNP is "contraindicated"
```

Deleted after the run: demobank-pay-071857-unapproved is gone at 2026-10-07T18:59:45Z

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

 id | from_account | to_account | amount |    fraud_ref     | tee |             client_cn              |           client_cert_serial           |          client_cert_issuer           | db_user  |          created_at           
----+--------------+------------+--------+------------------+-----+------------------------------------+----------------------------------------+---------------------------------------+----------+-------------------------------
  1 | ACC-1001     | ACC-2002   | 125.50 | FRD-0FABB5882275 | tdx | payments.workload.demobank.example | 40472214438482906792629711784142440451 | Demo Bank workload CA Intermediate CA | payments | 2026-10-07 18:48:14.219046+00
(1 row)

--- ledger log: connections
2026-10-07 18:46:44.278 UTC [4542] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 18:46:44.786 UTC [4545] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 18:46:44.787 UTC [4545] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 18:46:44.787 UTC [4545] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 18:46:45.303 UTC [4548] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 18:46:45.304 UTC [4548] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 18:46:45.304 UTC [4548] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 18:46:45.816 UTC [4551] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 18:46:45.817 UTC [4551] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 18:46:45.817 UTC [4551] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 18:46:45.902 UTC [4557] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 18:46:45.903 UTC [4557] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 18:46:45.903 UTC [4557] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 18:46:45.975 UTC [4561] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 18:46:45.976 UTC [4561] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 18:46:45.976 UTC [4561] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-10-07 18:46:46.046 UTC [4564] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 18:46:46.047 UTC [4564] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 18:46:46.047 UTC [4564] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-10-07 18:46:46.113 UTC [4565] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 18:46:46.114 UTC [4565] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 18:46:46.114 UTC [4565] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
2026-10-07 18:46:46.263 UTC [4571] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 18:46:46.264 UTC [4571] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 18:46:46.264 UTC [4571] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 18:46:46.277 UTC [4579] [unknown]@[unknown] 127.0.0.1(58904) LOG:  connection received: host=127.0.0.1 port=58904
2026-10-07 18:46:46.348 UTC [4585] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 18:46:46.349 UTC [4585] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 18:46:46.349 UTC [4585] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 18:48:14.212 UTC [4754] [unknown]@[unknown] 10.128.15.231(50366) LOG:  connection received: host=10.128.15.231 port=50366
2026-10-07 18:48:14.217 UTC [4754] payments@bank 10.128.15.231(50366) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-07 18:48:14.217 UTC [4754] payments@bank 10.128.15.231(50366) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-07 18:55:40.050 UTC [5152] [unknown]@[unknown] 10.128.0.17(45916) LOG:  connection received: host=10.128.0.17 port=45916
2026-10-07 18:55:40.057 UTC [5152] payments@bank 10.128.0.17(45916) FATAL:  connection requires a valid client certificate
2026-10-07 18:59:57.811 UTC [5406] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 18:59:57.813 UTC [5406] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 18:59:57.813 UTC [5406] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
--- fraud service log
2026/10/07 18:46:46 fraud-api listening on :8444
2026/10/07 18:46:46 http: TLS handshake error from 127.0.0.1:42920: EOF
2026/10/07 18:48:14 score FRD-0FABB5882275: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/10/07 18:55:40 score refused from 10.128.0.17:52668: wrong or missing API key
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

