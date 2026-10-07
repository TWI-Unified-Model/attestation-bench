# Demo Bank: TACRA end to end on real hardware

Demo Bank is fictional: its names, accounts and amounts are made up. Every server of the bank ran in the cloud; the operator's machine only built the programs, created the VMs and collected this evidence.

The bank: `demo-bank`, from its pack `packs/demo-bank/pack.json` (SHA-256 `028ebe899230c18c…`).

## Machines

```
demobank-trust-2610071932 internal 10.128.0.15 external 34.70.142.140
demobank-core-2610071932 internal 10.128.0.19 external 34.57.252.217
```

Trust zone: Veraison (sevsnp scheme, reference values for the approved launches), step-ca, Vault, the Credential Authority and Secret Vault gateways, the TDX verifier, the EST server (the only port workloads reach). Core: the ledger (PostgreSQL; the payment service's role logs in only by a client certificate from the bank's workload CA) and the fraud-scoring service (pre-shared API key). The payment service holds no credential of its own.

Configuration: written by the bench's own program, `scripts/trustzone.py`, from `packs/demo-bank/pack.json` and the approved launches, as on the bench: mutual TLS between the components (tacra-est N23), the verifiers' EAR keys given to the gateways as files (N24), the API key released in the signed container (MLKEM768-P256, signed by the Vault). RATS model: background-check.

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
| `20261007T194000Z-gcp-tdx` | payment | PASS: the payment went through, with credentials acquired by attestation | transfer 1 committed |
| `20261007T194222Z-gcp-snp` | payment | PASS: genuine hardware evidence, refused by the bank's platform rule: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set in LAUNCH_MIT_VECTOR 0xb | TACRA: ledger certificate: 403 RRP ca: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025 |
| `20261007T194516Z-aws-snp` | payment | PASS: genuine hardware evidence, refused by the bank's platform rule: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set in LAUNCH_MIT_VECTOR 0xfef | TACRA: ledger certificate: 403 RRP ca: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025 |
| `20261007T194721Z-ordinary` | refusal | PASS: no attestation, no credential; the ledger and the fraud service refused it | attestation plug-in and CAI: no attestation provider; ledger: login without a certificate: FATAL: connection requires a valid client certificate; fraud service: call without the key: HTTP 403: not admitted |
| `20261007T194951Z-unapproved` | refusal | PASS: genuine hardware evidence, unapproved launch: no credential issued | TACRA: ledger certificate: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

### 20261007T194000Z-gcp-tdx

```
confidentialInstanceConfig:
  confidentialInstanceType: TDX
cpuPlatform: Intel Sapphire Rapids
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/c3-standard-4
name: demobank-pay-071940-gcp-tdx
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 41.8 | tdx |
| TACRA: ledger certificate | yes | 648.5 | [payments.workload.demobank.example] serial d9069b752042c2449c7c3cf88556e7bb until 2026-10-07T20:41:06Z |
| TACRA: fraud-service API key | yes | 64.3 | sealed to this VM's CEK, opened in the guest |
| fraud service: score | yes | 5.3 | approve FRD-7A85160C837B |
| ledger: transfer | yes | 18.8 | one transaction, client-certificate login |

Receipt (as the ledger returned it):

```json
{
 "amount": "125.50",
 "at": "2026-10-07T19:41:06Z",
 "balance_after": {
  "ACC-1001": "4874.50",
  "ACC-2002": "1125.50"
 },
 "balance_before": {
  "ACC-1001": "5000.00",
  "ACC-2002": "1000.00"
 },
 "certificate": {
  "not_after": "2026-10-07T20:41:06Z",
  "serial_hex": "d9069b752042c2449c7c3cf88556e7bb"
 },
 "db_user": "payments",
 "fraud_ref": "FRD-7A85160C837B",
 "from": "ACC-1001",
 "recorded_by_ledger": {
  "client_cert_issuer": "Demo Bank workload CA Intermediate CA",
  "client_cert_serial": "288476781919645760386870361380661684155",
  "client_cn": "payments.workload.demobank.example",
  "tls": "TLSv1.3"
 },
 "to": "ACC-2002",
 "transfer_id": 1
}
```

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
ca-gateway: 2026/10/07 19:41:06 enrolled: target=https://ledger-db.demobank.example kind=present-nonce hint="payments.workload.demobank.example" caller=[est-server.trust.demobank.example]
vault-gateway: 2026/10/07 19:41:06 released: target=https://fraud-api.demobank.example kind=present-nonce group=48f360b593d60cd2 container=hpke-base-signed kem=MLKEM768-P256 caller=[est-server.trust.demobank.example]
tdx-verifier: 2026/10/07 19:41:06 appraisal: affirming, MRTD f21e6b48743fe14c…
tdx-verifier: 2026/10/07 19:41:06 appraisal: affirming, MRTD f21e6b48743fe14c…
postgresql: 2026-10-07 19:41:06.182 UTC [4738] payments@bank 10.128.15.230(53044) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
postgresql: 2026-10-07 19:41:06.182 UTC [4738] payments@bank 10.128.15.230(53044) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
fraud-api: 2026/10/07 19:41:06 score FRD-7A85160C837B: ACC-1001 -> ACC-2002 12550 cents: approve (0)
```

Deleted after the run: demobank-pay-071940-gcp-tdx is gone at 2026-10-07T19:42:12Z

### 20261007T194222Z-gcp-snp

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-2
name: demobank-pay-071942-gcp-snp
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 11.1 | sev-snp |
| TACRA: ledger certificate | no | 254.3 | — cai: EnrollCredential: 403 RRP ca: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set in LAUNCH_MIT_VECTOR 0xb |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP affirming {'hardware': 2, 'runtime-opaque': 2}
ca-gateway: 2026/10/07 19:43:58 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce caller=[est-server.trust.demobank.example]: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set i
```

Deleted after the run: demobank-pay-071942-gcp-snp is gone at 2026-10-07T19:45:06Z

### 20261007T194516Z-aws-snp

```
us-east-2 us-east-2a i-0885098261927371a ami-09519cc56eb20524a c6a.large
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 10.6 | sev-snp |
| TACRA: ledger certificate | no | 354.3 | — cai: EnrollCredential: 403 RRP ca: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set in LAUNCH_MIT_VECTOR 0xfef |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP affirming {'hardware': 2, 'runtime-opaque': 2}
ca-gateway: 2026/10/07 19:46:23 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce caller=[est-server.trust.demobank.example]: platform-policy: the platform is not one this RRP accepts: mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set i
```

Deleted after the run: instance i-0885098261927371a: terminated at 2026-10-07T19:47:02Z; security group sg-0bddbc07f68483b36 deleted; key pair demobank-pay-194516-aws-snp deleted; GCP firewall rule demobank-aws-194516 deleted

### 20261007T194721Z-ordinary

```
cpuPlatform: Intel Broadwell
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/e2-small
name: demobank-pay-071947-ordinary
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | no | 0.3 | sev-snp — no attestation from this machine: platform: configfs-tsm report: could not create report entry in configfs: mkdir /sys/kernel/config/tsm/report/entry4142376720: no such device or address |
| ledger: login without a certificate | yes | 10.5 | refused as expected: failed to connect to `user=payments database=bank`: 10.128.0.19:5432 (core.demobank.internal): server error: FATAL: connection requires a valid client certificate (SQLSTATE 28000) |
| fraud service: call without the key | yes | 5.2 | refused as expected: HTTP 403: not admitted |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
postgresql: 2026-10-07 19:48:36.644 UTC [5139] payments@bank 10.128.0.21(59068) FATAL:  connection requires a valid client certificate
fraud-api: 2026/10/07 19:48:36 score refused from 10.128.0.21:54394: wrong or missing API key
```

Deleted after the run: demobank-pay-071947-ordinary is gone at 2026-10-07T19:49:41Z

### 20261007T194951Z-unapproved

```
confidentialInstanceConfig:
  confidentialInstanceType: SEV_SNP
cpuPlatform: AMD Milan
machineType: https://www.googleapis.com/compute/v1/projects/rats-probe/zones/us-central1-c/machineTypes/n2d-standard-4
name: demobank-pay-071949-unapproved
```

| step | ok | ms | note |
|---|---|---|---|
| attestation plug-in and CAI | yes | 10.9 | sev-snp |
| TACRA: ledger certificate | no | 43.6 | — cai: EnrollCredential: 403 RRP ca: attestation: ear: not affirming: SEVSNP is "contraindicated" |

Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):

```
veraison: SEVSNP contraindicated {'hardware': 32, 'runtime-opaque': 96}
ca-gateway: 2026/10/07 19:51:49 enroll refused: target=https://ledger-db.demobank.example kind=present-nonce caller=[est-server.trust.demobank.example]: attestation: ear: not affirming: SEVSNP is "contraindicated"
```

Deleted after the run: demobank-pay-071949-unapproved is gone at 2026-10-07T19:52:55Z

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

 id | from_account | to_account | amount |    fraud_ref     | tee |             client_cn              |           client_cert_serial            |          client_cert_issuer           | db_user  |          created_at          
----+--------------+------------+--------+------------------+-----+------------------------------------+-----------------------------------------+---------------------------------------+----------+------------------------------
  1 | ACC-1001     | ACC-2002   | 125.50 | FRD-7A85160C837B | tdx | payments.workload.demobank.example | 288476781919645760386870361380661684155 | Demo Bank workload CA Intermediate CA | payments | 2026-10-07 19:41:06.18412+00
(1 row)

--- ledger log: connections
2026-10-07 19:39:35.291 UTC [4523] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 19:39:35.802 UTC [4526] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 19:39:35.803 UTC [4526] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 19:39:35.803 UTC [4526] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 19:39:36.323 UTC [4529] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 19:39:36.325 UTC [4529] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 19:39:36.325 UTC [4529] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 19:39:36.839 UTC [4532] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 19:39:36.840 UTC [4532] postgres@template1 [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 19:39:36.841 UTC [4532] postgres@template1 [local] LOG:  connection authorized: user=postgres database=template1 application_name=psql
2026-10-07 19:39:36.933 UTC [4538] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 19:39:36.935 UTC [4538] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 19:39:36.935 UTC [4538] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 19:39:37.017 UTC [4542] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 19:39:37.018 UTC [4542] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 19:39:37.018 UTC [4542] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-10-07 19:39:37.093 UTC [4545] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 19:39:37.094 UTC [4545] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 19:39:37.094 UTC [4545] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=psql
2026-10-07 19:39:37.168 UTC [4546] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 19:39:37.169 UTC [4546] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 19:39:37.169 UTC [4546] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
2026-10-07 19:39:37.330 UTC [4552] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 19:39:37.331 UTC [4552] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 19:39:37.331 UTC [4552] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 19:39:37.346 UTC [4559] [unknown]@[unknown] 127.0.0.1(52678) LOG:  connection received: host=127.0.0.1 port=52678
2026-10-07 19:39:37.424 UTC [4565] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 19:39:37.425 UTC [4565] postgres@postgres [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 19:39:37.425 UTC [4565] postgres@postgres [local] LOG:  connection authorized: user=postgres database=postgres application_name=pg_isready
2026-10-07 19:41:06.177 UTC [4738] [unknown]@[unknown] 10.128.15.230(53044) LOG:  connection received: host=10.128.15.230 port=53044
2026-10-07 19:41:06.182 UTC [4738] payments@bank 10.128.15.230(53044) LOG:  connection authenticated: identity="CN=payments.workload.demobank.example" method=cert (/etc/postgresql/16/main/pg_hba.conf:2)
2026-10-07 19:41:06.182 UTC [4738] payments@bank 10.128.15.230(53044) LOG:  connection authorized: user=payments database=bank SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)
2026-10-07 19:48:36.639 UTC [5139] [unknown]@[unknown] 10.128.0.21(59068) LOG:  connection received: host=10.128.0.21 port=59068
2026-10-07 19:48:36.644 UTC [5139] payments@bank 10.128.0.21(59068) FATAL:  connection requires a valid client certificate
2026-10-07 19:53:07.642 UTC [5394] [unknown]@[unknown] [local] LOG:  connection received: host=[local]
2026-10-07 19:53:07.643 UTC [5394] postgres@bank [local] LOG:  connection authenticated: identity="postgres" method=peer (/etc/postgresql/16/main/pg_hba.conf:1)
2026-10-07 19:53:07.643 UTC [5394] postgres@bank [local] LOG:  connection authorized: user=postgres database=bank application_name=psql
--- fraud service log
2026/10/07 19:39:37 fraud-api listening on :8444
2026/10/07 19:39:37 http: TLS handshake error from 127.0.0.1:37428: EOF
2026/10/07 19:41:06 score FRD-7A85160C837B: ACC-1001 -> ACC-2002 12550 cents: approve (0)
2026/10/07 19:48:36 score refused from 10.128.0.21:54394: wrong or missing API key
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

