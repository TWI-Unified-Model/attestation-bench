# TACRA on SPIRE: an attested workload on sev-snp

A walkthrough of one run of the SPIRE proof of concept of draft-novak-rats-tacra, written from the run's record
`20261103T225224Z-spire-gcp-sev-snp-e2e`. Every output below is the run's own.

## Roles, in the words of the draft

- The attested workload is the Attester, with the Credential Acquisition Interface built in; it holds CSKpri and CEKpri
  inside the environment its Evidence attests.
- SPIRE Agent is the CAS Client and SPIRE Server the CAS Server: conduits that hold no RATS role and no credential.
  The CAS Server forwards Evidence to the Verifier; it does not appraise Attestation Results.
- SPIRE Server's CA is the Credential Authority, the Relying Party for enrollment: it issued the Freshness Handle,
  recomputes the binding value, appraises the Attestation Results by its own policy and mints the X509-SVID.
- The bench's Secret Vault is the Relying Party for retrieval; the bench's Veraison is the Verifier.
- The vault's mode in this run: rats_model=passport origin_auth=on.

## What runs where

- On the bench machine: SPIRE Server (this organization's fork, branch tacra-credential-acquisition), Veraison, the
  Secret Vault.
- In a fresh confidential guest (n2d-standard-2, kernel 7.0.0-1014-gcp): SPIRE Agent and the attested workload, which
  generates its keys and obtains its Evidence through the Linux configfs-tsm interface.
- The guest reaches the server through an SSH reverse tunnel; the server reaches Veraison and the vault on the bench
  machine over mutually authenticated TLS.

## 1. Initiate-Credential-Acquisition

The workload asks the agent for the Target `spiffe://example.org` and Credential Type `x509`. The agent
attests the workload (unix selectors), picks its registration entry and forwards the request to the server. The
Credential Authority answers:

- mode: CREDENTIAL_ACQUISITION_MODE_ENROLL
- Freshness Kind: FRESHNESS_KIND_PRESENT_NONCE; Handle (32 octets, single use in this implementation): `3ae3994bf866200f4ef0d5bd3344333db1a7f1285806cb4a413abe526a73905d`
- acceptable CSK algorithms: ['ecdsa-p256-sha256']; acceptable Evidence formats: ['application/vnd.veraison.tsm-report+cbor']

## 2. Enroll-Credential

The workload generates a P-256 Credential Signing Key and a PKCS#10 CSR, and the hardware signs Evidence whose
freshness input is the TACRA binding value, SHA-512 over the Handle, the Target and the CSR:

- binding value: `b4c2f3a1c4d370f23f1ef7dbfea5ff7534a69208f5305620b38c2483b54cad8133caf36da520a519f6959c96d0d25e7c927c640d6d2f5616dd8612fcbca2dfc2`
- Evidence: 5989 octets of `application/vnd.veraison.tsm-report+cbor` (sev_guest, report version 5, signed by VCEK)
- launch measurement: `e79ebb5b789ddb6b7a9897f663a655a65c69445aa482c4e1a5ff9fdeb4af1a2c8d5d30fcad5f4f0e04f1a13885eb984d`

The CAS Server forwards the Evidence to Veraison with the binding value as the session nonce. The Credential
Authority takes the Handle it issued, recomputes the binding value from the Handle, the Target and the CSR, checks the
CSR's proof of possession, appraises the Attestation Results (the nonce they carry, the launch measurement against its
list, the bench's platform rule) and mints the X509-SVID. Timing: initiate 41.782 ms, enroll
515.099 ms, Veraison included.

The certificate as the workload received it, its chain verified against the trust domain's bundle, its key the
workload's own:

```
subject=C=US, O=SPIRE
issuer=C=US, O=SPIFFE, serialNumber=116671042965471882263584653723515374078
notBefore=Nov  3 22:54:53 2026 GMT
notAfter=Nov  3 23:55:03 2026 GMT
X509v3 Subject Alternative Name: 
    URI:spiffe://example.org/workload
```

The Credential Authority's audit records of the enrollment:

```
time="2026-11-03T16:55:03-06:00" level=info msg="API accessed" authorized_as=agent authorized_via=datastore caller_id="spiffe://example.org/spire/agent/join_token/fc136746-6ce3-424b-8f03-7147ab3f289f" credential_type=x509 csr=fce0555e54c07ed0798f157c7921fb4aecd14183f3eebbf04b8b8cc36e78ea59 entry_id=7bc28e3b-2659-49f5-b969-c078f9e3bae5 expires_at=1793750103 freshness_kind=present-nonce measurement=e79ebb5b789ddb6b7a9897f663a655a65c69445aa482c4e1a5ff9fdeb4af1a2c8d5d30fcad5f4f0e04f1a13885eb984d method=EnrollCredential request_id=633f86d5-efab-474b-8cc0-a69bb0c3e09f service=credentialacquisition.v1.CredentialAcquisition spiffe_id="spiffe://example.org/workload" status=success submod=SEVSNP subsystem_name=api target="spiffe://example.org" type=audit verifier=veraison waived="admitted without bit 4, AMD-SB-3034: Milan mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set (LAUNCH_MIT_VECTOR 0xfeb, CURRENT_MIT_VECTOR 0xfeb)"
time="2026-11-03T16:55:03-06:00" level=info msg="Enrolled an attested X509-SVID" authorized_as=agent authorized_via=datastore caller_id="spiffe://example.org/spire/agent/join_token/fc136746-6ce3-424b-8f03-7147ab3f289f" expiration="2026-11-03T23:55:03Z" measurement=e79ebb5b789ddb6b7a9897f663a655a65c69445aa482c4e1a5ff9fdeb4af1a2c8d5d30fcad5f4f0e04f1a13885eb984d method=EnrollCredential request_id=633f86d5-efab-474b-8cc0-a69bb0c3e09f serial_num=325445020513225148324440535568258352067 service=credentialacquisition.v1.CredentialAcquisition spiffe_id="spiffe://example.org/workload" subsystem_name=api verifier=veraison
```
The platform rule admitted the host under a named waiver:

```
time="2026-11-03T16:55:03-06:00" level=warning msg="Attestation Results admitted under a waiver of the platform rule" subsystem_name=credential_acquisition verifier=veraison waiver="admitted without bit 4, AMD-SB-3034: Milan mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set (LAUNCH_MIT_VECTOR 0xfeb, CURRENT_MIT_VECTOR 0xfeb)"
```

The Verifier's sessions, both opened by the CAS Server, the first with the enrollment's binding value as the nonce and
the second with the retrieval's; in the Passport model the CAS Server forwards the resulting Attestation Results,
unchanged, to the Secret Vault:

```
INFO	session requested	{"caller": ["ca-gateway.bench.tacra.example"]}
INFO	gin	[GIN] 2026/11/03 - 16:55:03 | 201 |   99.347875ms |       127.0.0.1 | POST     "/challenge-response/v1/newSession?nonce=tMLzocTTcPI_Hvfb_qX_dTSmkgj1MFYgs4wkg7VMrYEzyvNtpSClGfaVnJbQ0l58knxkDW0vVhbdhhL8vKLfwg%3D%3D"
INFO	gin	[GIN] 2026/11/03 - 16:55:03 | 200 |  254.588417ms |       127.0.0.1 | POST     "/challenge-response/v1/session/9b103962-d7d9-11f1-bfb3-313543423532"
INFO	gin	[GIN] 2026/11/03 - 16:55:03 | 204 |       2.708µs |       127.0.0.1 | DELETE   "/challenge-response/v1/session/9b103962-d7d9-11f1-bfb3-313543423532"
INFO	session requested	{"caller": ["ca-gateway.bench.tacra.example"]}
INFO	gin	[GIN] 2026/11/03 - 16:55:03 | 201 |      24.994ms |       127.0.0.1 | POST     "/challenge-response/v1/newSession?nonce=yGs8WwVdYDf0_ycrKKm5uqYBXmZmufZYiiaXgFG93U9em95Eta_ToxtyMpCtrFiBeHoSzKOVf85Dbpu3tdMv9w%3D%3D"
INFO	gin	[GIN] 2026/11/03 - 16:55:03 | 200 |   16.491583ms |       127.0.0.1 | POST     "/challenge-response/v1/session/9b5a3800-d7d9-11f1-bfb3-313543423532"
INFO	gin	[GIN] 2026/11/03 - 16:55:03 | 204 |       2.209µs |       127.0.0.1 | DELETE   "/challenge-response/v1/session/9b5a3800-d7d9-11f1-bfb3-313543423532"
```

## 3. Retrieve-Credential

For the Target `https://ledger-nonce.tacra.example` (Credential Type api-key, Credential Hint `payments.workload.tacra.example`)
the server answers mode CREDENTIAL_ACQUISITION_MODE_RETRIEVE with the Secret Vault's Handle. The workload generates a Credential Encryption
Key for the suite `MLKEM768-P256+HKDF-SHA256+AES-256-GCM` (CEKpub 1249 octets), binds it into fresh Evidence, and the
vault, the Relying Party, releases:

- credential group: `0156b1ec5fc72a6ccc6c04b33e23cb114c9e19979cd3fe68bdd7e9495544a46c`
- item: api-key `0156b1ec5fc72a6c`, purpose ['authenticate'], algorithm opaque-bearer, 64 octets (the record keeps only its SHA-256, `332e6832d1a35ebe5a1e3361d2306469c966868bffeb6dc25ed4a2cc7892ee10`)
- the container's origin signature verified under the vault's key: True
- timing: initiate 112.573 ms, retrieve 150.596 ms

In the Passport model the CAS Server sent the Evidence to Veraison and forwarded the Attestation Results, unchanged, to
the Secret Vault, which recomputed the binding value from its Handle, the Target and CEKpub and appraised them by its own
policy. Only the workload's CEK opens the container; the agent and the server carried it sealed.

The CAS Server's audit record of the retrieval, and the Secret Vault's release:

```
time="2026-11-03T16:55:04-06:00" level=info msg="API accessed" authorized_as=agent authorized_via=datastore caller_id="spiffe://example.org/spire/agent/join_token/fc136746-6ce3-424b-8f03-7147ab3f289f" credential_type=api-key entry_id=7bc28e3b-2659-49f5-b969-c078f9e3bae5 freshness_kind=present-nonce method=RetrieveCredential request_id=7cc60e4a-6c06-4e29-b460-114265b1d6a8 service=credentialacquisition.v1.CredentialAcquisition status=success subsystem_name=api target="https://ledger-nonce.tacra.example" type=audit
time="2026-11-03T16:55:04-06:00" level=info msg="Retrieved an attested credential bundle" authorized_as=agent authorized_via=datastore caller_id="spiffe://example.org/spire/agent/join_token/fc136746-6ce3-424b-8f03-7147ab3f289f" method=RetrieveCredential request_id=7cc60e4a-6c06-4e29-b460-114265b1d6a8 service=credentialacquisition.v1.CredentialAcquisition spiffe_id="spiffe://example.org/workload" subsystem_name=api
2026/11/03 16:55:04 released: target=https://ledger-nonce.tacra.example kind=present-nonce group=0156b1ec5fc72a6c container=hpke-base kem=MLKEM768-P256 origin=true caller=[est-server.bench.tacra.example]; under the platform rule's waiver: admitted without bit 4, AMD-SB-3034: Milan mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set (LAUNCH_MIT_VECTOR 0xfeb, CURRENT_MIT_VECTOR 0xfeb)
```

## The server's configuration

```
credential_acquisition {
    acceptable_evidence = ["application/vnd.veraison.tsm-report+cbor"]
    ear_max_age = "120s"
    ear_skew = "5s"
    client_cert_path = "~/.attestation-bench/tls/clients/ca-gateway.crt"
    client_key_path = "~/.attestation-bench/tls/clients/ca-gateway.key"
    verifier "veraison" {
        url = "https://localhost:8443"
        ca_path = "~/.attestation-bench/veraison/certs/rootCA.crt"
        ear_key_path = "~/.attestation-bench/gateways/veraison.ear.jwk"
        provider = "sev_guest"
        submods = ["SEVSNP"]
    }
    target "spiffe://example.org" {
        mode = "enroll"
        credential_types = ["x509"]
        freshness_kind = "present-nonce"
        expires_in = "5m"
        verifiers = ["veraison"]
        acceptable_csk = ["ecdsa-p256-sha256"]
        measurements = ["7a89cceaaba0bbdddc4f775acca3ef15d1f9bf8abccdc6115cfad7fb8eae113df3ee0bb50efa34db9c53ae065b1dc766", "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5", "ccdc5cf01ba25526bd65503d95931b787b4385a3277cfe4448addf9c3e894948ae8cf7b099620e3e22717de2fb5d26fa", "e79ebb5b789ddb6b7a9897f663a655a65c69445aa482c4e1a5ff9fdeb4af1a2c8d5d30fcad5f4f0e04f1a13885eb984d", "f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3"]
    }
    target "https://ledger-nonce.tacra.example" {
        mode = "retrieve"
        credential_types = ["api-key", "x509"]
        rats_model = "passport"
        verifiers = ["veraison"]
    }
    secret_vault {
        url = "https://127.0.0.1:9102"
        ca_path = "~/.attestation-bench/tls/root.crt"
        client_cert_path = "~/.attestation-bench/tls/clients/est-server.crt"
        client_key_path = "~/.attestation-bench/tls/clients/est-server.key"
    }
    platform_rule_path = "~/.attestation-bench/spire/platform-rule.json"
}
```

## The verdict

```
ADMITTED  enroll: workload ok
ADMITTED  enroll: chain verified against the bundle
ADMITTED  enroll: the SVID carries the workload's key
ADMITTED  enroll: SPIFFE ID of the entry
ADMITTED  enroll: launch measurement approved
ADMITTED  enroll: server enrolled with the report's measurement
ADMITTED  enroll: server audited the enrollment
ADMITTED  retrieve: workload ok
ADMITTED  retrieve: a credential came back, opened by the workload's CEK
ADMITTED  retrieve: the same launch measurement
ADMITTED  retrieve: server audited the retrieval
ADMITTED  retrieve: the Secret Vault released for the Target
ADMITTED  retrieve: the container's origin signature verified under the vault's key

enroll: spiffe_id=spiffe://example.org/workload serial=325445020513225148324440535568258352067 not_after=2026-11-03T23:55:03Z
enroll: measurement=e79ebb5b789ddb6b7a9897f663a655a65c69445aa482c4e1a5ff9fdeb4af1a2c8d5d30fcad5f4f0e04f1a13885eb984d report_version=5 signer=VCEK waived=
enroll: initiate_ms=41.782 enroll_ms=515.099 evidence_bytes=5989
retrieve: item=api-key/0156b1ec5fc72a6c suite=MLKEM768-P256+HKDF-SHA256+AES-256-GCM secret_bytes=64 secret_sha256=332e6832d1a35ebe5a1e3361d2306469c966868bffeb6dc25ed4a2cc7892ee10 group=0156b1ec5fc72a6c…
retrieve: initiate_ms=112.573 retrieve_ms=150.596 cek_pub_bytes=1249 origin_verified=True vault: vault rats_model=passport origin_auth=on
```
