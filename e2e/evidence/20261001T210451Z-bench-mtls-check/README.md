# Mutual TLS on the bench: 40 of 40 (01.10.2026, 21:04Z)

`e2e/scripts/bench-mtls-check.py`, on the bench restarted after the step-ca fix
(`../20261001T210405Z-bench-mtls-check/README.md`). This is tacra-est N23: "no mutual authentication on the
channels between EST server, Verifier, CA and Vault".

**The callers.**

- **The bench's infrastructure identities.** One client certificate each, under the bench's TLS root, named
  `<name>.bench.tacra.example`: `est-server`, `ca-gateway`, `vault-gateway` and `operator`.
- **`localhost`.** A service certificate of the same root.
- **`foreign`.** A certificate with the EST server's name, from a CA the bench does not know.
- **`none`.** No certificate.

**What every listener does.** It takes TLS 1.3 only: each refused an allowed caller held to TLS 1.2.

| channel | gets through | refused 403 | refused at the handshake |
|---|---|---|---|
| EST server → CA gateway, attest-initiate | `est-server` | `operator`, `localhost`, `ca-gateway` | `foreign`, none |
| EST server → Vault gateway, attest-initiate | `est-server` | `operator`, `vault-gateway` | `foreign`, none |
| Vault gateway's origin keys (public material) | `operator`, `est-server` | - | `foreign`, none |
| EST server or gateway → TDX verifier, new session | `est-server`, `ca-gateway`, `vault-gateway` | `operator` | `foreign`, none |
| EST server or gateway → Veraison, new session | `est-server`, `ca-gateway` | - (Veraison has no list of callers) | `foreign`, none |
| Vault gateway → HashiCorp Vault | `vault-gateway`, `operator` | - | `foreign`, none |
| CA gateway → step-ca | a caller without a certificate | - | a certificate of the bench's root |
| workload → EST server, attest-initiate | a caller without a certificate | - | - |

**step-ca.** The CA gateway authenticates to step-ca with its provisioner's one-time token, signed with the key it
holds, rather than with a TLS client certificate.

**The workload's channel.** The EST server takes TLS 1.3 only, and no client certificate. The workload stays
untrusted until attestation.

The logs show who each component took:

- the gateways log `caller=[est-server.bench.tacra.example]` on each enrollment and release;
- the TDX verifier logs `session for [...]`;
- Veraison logs `session requested {"caller": [...]}`.

These need Veraison with `verification.client-ca` (veraison-services branch `tacra/verification-client-ca`, `675fe11`)
and HashiCorp Vault with `tls_require_and_verify_client_cert`, both set by `bench.sh config`.
