# Mutual TLS on the bench, first check: 39 of 40 (01.10.2026, 21:04Z)

`e2e/scripts/bench-mtls-check.py` ran on the running bench right after it was first configured for mutual TLS (tacra-est
N23). The bench was started from `bench.sh config` with the client certificates under the bench's TLS root; the
gateways, the TDX verifier, Veraison's verification API and HashiCorp Vault required a client certificate.

**The one check that failed.** The CA gateway's client certificate, presented to step-ca, ended the handshake
("tls"); without a certificate step-ca answered 200.

**Why.** step-ca checks a client certificate it is given against its own roots, and the bench's infrastructure root
is not one of them. The CA gateway, which then presented its certificate to step-ca, would have been refused at every
enrollment.

**The fix (in the same commit as the check).** The CA gateway now presents no TLS client certificate to step-ca and
reaches it over TLS 1.3. It authenticates to step-ca as before: with its provisioner's one-time token, signed with the
provisioner key it holds, for each certificate.

**The next run.** The check now expects step-ca to refuse a certificate of the bench's root, and to answer the gateway
without one. The run after this directory holds all 40 checks as expected.
