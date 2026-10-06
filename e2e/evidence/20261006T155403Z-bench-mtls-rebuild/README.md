# Mutual TLS on the rebuilt bench (06.10.2026, 15:54Z)

**Code:** branch `bench/rebuild`, `code-rev.txt` (the group's main `0d858d0` with our ported work). The binaries were
rebuilt from this tree by `e2e/scripts/bench.sh config` at 15:53Z.

**Setup:** the bench runs locally on the Mac (`bench.sh start`):
- Veraison (four services);
- step-ca;
- HashiCorp Vault;
- the TDX verifier;
- the CA and Vault gateways;
- the EST server;
- the RUP.

The RATS model is Passport, the decision of the TWI SIG meeting on 06.10. No hardware is involved in this check.

**What it checks:** `e2e/scripts/bench-mtls-check.py`, N23. For every channel between the infrastructure components,
it tries each caller:
- the named infrastructure identities;
- a certificate of the same root but another role;
- a certificate from a CA the bench does not know;
- no certificate;
- an allowed caller limited to TLS 1.2.

**Result:** 40 of 40 as expected (`run.log`, `mtls.json`).
- Callers without a certificate, with a foreign certificate, or on TLS 1.2 are refused at the handshake.
- A caller of the root in the wrong role gets 403.
- Two endpoints are open by design:
  - the workload's `attest-initiate` at the EST server, TLS 1.3 with server authentication only, because the CAS client
    is untrusted;
  - step-ca's health endpoint.

This answers part of attack G4 (a network attacker at an infrastructure hop) on the local bench. The workload's hop
from the guest is covered by the hardware runs.
