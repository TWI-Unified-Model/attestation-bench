#!/usr/bin/env python3
"""Mutual TLS on the running bench (tacra-est 10-REQUIREMENTS-MATRIX N23): for each channel between the bench's
infrastructure components, who gets through and who does not. No hardware; the bench must be running
(e2e/scripts/bench.sh start). Prints one line per check and writes them as JSON.

    python3 e2e/scripts/bench-mtls-check.py OUT.json

The callers:
  est-server, ca-gateway, vault-gateway, operator  the bench's infrastructure identities (tls/clients/)
  localhost        a service certificate of the same root (CN=localhost), with the client-auth key usage
  foreign          a certificate with the EST server's name, from a CA the bench does not know (made here)
  none             no certificate
and, for each listener, a caller allowed there but limited to TLS 1.2.

A refusal at the handshake is "tls"; an answer is its HTTP status. A route the policy keeps for named callers answers
403 to another caller of the root.
"""
import datetime
import http.client
import json
import os
import ssl
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# BENCH_HOME and VERAISON_DEPLOYMENT as in scripts/lib.sh
B = os.environ.get("BENCH_HOME") or os.environ.get("TACRA_BENCH") or os.path.expanduser("~/.attestation-bench")
ROOT = f"{B}/tls/root.crt"
VERAISON_CA = os.path.join(os.environ.get("VERAISON_DEPLOYMENT") or f"{B}/veraison", "certs", "rootCA.crt")


def foreign_identity(tmp: str) -> tuple[str, str]:
    """A certificate named like the EST server, from a CA of its own."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not the bench's root")])
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "est-server.bench.tacra.example")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("est-server.bench.tacra.example")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    cp, kp = os.path.join(tmp, "foreign.crt"), os.path.join(tmp, "foreign.key")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    return cp, kp


def call(port: int, ca: str, method: str, path: str, ident, body: bytes | None = None, tls12: bool = False):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    if tls12:
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if ident:
        ctx.load_cert_chain(*ident)
    try:
        c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=15)
        c.request(method, path, body=body, headers={"Content-Type": "application/json"} if body is not None else {})
        r = c.getresponse()
        r.read()
        return r.status
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected) as e:
        return "tls"


def main() -> int:
    out = sys.argv[1]
    tmp = tempfile.mkdtemp(prefix="mtls-check-")
    ids = {n: (f"{B}/tls/clients/{n}.crt", f"{B}/tls/clients/{n}.key") for n in ("est-server", "ca-gateway", "vault-gateway", "operator")}
    ids["localhost"] = (f"{B}/tls/rup.crt", f"{B}/tls/rup.key")
    ids["foreign"] = foreign_identity(tmp)
    ids["none"] = None
    init = json.dumps({"target": "https://db-nonce.tacra.example", "credential_type": "x509"}).encode()
    vinit = json.dumps({"target": "https://ledger-nonce.tacra.example", "credential_type": "api-key"}).encode()
    nonce = "?nonce=" + "A" * 43 + "="
    # (channel, port, server CA, method, path, body, {caller: expected}, the allowed caller for the TLS 1.2 check)
    checks = [
        ("EST server -> CA gateway: attest-initiate", 9101, ROOT, "POST", "/tacra/v1/initiate", init,
         {"est-server": 200, "operator": 403, "localhost": 403, "ca-gateway": 403, "foreign": "tls", "none": "tls"}, "est-server"),
        ("EST server -> Vault gateway: attest-initiate", 9102, ROOT, "POST", "/tacra/v1/initiate", vinit,
         {"est-server": 200, "operator": 403, "vault-gateway": 403, "foreign": "tls", "none": "tls"}, "est-server"),
        ("operator -> Vault gateway: origin keys (public)", 9102, ROOT, "GET", "/tacra/v1/origin-keys", None,
         {"operator": 200, "est-server": 200, "foreign": "tls", "none": "tls"}, "operator"),
        ("EST server or gateway -> TDX verifier: new session", 8453, ROOT, "POST", "/challenge-response/v1/newSession" + nonce, None,
         {"est-server": 201, "ca-gateway": 201, "vault-gateway": 201, "operator": 403, "foreign": "tls", "none": "tls"}, "est-server"),
        ("EST server or gateway -> Veraison: new session", 8443, VERAISON_CA, "POST", "/challenge-response/v1/newSession" + nonce, None,
         {"est-server": 201, "ca-gateway": 201, "foreign": "tls", "none": "tls"}, "est-server"),
        ("Vault gateway -> HashiCorp Vault: health", 8200, ROOT, "GET", "/v1/sys/health", None,
         {"vault-gateway": 200, "operator": 200, "foreign": "tls", "none": "tls"}, "vault-gateway"),
        # step-ca checks client certificates against its own roots and refuses the handshake for one of the bench's
        # root; the CA gateway presents none there and authenticates with its provisioner's one-time token
        ("CA gateway -> step-ca: health", 9000, f"{B}/step/certs/root_ca.crt", "GET", "/health", None,
         {"none": 200, "ca-gateway": "tls"}, "none"),
        ("workload -> EST server: attest-initiate (TLS 1.3, no client certificate required)", 18443, ROOT, "GET",
         "/.well-known/est/attest-initiate?target=https%3A%2F%2Fdb-none.tacra.example&credential_type=x509", None,
         {"none": 200}, "none"),
    ]
    results, bad = [], 0
    for channel, port, ca, method, path, body, expect, tls12_caller in checks:
        for caller, want in expect.items():
            got = call(port, ca, method, path, ids[caller], body)
            ok = got == want
            bad += not ok
            results.append({"channel": channel, "caller": caller, "tls": "1.3", "expected": want, "got": got, "ok": ok})
            print("%s %-80s %-14s want %-5s got %s" % ("ok " if ok else "BAD", channel, caller, want, got), flush=True)
        got = call(port, ca, method, path, ids[tls12_caller], body, tls12=True)
        ok = got == "tls"
        bad += not ok
        results.append({"channel": channel, "caller": tls12_caller, "tls": "1.2", "expected": "tls", "got": got, "ok": ok})
        print("%s %-80s %-14s want %-5s got %s (TLS 1.2 only)" % ("ok " if ok else "BAD", channel, tls12_caller, "tls", got), flush=True)
    json.dump(results, open(out, "w"), indent=1)
    print("%d of %d checks as expected" % (len(results) - bad, len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
