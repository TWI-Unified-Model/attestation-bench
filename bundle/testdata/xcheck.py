"""Cross-implementation check of the hpke-auth bundle against the reference implementation (tacra-est/impl).

    xcheck.py make OUT.json     the reference Secret Vault seals a bundle to a fresh X25519 CEK
    xcheck.py make-nohint OUT   the same without a Credential Hint
    xcheck.py open IN.json      the reference Attester opens a bundle made elsewhere; prints the content

Run with the tacra-est virtual environment; TACRA_EST_IMPL points at tacra-est/impl.
"""
import json, os, sys

sys.path.insert(0, os.environ.get("TACRA_EST_IMPL", os.path.expanduser("~/dev/tacra-est/impl")))
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: E402
from common import b64u, b64u_dec  # noqa: E402
from est_server import SecretVault  # noqa: E402
from attester import Attester  # noqa: E402

RRP, TARGET, HINT = "https://vault1.tacra.example", "https://ledger.tacra.example", "workload.tacra.example"
HANDLE = bytes(range(32))


def make(path, hint=HINT):
    vault = SecretVault(rrp_id=RRP)
    cek = x25519.X25519PrivateKey.generate()
    spki = cek.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    results = {"measurement": "ab" * 48, "platform": "sev-snp"}
    b = vault.release(spki, results, HANDLE, TARGET, hint)
    json.dump({"cek_x25519": b64u(cek.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                    serialization.NoEncryption())),
               "vault_spki": b64u(vault.origin_spki_der()), "rrp_id": RRP, "target": TARGET,
               "handle": b64u(HANDLE), "credential_hint": hint or "", "bundle": b}, open(path, "w"), indent=1)


def open_(path):
    f = json.load(open(path))
    a = Attester(tee=None, target=f["target"], credential_type="x509", vault_origin_spki_der=b64u_dec(f["vault_spki"]))
    a.bound_rrp_id, a.handle = f["rrp_id"], b64u_dec(f["handle"])
    a.credential_hint = f.get("credential_hint")
    a.cek = x25519.X25519PrivateKey.from_private_bytes(b64u_dec(f["cek_x25519"]))
    print(json.dumps(a.accept_bundle(f["bundle"]), sort_keys=True))


if __name__ == "__main__":
    {"make": make, "make-nohint": lambda p: make(p, None), "open": open_}[sys.argv[1]](sys.argv[2])
