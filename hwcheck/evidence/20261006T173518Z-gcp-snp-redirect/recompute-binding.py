#!/usr/bin/env python3
# Independent character-level check (no Go): the SEV-SNP report's REPORT_DATA is SHA-512 of the TACRA binding input
# (len32||handle, len32||target, len32||rrp_id, len32||subject) with ca1's identifier, and differs with ca2's. This is
# why a second CA refuses: it recomputes the binding with its own identifier and the Verifier's nonce no longer matches.
#   python3 recompute-binding.py
import json, hashlib, struct, base64, cbor2, os
HERE = os.path.dirname(os.path.abspath(__file__))
def lp(*parts):
    out = b""
    for p in parts:
        b = p if isinstance(p, bytes) else p.encode()
        out += struct.pack(">I", len(b)) + b
    return out
case = os.path.join(HERE, "with-rrp-id", "redir", "enroll-present-epoch")
meta = json.load(open(os.path.join(case, "meta.json")))
subject = open(os.path.join(case, "subject.der"), "rb").read()
elem = base64.urlsafe_b64decode(meta["freshness_element_b64"] + "=" * (-len(meta["freshness_element_b64"]) % 4))
report = cbor2.loads(open(os.path.join(case, "evidence.tsm.cbor"), "rb").read())["outblob"]
report_data = report[0x50:0x50 + 64]
for name, rrpid in [("ca1", "https://ca1.tacra.example"), ("ca2", "https://ca2.tacra.example")]:
    bv = hashlib.sha512(lp(elem, meta["target"], rrpid, subject)).digest()
    print(f"binding with {name}: {'MATCHES REPORT_DATA' if bv == report_data else 'differs from REPORT_DATA'}")
