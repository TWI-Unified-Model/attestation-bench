#!/usr/bin/env python3
"""Independent character-level check of the TACRA binding in a redirect.sh run (no Go code involved).

    recompute-binding.py EVIDENCE_DIR sev-snp|tdx|sim

For every Enrollment case of both passes, recompute SHA-512 over (len32||freshness element, len32||Target,
len32||RRP identifier, len32||CSR DER) with each candidate identifier: ca1's, ca2's and none. Compare it with the
report's own REPORT_DATA: SEV-SNP report offset 0x50; TDX quote 48+520 (hwcheck/cmd/rrpverify/tdx.go:90); the
software stand-in's report_data inside its COSE_Sign1 payload (platform/simtee.go; the signature is not checked here).
Expected: the with-rrp-id pass matches ca1's identifier only, and the no-rrp-id pass matches no identifier only
(redirect.sh binds "" there). It also checks that hwrun's recorded binding_value_hex is the matching value. Exit
status 0 only when every case is as expected.
"""

import base64
import glob
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

import cbor2

DIR, TEE = sys.argv[1], sys.argv[2]
IDS = {"ca1": "https://ca1.tacra.example", "ca2": "https://ca2.tacra.example", "none": ""}
EXPECT = {"with-rrp-id": "ca1", "no-rrp-id": "none"}


def lp(*parts):
    out = b""
    for p in parts:
        b = p if isinstance(p, bytes) else p.encode()
        out += struct.pack(">I", len(b)) + b
    return out


def report_data(token):
    blob = cbor2.loads(token)["outblob"]
    if TEE == "sim":
        sign1 = cbor2.loads(blob)
        sign1 = sign1.value if hasattr(sign1, "value") else sign1  # COSE_Sign1, tag 18
        return cbor2.loads(sign1[2])["report_data"]
    return blob[0x50 : 0x50 + 64] if TEE == "sev-snp" else blob[48 + 520 : 48 + 584]


bad = 0
for pass_name, want in EXPECT.items():
    cases = sorted(glob.glob(os.path.join(DIR, pass_name, "redir", "enroll-*")))
    if not cases:
        sys.exit(f"no Enrollment cases under {DIR}/{pass_name}/redir")
    for case in cases:
        meta = json.loads(Path(case, "meta.json").read_text())
        e = meta.get("freshness_element_b64", "")
        elem = base64.urlsafe_b64decode(e + "=" * (-len(e) % 4)) if e else b""
        subject = Path(case, "subject.der").read_bytes()
        rd = report_data(Path(case, "evidence.tsm.cbor").read_bytes())
        bvs = {n: hashlib.sha512(lp(elem, meta["target"], i, subject)).digest() for n, i in IDS.items()}
        matches = [n for n, bv in bvs.items() if bv == rd]
        ok = matches == [want] and meta["binding_value_hex"] == bvs[want].hex()
        bad += not ok
        print(
            f"{'ok ' if ok else 'BAD'} {pass_name:12s} {os.path.basename(case):26s} REPORT_DATA matches: "
            f"{','.join(matches) or 'nothing'} (expected {want})"
        )
print(f"{TEE}: {bad} not as expected")
sys.exit(1 if bad else 0)
