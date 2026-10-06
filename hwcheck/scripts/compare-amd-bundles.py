#!/usr/bin/env python3
"""Compare AMD product bundles embedded in go-sev-guest v0.15.0: per product line, is the ARK in the VCEK bundle the
same certificate (DER bytes) as the ARK in the VLEK bundle; and is the embedded Milan VLEK bundle the same as the one
fetched from AMD KDS into the bench evidence. Prints subject CNs and SHA-256 of each DER certificate."""

import hashlib
import os
import re
import ssl
import subprocess
import sys
from pathlib import Path

trust = sys.argv[1]
kds_file = sys.argv[2]

PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----", re.DOTALL)


def ders(path):
    data = Path(path).read_bytes()
    return [ssl.PEM_cert_to_DER_cert(m.group(0).decode()) for m in PEM_RE.finditer(data)], data


def cn(der):
    out = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-nameopt", "multiline"],
        input=der,
        capture_output=True,
        check=True,
    ).stdout.decode()
    m = re.search(r"commonName\s*=\s*(\S+)", out)
    return m.group(1) if m else "?"


def show(label, path):
    certs, raw = ders(path)
    print(f"{label}: {os.path.basename(path)} bytes={len(raw)} certs={len(certs)} tail={raw[-4:]!r}")
    for d in certs:
        print(f"   {cn(d):16s} sha256(DER)={hashlib.sha256(d).hexdigest()}")
    return certs


for line, vcek, vlek in (
    ("Milan", "ask_ark_milan.pem", "ask_ark_milan_vlek.pem"),
    ("Genoa", "ask_ark_genoa.pem", "ask_ark_genoa_vlek.pem"),
    ("Turin", "ask_ark_turin_vcek.pem", "ask_ark_turin_vlek.pem"),
):
    a = show(f"{line} VCEK", os.path.join(trust, vcek))
    b = show(f"{line} VLEK", os.path.join(trust, vlek))
    print(f"   => {line}: ARK in VCEK bundle == ARK in VLEK bundle: {a[1] == b[1]}")

k = show("AMD KDS Milan VLEK (bench)", kds_file)
e, _ = ders(os.path.join(trust, "ask_ark_milan_vlek.pem"))
print(f"   => KDS Milan VLEK == embedded Milan VLEK (all certs, DER): {k == e}")
