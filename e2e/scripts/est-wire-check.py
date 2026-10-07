#!/usr/bin/env python3
"""The EST server's wire format, on the running bench (scripts/test-live.sh, make test-live).

For each attest-* resource: attest-initiate answers JSON with the Handle as unpadded base64url; the resource takes its
own media type (the reference implementation's) and application/json, and answers 415 to any other, the other
resource's included, without using up the Handle; a Handle serves one request only.

Every request carries real Evidence and a real CSR or CEKpub: those of the honest present-nonce cases of a committed
Google Cloud SEV-SNP hardware run. That Evidence is bound to the Handle of its own run, so on a fresh Handle the
verifier finds another binding value and the RRP refuses it: a request the server takes ends in the RRP's 403.

    e2e/scripts/est-wire-check.py [--home BENCH_HOME] [--run hwcheck/evidence/<run>]

Prints one line per check and exits 1 unless every check came out as expected.
"""

import argparse
import base64
import binascii
import http.client
import json
import os
import re
import ssl
import sys
from pathlib import Path
from urllib.parse import urlencode

REPO = Path(__file__).resolve().parents[2]
RUN = REPO / "hwcheck" / "evidence" / "20261007T134801Z-gcp-sev-snp"
PROFILE = "application/vnd.veraison.tsm-report+cbor"  # the media type of the Evidence the bench's RRPs take
B64URL = re.compile(r"[A-Za-z0-9_-]+")

# mode, Target (present-nonce), credential type, the run's case, the request's subject field, the resource's own media
# type, the other resource's, the RRP the Target names
RESOURCES = [
    ("enroll", "https://db-nonce.tacra.example", "x509", "enroll-present-nonce", "csr",
     "application/est-attest-enroll+json", "application/est-attest-retrieve+json", "RRP ca"),
    ("retrieve", "https://ledger-nonce.tacra.example", "api-key", "retrieve-present-nonce", "cek_pub",
     "application/est-attest-retrieve+json", "application/est-attest-enroll+json", "RRP vault"),
]  # fmt: skip


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class EST:
    """The bench's EST server, over TLS 1.3 under the bench's TLS root, as a workload reaches it."""

    def __init__(self, home):
        cfg = json.loads(Path(home, "config", "est-server.json").read_text())
        host, port = cfg["tls"]["listen_address"].rsplit(":", 1)
        self.host, self.port = host, int(port)
        self.ctx = ssl.create_default_context(cafile=str(Path(home, "tls", "root.crt")))
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    def call(self, method, path, body=None, ctype=None):
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=120)
        try:
            conn.request(method, "/.well-known/est" + path, body=body, headers={"Content-Type": ctype} if ctype else {})
            resp = conn.getresponse()
            return resp.status, resp.getheader("Content-Type", ""), resp.read().decode(errors="replace").strip()
        finally:
            conn.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--home", default=os.environ.get("BENCH_HOME", str(Path.home() / ".attestation-bench")))
    ap.add_argument("--run", type=Path, default=RUN, help="the committed hardware run whose Evidence is sent")
    a = ap.parse_args(argv)
    est = EST(a.home)
    bad = 0

    def check(name, ok, got):
        nonlocal bad
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {name}: {got}")

    def answer(st, body, n=140):  # the server's error bodies begin with their status
        return body[:n] if body.startswith(str(st)) else f"{st} {body[:n]}"

    for mode, target, ctype_, case, field, own, other, rrp in RESOURCES:
        resource = f"/attest-{mode}"

        def initiate(mode=mode, target=target, ctype_=ctype_):
            st, ct, body = est.call(
                "GET", "/attest-initiate?" + urlencode({"target": target, "credential_type": ctype_})
            )
            name = f"attest-initiate {target}"
            try:
                answer = json.loads(body)
                handle = answer["handle"]
                octets = len(base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4)))
            except (ValueError, KeyError, TypeError, binascii.Error) as e:
                check(name, False, f"{st} {ct}: {body[:160]} ({e!r})")
                return None
            ok = (st == 200 and ct.startswith("application/json") and answer.get("mode") == mode
                  and answer.get("freshness_kind") == "present-nonce" and B64URL.fullmatch(handle) is not None
                  and len(handle) % 4 != 1)  # fmt: skip
            check(name, ok, f"{st}, mode {answer.get('mode')}, Handle {len(handle)} characters of unpadded "
                            f"base64url, {octets} octets")  # fmt: skip
            return handle

        def request(handle, case=case, field=field, target=target, ctype_=ctype_):
            evidence = (a.run / case / "evidence.tsm.cbor").read_bytes()
            subject = (a.run / case / "subject.der").read_bytes()
            return json.dumps({"target": target, "credential_type": ctype_, "freshness_kind": "present-nonce",
                               "handle": handle, field: b64u(subject), "evidence": b64u(evidence),
                               "binding": {"method": "binding-input", "hash": "sha512"},
                               "profile": PROFILE}).encode()  # fmt: skip

        def refused_by_rrp(st, body, rrp=rrp):
            return st == 403 and body.startswith(f"403 {rrp}: attestation:")

        handle = initiate()
        if handle is None:
            continue
        for wrong in ("text/plain", other):
            st, _, body = est.call("POST", resource, request(handle), wrong)
            check(f"{resource} as {wrong}", st == 415, answer(st, body))
        st, _, body = est.call("POST", resource, request(handle), own)
        check(f"{resource} as {own}, the Handle the 415s left unused", refused_by_rrp(st, body), answer(st, body))
        st, _, body = est.call("POST", resource, request(handle), own)
        check(f"{resource}, the same Handle again", st == 409, answer(st, body))
        handle = initiate()
        if handle is None:
            continue
        st, _, body = est.call("POST", resource, request(handle), "application/json")
        check(f"{resource} as application/json, a new Handle", refused_by_rrp(st, body), answer(st, body))

    print(f"EST wire format: {'every check as expected' if not bad else f'{bad} checks not as expected'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
