#!/usr/bin/env python3
"""The EST server's wire format, on the running bench (scripts/test-live.sh, make test-live).

For each of attest-enroll and attest-retrieve, as the wire format proposed for draft-novak-lamps-tacra-est in October
2026 defines it (its CDDL: e2e/est-attest.cddl):

- attest-initiate answers its own media type, application/est-attest-initiate+json, with the members the CDDL gives a
  present-nonce Target of the mode and no others (no rrp_id), the Handle as unpadded base64url;
- the resource takes its own media type only: application/json, text/plain and the other resource's type are refused
  with 415 and an Accept header naming its type;
- a request that is not of the CDDL's syntax is refused with 400, saying why: with a member the CDDL does not define
  (endorsements), sent twice in one body, with a member twice, with a byte string in standard base64;
- none of these refusals uses up the Handle: the request as sent, under the resource's type and a CA label, reaches the
  RRP, and the same Handle again is refused with 409;
- Evidence of a format the server does not accept is refused with 415 before the Handle is correlated: a new Handle
  then still serves the request.

The server's wire log (est-server.json, wire_log) holds each of these exchanges as it was sent and answered, octet for
octet.

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
INITIATE = "application/est-attest-initiate+json"
B64URL = re.compile(r"[A-Za-z0-9_-]*")

# mode, Target (present-nonce), credential type, the run's case, the request's subject field, the resource's own media
# type, the other resource's, the RRP the Target names, the algorithms member of the mode's attest-initiate response
RESOURCES = [
    ("enroll", "https://db-nonce.tacra.example", "x509", "enroll-present-nonce", "csr",
     "application/est-attest-enroll+json", "application/est-attest-retrieve+json", "RRP ca", "acceptable_csk"),
    ("retrieve", "https://ledger-nonce.tacra.example", "api-key", "retrieve-present-nonce", "cek_pub",
     "application/est-attest-retrieve+json", "application/est-attest-enroll+json", "RRP vault", "acceptable_cek"),
]  # fmt: skip
LABEL = "/arbitraryLabel1"  # a CA label (RFC 7030, Section 3.2.2), RFC 7030's own example


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def is_b64u(text):
    """Whether text is unpadded base64url as the CDDL control .b64u takes it (RFC 9741, Section 2.1): the alphabet, no
    padding, a length that encodes whole octets, and the bits after the last octet zero (it encodes back the same)."""
    if not B64URL.fullmatch(text) or len(text) % 4 == 1:
        return False
    return b64u(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))) == text


def media_type(header):
    return header.split(";", 1)[0].strip().lower()


class EST:
    """The bench's EST server, over TLS 1.3 under the bench's TLS root, as a workload reaches it."""

    def __init__(self, home):
        cfg = json.loads(Path(home, "config", "est-server.json").read_text())
        host, port = cfg["tls"]["listen_address"].rsplit(":", 1)
        self.host, self.port = host, int(port)
        self.ctx = ssl.create_default_context(cafile=str(Path(home, "tls", "root.crt")))
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.wire_log = Path(cfg["wire_log"]) if cfg.get("wire_log") else None
        self.exchanges = []  # every exchange as this check sent it and the server answered it, in order

    def call(self, method, path, body=None, ctype=None):
        """One exchange: (status, Content-Type, Accept, body)."""
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=120)
        try:
            conn.request(method, "/.well-known/est" + path, body=body, headers={"Content-Type": ctype} if ctype else {})
            resp = conn.getresponse()
            raw = resp.read()
            where, _, query = ("/.well-known/est" + path).partition("?")
            self.exchanges.append({"method": method, "path": where, "query": query,
                                   "request_content_type": ctype or "", "request_body": (body or b"").decode(),
                                   "status": resp.status, "response_content_type": resp.getheader("Content-Type", ""),
                                   "response_body": raw.decode()})  # fmt: skip
            return (resp.status, resp.getheader("Content-Type", ""), resp.getheader("Accept", ""),
                    raw.decode(errors="replace").strip())  # fmt: skip
        finally:
            conn.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--home", default=os.environ.get("BENCH_HOME", str(Path.home() / ".attestation-bench")))
    ap.add_argument("--run", type=Path, default=RUN, help="the committed hardware run whose Evidence is sent")
    a = ap.parse_args(argv)
    est = EST(a.home)
    bad = 0
    if est.wire_log is None or not est.wire_log.is_file():
        print(f"BAD the EST server keeps no wire log ({est.wire_log}): make config, then make stop start")
        return 1
    wire_from = est.wire_log.stat().st_size

    def check(name, ok, got):
        nonlocal bad
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {name}: {got}")

    def answer(st, body, n=140):  # the server's error bodies begin with their status
        return body[:n] if body.startswith(str(st)) else f"{st} {body[:n]}"

    for mode, target, ctype_, case, field, own, other, rrp, algorithms in RESOURCES:
        resource = f"/attest-{mode}"
        members = {"freshness_kind", "handle", "expires_in", "mode", "acceptable_evidence", algorithms}

        st, ct, _, body = est.call(
            "GET", "/attest-initiate?" + urlencode({"target": target, "credential_type": ctype_})
        )
        name = f"attest-initiate {target}"
        try:
            init = json.loads(body)
            handle = init["handle"]
            octets = len(base64.urlsafe_b64decode(handle + "=" * (-len(handle) % 4)))
        except (ValueError, KeyError, TypeError, binascii.Error) as e:
            check(name, False, f"{st} {ct}: {body[:160]} ({e!r})")
            continue
        ok = (st == 200 and media_type(ct) == INITIATE and set(init) == members and init["mode"] == mode
              and init["freshness_kind"] == "present-nonce" and isinstance(handle, str) and is_b64u(handle))  # fmt: skip
        check(name, ok, f"{st} {ct}, members {', '.join(sorted(init))}; Handle {len(handle)} characters of unpadded "
                        f"base64url, {octets} octets")  # fmt: skip

        evidence = (a.run / case / "evidence.tsm.cbor").read_bytes()
        subject = (a.run / case / "subject.der").read_bytes()
        req = {"target": target, "credential_type": ctype_, "freshness_kind": "present-nonce", "handle": handle,
               field: b64u(subject), "evidence": b64u(evidence),
               "binding": {"method": "binding-input", "hash": "sha512"}, "profile": PROFILE}  # fmt: skip
        sent = json.dumps(req).encode()

        for wrong in ("application/json", "text/plain", other):
            st, _, accept, body = est.call("POST", resource, sent, wrong)
            want = f"415 Content-Type must be {own}"
            check(f"{resource} as {wrong}", st == 415 and body == want and accept == own,
                  f"{answer(st, body)}; Accept {accept or '(none)'}")  # fmt: skip

        std = req["evidence"][:-2] + "+/"  # characters of standard base64, not of base64url
        for what, altered, why in (
            ("with endorsements", json.dumps(dict(req, endorsements="AAAA")).encode(),
             'member "endorsements" is not defined'),
            ("twice in one body", sent + sent, "data after the JSON object"),
            ("with a member twice", b'{"target":"https://other.tacra.example",' + sent[1:],
             'member "target" appears more than once'),
            ("with evidence in standard base64", json.dumps(dict(req, evidence=std)).encode(),
             'member "evidence" is not unpadded base64url (RFC 4648, Section 5)'),
        ):  # fmt: skip
            st, _, _, body = est.call("POST", resource, altered, own)
            check(f"{resource} {what}", st == 400 and body == f"400 malformed request: {why}", answer(st, body))

        st, _, _, body = est.call("POST", LABEL + resource, sent, own)
        check(f"{LABEL}{resource} as {own}, the Handle the refusals left unused",
              st == 403 and body.startswith(f"403 {rrp}: attestation:"), answer(st, body))  # fmt: skip
        st, _, _, body = est.call("POST", resource, sent, own)
        check(f"{resource}, the same Handle again", st == 409, answer(st, body))

        # an Evidence format the server does not accept: 415, before the Handle is correlated, so a new Handle stays
        # usable for the request that follows
        st, _, _, body = est.call("GET", "/attest-initiate?" + urlencode({"target": target, "credential_type": ctype_}))
        try:
            fresh = json.loads(body)["handle"]
        except (ValueError, KeyError, TypeError) as e:
            check(f"attest-initiate {target}, a second Handle", False, f"{st}: {body[:160]} ({e!r})")
            continue
        unknown = "application/vnd.example.unknown"
        retry = dict(req, handle=fresh)
        st, _, _, body = est.call("POST", resource, json.dumps(dict(retry, profile=unknown)).encode(), own)
        check(f"{resource} with Evidence of a format not accepted",
              st == 415 and body == f'415 Evidence format "{unknown}" is not accepted', answer(st, body))  # fmt: skip
        st, _, _, body = est.call("POST", resource, json.dumps(retry).encode(), own)
        check(f"{resource}, the Handle the 415 left unused",
              st == 403 and body.startswith(f"403 {rrp}: attestation:"), answer(st, body))  # fmt: skip

    with est.wire_log.open("rb") as f:
        f.seek(wire_from)
        recorded = [json.loads(line) for line in f.read().splitlines() if line.strip()]
    fields = ("method", "path", "query", "request_content_type", "request_body", "status", "response_content_type",
              "response_body")  # fmt: skip
    seen = [{k: r.get(k, 0 if k == "status" else "") for k in fields} for r in recorded]
    differ = [i for i, (s, e) in enumerate(zip(seen, est.exchanges)) if s != e]
    check("the wire log", len(seen) == len(est.exchanges) and not differ,
          f"{len(seen)} exchanges recorded, {len(est.exchanges)} made"
          + (f"; first difference at exchange {differ[0] + 1}" if differ else "; each as sent and answered"))  # fmt: skip

    print(f"EST wire format: {'every check as expected' if not bad else f'{bad} checks not as expected'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
