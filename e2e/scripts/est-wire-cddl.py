#!/usr/bin/env python3
"""Checks the messages of EST wire logs against the CDDL of the attest-* wire, with the cddl tool, and their media types.

A wire log is the log of the EST Server (est-server.json, wire_log). A run keeps its part of that log in
bench-logs/est-wire.log. The log holds one JSON object for each exchange on an attest-* resource: the request and the
response as they crossed the wire.

The CDDL is e2e/est-attest.cddl. It holds:

- the CDDL of the EST profile;
- the container of TACRA;
- the container with the origin member that the Secret Vault of the bench adds when it signs.

Each of these messages is checked against its CDDL rule:

- the attest-initiate response;
- the attest-enroll request;
- the attest-retrieve request;
- the attest-retrieve response.

The media type of every message is checked:

- application/est-attest-initiate+json for the attest-initiate response;
- application/est-attest-enroll+json for the attest-enroll request;
- application/est-attest-retrieve+json for the attest-retrieve request;
- application/est-attest-bundle+json for the attest-retrieve response;
- application/pkcs7-mime for the attest-enroll response, which is the certificate of an Enrollment;
- text/plain for a refusal.

The check also shows that the cddl tool refuses what the CDDL must refuse. It alters the first message of each kind
(each rule, Freshness Kind and mode) in the ways below, and expects the tool to refuse every altered message:

- the message without freshness_kind;
- the message with a member that the CDDL does not define;
- the message with a byte string in standard base64;
- the message without a Handle, under a Freshness Kind that has one;
- the message with a Handle, under a Freshness Kind that has none;
- an attest-initiate response with a Handle shorter than the CDDL allows;
- an attest-initiate response of one mode with the algorithms of the other mode;
- a container whose origin member has no signature;
- a container whose origin member names another algorithm;
- a container with another label;
- a container whose suite has no KEM;
- a container whose suite has a member that the CDDL does not define;
- a container whose associated data have no Target.

The names in the suite of a container are open text in the CDDL. TACRA names the mandatory suite and allows others,
so the Attester, not the grammar, refuses a suite with another name.

    e2e/scripts/est-wire-cddl.py [--cddl CDDL] WIRE_LOG...

Use the wire log of an end-to-end run: every request in that log is as the Workload sent it. Do not use the wire log
of make test-live: that test sends requests that the EST Server must refuse.

The cddl tool is the Ruby gem `cddl` by Carsten Bormann. The check runs the program that $CDDL_TOOL names, or
BENCH_HOME/gems/bin/cddl. Ruby 4 does not bundle two libraries that the gem needs, so this command installs them with
the gem:

    GEM_HOME="$BENCH_HOME/gems" gem install --no-document cddl:0.12.14 pstore:0.2.1 base64:0.3.0

The check prints one line for each message and one line for each altered message. Its exit status is 1 unless every
message is valid, every message has the media type of its place, and every altered message is refused.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HOME = Path(os.environ.get("BENCH_HOME", str(Path.home() / ".attestation-bench")))
CDDL = Path(__file__).resolve().parents[1] / "est-attest.cddl"

# (method, resource, which body) -> the CDDL rule of that message; a response only when its status is 200
RULES = {
    ("GET", "attest-initiate", "response"): "attestation-initiation-response",
    ("POST", "attest-enroll", "request"): "attested-enrollment-request",
    ("POST", "attest-retrieve", "request"): "attested-retrieval-request",
    ("POST", "attest-retrieve", "response"): "attest-retrieve-response",
}
BUNDLE = "attest-retrieve-response"
# (method, resource, which body) -> the media type of the request, or of the response when its status is 200; any
# other response is a refusal, in text/plain
TYPES = {
    ("POST", "attest-enroll", "request"): "application/est-attest-enroll+json",
    ("POST", "attest-retrieve", "request"): "application/est-attest-retrieve+json",
    ("GET", "attest-initiate", "response"): "application/est-attest-initiate+json",
    ("POST", "attest-enroll", "response"): "application/pkcs7-mime",
    ("POST", "attest-retrieve", "response"): "application/est-attest-bundle+json",
}
PRESENT = ("present-nonce", "present-epoch")


def tool():
    exe = os.environ.get("CDDL_TOOL") or str(HOME / "gems" / "bin" / "cddl")
    env = dict(os.environ, GEM_HOME=str(HOME / "gems"), GEM_PATH=str(HOME / "gems"))
    return exe, env


def validate(spec, start, instance, tmp):
    """The tool's verdict on an instance against a start rule: (valid, the tool's first line of explanation)."""
    s, m = Path(tmp, "check.cddl"), Path(tmp, "message.json")
    s.write_text(f"start = {start}\n\n{spec}")
    m.write_text(json.dumps(instance))
    exe, env = tool()
    out = subprocess.run([exe, str(s), "validate", str(m)], capture_output=True, text=True, env=env, check=False)
    lines = (out.stderr + out.stdout).splitlines()  # the tool says why on stderr, then its trace on stdout
    why = [line for line in lines if line and not line.startswith("*** Unused rule")]
    return out.returncode == 0, (why[0][:300] if why else "")


def media_type(header):
    return header.split(";", 1)[0].strip().lower()


def messages(log):
    """Every message of a wire log: (where, what it is, its media type, the media type of its place, its CDDL rule or
    None, its body). attest-initiate's request, a GET without a body, is not one."""
    for n, line in enumerate(log.read_text().splitlines(), 1):
        if not line.strip():
            continue
        rec = json.loads(line)
        resource, method, status = rec["path"].rsplit("/", 1)[-1], rec["method"], rec["status"]
        for part in ("request", "response"):
            ctype = rec.get(f"{part}_content_type", "")
            body = rec.get(f"{part}_body", "") or rec.get(f"{part}_body_base64", "")
            if part == "request" and method == "GET":
                continue
            ok_response = part == "request" or status == 200
            want = TYPES.get((method, resource, part)) if ok_response else "text/plain"
            rule = RULES.get((method, resource, part)) if ok_response else None
            what = f"{resource} {part}" + (f" {status}" if part == "response" else "")
            yield f"{log}:{n}", what, ctype, want, rule, body


def altered(rule, message):
    """The message, altered in each way the CDDL must refuse for its rule, kind and mode: (what was done, message)."""
    if rule == BUNDLE:
        origin = message.get("origin") or {
            "alg": "ECDSA-P256-SHA256",
            "signature": "AAAA",
        }  # one of the container's own, or made up
        yield "origin without its signature", dict(message, origin={"alg": origin["alg"]})
        yield "origin of another algorithm", dict(message, origin=dict(origin, alg="ECDSA-P384-SHA384"))
        yield "container relabelled", dict(message, container="hpke-base-signed")
        yield "suite without its kem", dict(message, suite={k: v for k, v in message["suite"].items() if k != "kem"})
        yield (
            "suite with sig, which the CDDL does not define",
            dict(message, suite=dict(message["suite"], sig="ECDSA-P256-SHA256")),
        )
        aad = dict(message["aad"])
        del aad["target"]
        yield "aad without target", dict(message, aad=aad)
        yield "with server_id, which the CDDL does not define", dict(message, server_id="est.tacra.example")
        yield "with enc in standard base64", dict(message, enc=message["enc"][:-2] + "+/")
        return
    kind = message.get("freshness_kind")
    m = dict(message)
    del m["freshness_kind"]
    yield "without freshness_kind", m
    name, value = (
        ("rrp_id", "https://ca1.tacra.example") if rule.startswith("attestation-") else ("endorsements", "AAAA")
    )
    yield f"with {name}, which the CDDL does not define", dict(message, **{name: value})
    for k in ("evidence", "handle"):
        if isinstance(message.get(k), str) and len(message[k]) >= 4:
            # the characters + and / are not in the alphabet of base64url
            yield f"with {k} in standard base64", dict(message, **{k: message[k][:-2] + "+/"})
            break
    has_handle = kind in PRESENT if rule.startswith("attestation-") else kind != "absent-none"
    if has_handle:
        m = dict(message)
        m.pop("handle", None)
        yield "without a handle", m
        if rule.startswith("attestation-"):
            yield "with a 4-octet handle, under the 8 the profile sets", dict(message, handle="AAAAAA")
    else:
        yield "with a handle", dict(message, handle="AAAAAAAAAAA")
    if rule.startswith("attestation-"):
        other = "acceptable_cek" if message.get("mode") == "enroll" else "acceptable_csk"
        yield f"with {other}", dict(message, **{other: ["x"]})


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cddl", type=Path, default=CDDL, help="the CDDL (default: e2e/est-attest.cddl)")
    ap.add_argument("logs", type=Path, nargs="+", metavar="WIRE_LOG")
    a = ap.parse_args(argv)
    spec = a.cddl.read_text()
    found = [m for log in a.logs for m in messages(log)]
    if not found:
        print("EST wire CDDL: no message in the wire log")
        return 1
    bad = valid = typed = refused = 0
    verdicts = {}  # (where, what) -> (valid, why)
    firsts = {}  # (rule, Freshness Kind, mode) -> (what, the first valid message of that kind)
    with tempfile.TemporaryDirectory() as tmp:
        for rule in RULES.values():
            items = []
            for where, what, _, _, r, body in found:
                if r != rule:
                    continue
                try:
                    message = json.loads(body)
                except ValueError:
                    message = None
                items.append((where, what, message))
            objects = [m for _, _, m in items if isinstance(m, dict)]
            # every message of the rule at once, as an array of them; one by one only if that fails
            all_ok = bool(objects) and validate(spec, f"[* {rule}]", objects, tmp)[0]
            for where, what, message in items:
                if not isinstance(message, dict):
                    verdicts[(where, what)] = (False, "not a JSON object")
                    continue
                verdicts[(where, what)] = (True, "") if all_ok else validate(spec, rule, message, tmp)
                if verdicts[(where, what)][0]:
                    firsts.setdefault((rule, message.get("freshness_kind"), message.get("mode")), (what, message))
        for where, what, ctype, want, rule, _ in found:
            ok, why = verdicts[(where, what)] if rule else (True, "")
            type_ok = media_type(ctype) == want
            valid += bool(rule) and ok
            typed += type_ok
            bad += not (ok and type_ok)
            note = f" as {rule}" if rule else ""
            print(f"{'ok ' if ok and type_ok else 'BAD'} {where} {what}{note}, {media_type(ctype) or 'no media type'}"
                  + ("" if ok else f": {why}") + ("" if type_ok else f", not {want}"))  # fmt: skip
        for (rule, kind, mode), (what, message) in firsts.items():
            for how, m in altered(rule, message):
                ok, _ = validate(spec, rule, m, tmp)
                refused += not ok
                bad += ok
                print(f"{'ok ' if not ok else 'BAD'}   {what}, {kind}{' ' + mode if mode else ''}, {how}: "
                      f"{'refused' if not ok else 'accepted'}")  # fmt: skip
    print(f"EST wire CDDL: {valid} messages valid, {typed} of {len(found)} with their place's media type, "
          f"{refused} altered messages refused, {bad} not as expected")  # fmt: skip
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
