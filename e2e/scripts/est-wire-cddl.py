#!/usr/bin/env python3
"""Checks the messages of EST wire logs against a CDDL of the draft's envelopes, with the cddl tool.

A wire log is the EST server's (est-server.json, wire_log; a run keeps its part in bench-logs/est-wire.log): one JSON
object per exchange on an attest-* resource, the request and the response as they crossed the wire. Each message the
CDDL defines is checked against its rule: the attest-initiate response, the attest-enroll and attest-retrieve requests
and the attest-retrieve response. Before that, for the first message of each kind, the check shows that the tool
refuses what it must: the message without a member every message of the kind carries, with a member the CDDL does not
define, and with a byte string in standard base64 instead of unpadded base64url.

    e2e/scripts/est-wire-cddl.py CDDL WIRE_LOG...

The cddl tool is Carsten Bormann's (the Ruby gem `cddl`), found as $CDDL_TOOL or in BENCH_HOME/gems; Ruby 4 no longer
bundles two libraries it needs, so they come with it:

    GEM_HOME="$BENCH_HOME/gems" gem install --no-document cddl:0.12.14 pstore:0.2.1 base64:0.3.0

Prints one line per message and exits 1 unless every message is valid and every altered message refused.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HOME = Path(os.environ.get("BENCH_HOME", str(Path.home() / ".attestation-bench")))

# (method, resource, status or None for any, which body) -> the CDDL rule of that message
RULES = {
    ("GET", "attest-initiate", 200, "response"): "attestation-initiation-response",
    ("POST", "attest-enroll", None, "request"): "attested-enrollment-request",
    ("POST", "attest-retrieve", None, "request"): "attested-retrieval-request",
    ("POST", "attest-retrieve", 200, "response"): "encrypted-credential-bundle",
}
# for the altered messages: a member every message of the kind carries, and byte strings, in the order tried
REQUIRED = ("freshness_kind", "ciphertext")
BYTES = ("evidence", "handle", "ciphertext")


def tool():
    exe = os.environ.get("CDDL_TOOL") or str(HOME / "gems" / "bin" / "cddl")
    env = dict(os.environ, GEM_HOME=str(HOME / "gems"), GEM_PATH=str(HOME / "gems"))
    return exe, env


def validate(spec, rule, message, tmp):
    """The tool's verdict on one message against one rule: (valid, the tool's first line of explanation)."""
    s, m = Path(tmp, "check.cddl"), Path(tmp, "message.json")
    s.write_text(f"start = {rule}\n\n{spec}")
    m.write_text(json.dumps(message))
    exe, env = tool()
    out = subprocess.run([exe, str(s), "validate", str(m)], capture_output=True, text=True, env=env, check=False)
    lines = (out.stderr + out.stdout).splitlines()  # the tool says why on stderr, then its trace on stdout
    why = [line for line in lines if line and not line.startswith("*** Unused rule")]
    return out.returncode == 0, (why[0] if why else "")


def messages(log):
    """Every message of a wire log the rules define: (where, kind, rule, message)."""
    for n, line in enumerate(log.read_text().splitlines(), 1):
        if not line.strip():
            continue
        rec = json.loads(line)
        resource = rec["path"].rsplit("/", 1)[-1]
        for (method, res, status, part), rule in RULES.items():
            if rec["method"] != method or resource != res or (status is not None and rec["status"] != status):
                continue
            body = rec.get(f"{part}_body", "")
            try:
                message = json.loads(body)
            except ValueError:
                yield f"{log}:{n}", f"{resource} {part}", rule, None  # not JSON: invalid as any rule
                continue
            yield f"{log}:{n}", f"{resource} {part}", rule, message


def altered(message):
    """The message three ways it must be refused, each with what was done."""
    for k in REQUIRED:
        if k in message:
            m = dict(message)
            del m[k]
            yield f"without {k}", m
            break
    yield "with a member the CDDL does not define", dict(message, x_not_in_the_cddl="")
    for k in BYTES:
        if isinstance(message.get(k), str) and len(message[k]) >= 4:
            m = dict(message)
            m[k] = m[k][:-2] + "+/"  # characters of standard base64, not of base64url
            yield f"with {k} in standard base64", m
            break


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2:
        print(__doc__.split("\n\n")[1].strip())
        return 2
    spec = Path(argv[0]).read_text()
    bad = valid = refused = 0
    first = set()
    with tempfile.TemporaryDirectory() as tmp:
        for log in map(Path, argv[1:]):
            for where, kind, rule, message in messages(log):
                if message is None:
                    bad += 1
                    print(f"BAD {where} {kind}: not JSON")
                    continue
                ok, why = validate(spec, rule, message, tmp)
                valid += ok
                bad += not ok
                print(f"{'ok ' if ok else 'BAD'} {where} {kind} as {rule}" + ("" if ok else f": {why}"))
                if rule in first or not ok:
                    continue
                first.add(rule)
                for what, m in altered(message):
                    ok2, _ = validate(spec, rule, m, tmp)
                    refused += not ok2
                    bad += ok2
                    print(f"{'ok ' if not ok2 else 'BAD'}   {kind} {what}: {'refused' if not ok2 else 'accepted'}")
    total = valid + bad
    print(f"EST wire CDDL: {valid} messages valid, {refused} altered messages refused, {bad} not as expected"
          if total else "EST wire CDDL: no message in the wire log")  # fmt: skip
    return 1 if bad or not total else 0


if __name__ == "__main__":
    sys.exit(main())
