#!/usr/bin/env python3
"""Compare two redirect.sh results.jsonl files case by case, and print the result table of the second.

    compare-redirect.py [--ignore-platform] BEFORE/results.jsonl AFTER/results.jsonl

A case is keyed by (pass, freshness kind, RRP). Its outcome is (issued, HTTP status, refusal reason). The reason is
compared without the Handle- or session-specific values that change from run to run: hex strings of 16 or more digits
and base64url strings of 22 or more characters are replaced by a placeholder. Serials and certificate details are not
compared. --ignore-platform also reads the verifier's submodule named in a reason (SEVSNP, TDX, SIM) as one, to
compare a run on one platform with a run on another (a local run with the software stand-in against a hardware run).
Exit status 0 only when both runs hold the same cases with the same outcomes.
"""

import json
import re
import sys
from pathlib import Path

VOLATILE = re.compile(r"\b[0-9a-f]{16,}\b|[A-Za-z0-9_-]{22,}")
PLATFORM = re.compile(r"\b(SEVSNP|TDX|SIM)\b")
args = [a for a in sys.argv[1:] if a != "--ignore-platform"]
IGNORE_PLATFORM = len(args) != len(sys.argv) - 1


def load(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        r = json.loads(line)
        key = (r["pass"], r["kind"], r["rrp"])
        if key in out:
            sys.exit(f"{path}: duplicate case {key}")
        res = r["result"]
        reason = VOLATILE.sub("<v>", res.get("reason", ""))
        if IGNORE_PLATFORM:
            reason = PLATFORM.sub("<platform>", reason)
        out[key] = (res.get("issued"), res.get("status"), reason)
    return out


before, after = load(args[0]), load(args[1])
diff = 0
for key in sorted(set(before) | set(after)):
    if before.get(key) != after.get(key):
        diff += 1
        print(f"DIFF {key}:\n  before={before.get(key)}\n  after ={after.get(key)}")

kinds = ["present-nonce", "present-epoch", "absent-epoch", "absent-timestamp", "absent-none"]
for p in ("with-rrp-id", "no-rrp-id"):
    for rrp in ("ca1", "ca2"):
        row = ["ISSUED" if after.get((p, k, rrp), (None,))[0] else "refused" for k in kinds]
        print(f"{p:12s} {rrp}: " + "  ".join(f"{k}={v}" for k, v in zip(kinds, row)))
print(f"{len(before)} cases before, {len(after)} after, {diff} differ")
sys.exit(1 if diff else 0)
