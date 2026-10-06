#!/usr/bin/env python3
"""Compare two e2e results.json files Target by Target.

    compare-e2e.py BEFORE/results.json AFTER/results.json

A Target's outcome is (credential type, ok, attempts, relying-party status, the names certified, the issuer). Serials,
timings and expiry differ by nature and are not compared. Prints every Target whose outcome differs or that is in only
one file, then a summary. Exit status 0 only when both runs hold the same Targets with the same outcomes.
"""

import json
import sys
from pathlib import Path

FIELDS = ("type", "ok", "attempts", "rup_status", "cert_names", "cert_issuer")


def load(path):
    out = {}
    for r in json.loads(Path(path).read_text()):
        if r["target"] in out:
            sys.exit(f"{path}: Target {r['target']} twice")
        out[r["target"]] = tuple(r.get(f) for f in FIELDS)
    return out


before, after = load(sys.argv[1]), load(sys.argv[2])
diff = 0
for t in sorted(set(before) | set(after)):
    if before.get(t) != after.get(t):
        diff += 1
        print(f"DIFF {t}: before={before.get(t)} after={after.get(t)}")
ok = sum(1 for v in after.values() if v[1])
print(f"{len(before)} Targets before, {len(after)} after ({ok} ok), {diff} differ")
sys.exit(1 if diff else 0)
