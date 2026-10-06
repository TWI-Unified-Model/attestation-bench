#!/usr/bin/env python3
"""Compare two bench-mtls-check.py results files check by check.

    compare-mtls.py BEFORE/mtls.json AFTER/mtls.json

A check is keyed by (channel, caller, TLS version): each channel is tried at TLS 1.3 and at TLS 1.2. Its outcome is
(expected, got, ok). Prints every check whose outcome differs or that is in only one file, then a summary. Exit status
0 only when both files hold the same checks with the same outcomes.
"""
import json
import sys


def load(path):
    out = {}
    for r in json.load(open(path)):
        key = (r["channel"], r["caller"], r["tls"])
        if key in out:
            sys.exit(f"{path}: duplicate check {key}")
        out[key] = (r["expected"], r["got"], r["ok"])
    return out


before, after = load(sys.argv[1]), load(sys.argv[2])
diff = 0
for key in sorted(set(before) | set(after), key=str):
    if before.get(key) != after.get(key):
        diff += 1
        print(f"DIFF {key}: before={before.get(key)} after={after.get(key)}")
print(f"{len(before)} checks before, {len(after)} after, {diff} differ")
sys.exit(1 if diff else 0)
