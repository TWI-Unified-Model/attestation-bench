#!/usr/bin/env python3
"""Compare two rrpverify results files check by check.

    compare-rrpverify.py BEFORE.json AFTER.json

A check is keyed by (case, certificate_table, check); its outcome is (want, got, ok, ear_status). Prints every check
whose outcome differs, every check present in only one file, and a one-line summary. Exit status 0 only when both
files hold the same checks with the same outcomes. Timings (ms) and error texts are not compared.
"""
import json
import sys


def load(path):
    doc = json.load(open(path))
    out = {}
    for r in doc["results"]:
        key = (r.get("case"), r.get("certificate_table"), r.get("check"))
        if key in out:
            sys.exit(f"{path}: duplicate check {key}")
        out[key] = (r.get("want"), r.get("got"), r.get("ok"), r.get("ear_status"))
    return out


before, after = load(sys.argv[1]), load(sys.argv[2])
diff = 0
for key in sorted(set(before) | set(after), key=str):
    b, a = before.get(key), after.get(key)
    if b != a:
        diff += 1
        print(f"DIFF {key}: before={b} after={a}")
print(f"{len(before)} checks before, {len(after)} after, {diff} differ")
sys.exit(1 if diff else 0)
