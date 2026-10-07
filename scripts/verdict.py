#!/usr/bin/env python3
"""Says whether a run came out as its experiment expects.

    python3 scripts/verdict.py demo RUN_DIR [--expect admitted|refused] [--reason TEXT] [--cause TEXT] [--out FILE]
    python3 scripts/verdict.py attacks RUN_DIR [--out FILE]
    python3 scripts/verdict.py redirect RUN_DIR [--out FILE]
    python3 scripts/verdict.py bank-pay RUN_DIR --expect pay|ordinary|unapproved [--out FILE]
    python3 scripts/verdict.py mtls RUN_DIR [--out FILE]

Every run script calls it before it seals its run directory, with --out RUN_DIR/verdict.txt. It prints what the run
did and a last line, "VERDICT PASS: ..." or "VERDICT FAIL: ...", writes the same to FILE if given, and exits 1 on
FAIL. It reads nothing but the run directory, so it judges any earlier run as well, those under e2e/evidence and
hwcheck/evidence included.

  demo      results.json. admitted (the default): every Target's credential acquired and admitted by the RATS-unaware
            Relying Party. refused: no credential issued for any Target, and each refusal's error contains the
            --reason TEXT; with --cause, every appraisal the stand-in's verifier logged in the run
            (bench-logs/sim-verifier.log) gives that cause.
  attacks   rrpverify-*.json. Every check as expected: the honest Evidence passed, each attack refused for its own
            reason. The builds of Veraison the bench compares with (rrpverify-veraison-fork and -fixed) are reported,
            not judged: what they get wrong is the reason the bench runs its own build.
  redirect  results.jsonl. ca1 issues for every Freshness Kind in both passes. With the RRP identifier in the binding,
            ca2 refuses every kind; without it, ca2 refuses present-nonce alone.
  bank-pay  report.json, from the Demo Bank's payment service. pay: the payment went through. ordinary: no
            attestation, no credential, and the ledger and the fraud service refused the workload. unapproved:
            genuine hardware Evidence, and no credential.
  mtls      mtls.json (checks.json in the runs of 1 October 2026), from make check-mtls. Every check as expected: on
            each channel only the allowed components, over TLS 1.3, got through.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

FRESHNESS_KINDS = ("present-nonce", "present-epoch", "absent-epoch", "absent-timestamp", "absent-none")
REDIRECT_PASSES = ("with-rrp-id", "no-rrp-id")
COMPARED_BUILDS = ("rrpverify-veraison-fork", "rrpverify-veraison-fixed")


def demo(run, expect, reason, cause):
    results = json.loads((run / "results.json").read_text())
    admitted = [r for r in results if r["ok"]]
    lines = [f"{len(admitted)} of {len(results)} Targets: credential acquired and admitted by the relying party"]
    for r in results:
        cells = ["ok " if r["ok"] else "no ", r["target"].ljust(38), r["type"].ljust(8), f"{r['acquire_ms']:8.1f} ms"]
        lines.append(" ".join([*cells, str(r["rup_status"]), r.get("error", "")[:120]]).rstrip())
    if not results:
        return lines, False, "the workload asked for no Target"
    if expect == "admitted":
        if len(admitted) < len(results):
            return lines, False, f"{len(results) - len(admitted)} of {len(results)} Targets not admitted"
        return lines, True, f"all {len(results)} Targets: credential acquired and admitted by the relying party"
    issued = [r["target"] for r in results if r.get("cert_serial") or r.get("secret_sha256")]
    if issued:
        return lines, False, f"a credential was issued for {', '.join(issued)}"
    other = [r["target"] for r in results if reason not in r.get("error", "")]
    if other:
        return lines, False, f"refused, but not with {reason!r}: {', '.join(other)}"
    because = f", each with {reason!r}" if reason else ""
    if cause:
        log = (run / "bench-logs" / "sim-verifier.log").read_text().splitlines()
        appraisals = [x.split("appraisal: ", 1)[1] for x in log if "appraisal: " in x]
        lines += [f"the stand-in's verifier, {n} appraisal(s): {a}" for a, n in Counter(appraisals).items()]
        if not appraisals:
            return lines, False, "the stand-in's verifier logged no appraisal"
        off = [a for a in appraisals if cause not in a]
        if off:
            return lines, False, f"{len(off)} of {len(appraisals)} appraisals without {cause!r}"
        because += f"; the stand-in's verifier: {cause!r}, {len(appraisals)} of {len(appraisals)} appraisals"
    return lines, True, f"{len(results)} of {len(results)} Targets refused, no credential issued{because}"


def attacks(run):
    lines, judged, failed = [], 0, 0
    files = sorted(run.glob("rrpverify-*.json"))
    for f in files:
        results = json.loads(f.read_text())["results"]
        bad = [r for r in results if not r["ok"]]
        compared = f.stem in COMPARED_BUILDS
        note = " (a build the bench compares with: reported, not judged)" if compared else ""
        lines.append(f"{f.stem}: {len(results)} checks, {len(bad)} not as expected{note}")
        if compared:
            continue
        judged += len(results)
        failed += len(bad)
        for r in bad:
            lines.append(f"  {r['case']}: {r['check']}: want {r['want']}, got {r['got']} {r.get('error', '')}".rstrip())
    if not judged:
        return lines, False, "no results of the bench's own checks (rrpverify-*.json)"
    if failed:
        return lines, False, f"{failed} of {judged} checks not as expected"
    return lines, True, f"{judged} checks: the honest Evidence passed, every attack refused for its own reason"


def redirect(run):
    rows = [json.loads(x) for x in (run / "results.jsonl").read_text().splitlines() if x.strip()]
    got = {(r["pass"], r["kind"], r["rrp"]): r["result"]["issued"] for r in rows}
    lines, wrong = [f"{'pass':12} {'kind':18} {'ca1':8} ca2"], []
    for p in REDIRECT_PASSES:
        for k in FRESHNESS_KINDS:
            want = {"ca1": True, "ca2": p == "no-rrp-id" and k != "present-nonce"}
            cells = []
            for rrp in ("ca1", "ca2"):
                issued = got.get((p, k, rrp))
                cells.append({True: "ISSUED", False: "refused", None: "missing"}[issued])
                if issued is not want[rrp]:
                    wrong.append(f"{p} {k} {rrp}: {cells[-1]}, expected {'ISSUED' if want[rrp] else 'refused'}")
            lines.append(f"{p:12} {k:18} {cells[0]:8} {cells[1]}")
    if wrong:
        outcomes = len(REDIRECT_PASSES) * len(FRESHNESS_KINDS) * 2
        return lines + wrong, False, f"{len(wrong)} of {outcomes} outcomes not as expected"
    summary = "with the RRP identifier, ca2 refused all 5 Freshness Kinds; without it, all but present-nonce"
    return lines, True, summary


def bank_pay(run, expect):
    report = json.loads((run / "report.json").read_text())
    steps = {s["step"]: s for s in report["steps"]}
    lines = []
    for s in report["steps"]:
        mark = "ok " if s["ok"] else "NO "
        lines.append(f"{mark}{s['step']:38}{s['ms']:9.1f} ms  {s.get('note') or ''} {s.get('error') or ''}".rstrip())
    paid = bool(steps.get("ledger: transfer", {}).get("ok") and report.get("receipt"))
    credentials = [n for n, s in steps.items() if n.startswith("TACRA:") and s["ok"]]
    if expect == "pay":
        if paid:
            return lines, True, "the payment went through, with credentials acquired by attestation"
        return lines, False, "no payment"
    wrong = ["the payment went through"] if paid else []
    wrong += [f"a credential was issued ({n})" for n in credentials]
    if expect == "ordinary":
        refusals = ("ledger: login without a certificate", "fraud service: call without the key")
        wrong += [f"not refused: {n}" for n in refusals if not steps.get(n, {}).get("ok")]
        summary = "no attestation, no credential; the ledger and the fraud service refused it"
    else:
        if steps.get("attestation plug-in and CAI", {}).get("ok") is not True:
            wrong.append("no hardware Evidence (the attestation plug-in and CAI step failed)")
        summary = "genuine hardware evidence, unapproved launch: no credential issued"
    if wrong:
        return lines, False, "; ".join(wrong)
    return lines, True, summary


def mtls(run):
    results = json.loads((run / "mtls.json" if (run / "mtls.json").exists() else run / "checks.json").read_text())
    bad = [r for r in results if not r["ok"]]
    lines = [
        f"not as expected: {r['channel']}, {r['caller']} over TLS {r['tls']}: want {r['expected']}, got {r['got']}"
        for r in bad
    ]
    if not results:
        return lines, False, "no check ran"
    if bad:
        return lines, False, f"{len(bad)} of {len(results)} checks not as expected"
    summary = f"{len(results)} of {len(results)} checks as expected: only the allowed components, over TLS 1.3"
    return lines, True, summary


JUDGES = {
    "demo": lambda a: demo(a.run, a.expect, a.reason, a.cause),
    "attacks": lambda a: attacks(a.run),
    "redirect": lambda a: redirect(a.run),
    "bank-pay": lambda a: bank_pay(a.run, a.expect),
    "mtls": lambda a: mtls(a.run),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Says whether a run came out as its experiment expects.")
    kinds = parser.add_subparsers(dest="kind", required=True)
    for kind in JUDGES:
        p = kinds.add_parser(kind)
        p.add_argument("run", type=Path, help="the run directory")
        p.add_argument("--out", type=Path, help="also write the verdict to this file")
        if kind == "demo":
            p.add_argument("--expect", choices=("admitted", "refused"), default="admitted")
            p.add_argument("--reason", default="", help="refused: the text every refusal's error must contain")
            p.add_argument("--cause", default="", help="refused: the cause every appraisal of the stand-in must give")
        if kind == "bank-pay":
            p.add_argument("--expect", choices=("pay", "ordinary", "unapproved"), required=True)
    args = parser.parse_args(argv)
    try:
        lines, ok, summary = JUDGES[args.kind](args)
    except (OSError, ValueError, KeyError, TypeError) as e:
        lines, ok, summary = [], False, f"cannot read the run in {args.run}: {e!r}"
    text = "\n".join([*lines, f"VERDICT {'PASS' if ok else 'FAIL'}: {summary}"]) + "\n"
    sys.stdout.write(text)
    if args.out:
        args.out.write_text(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
