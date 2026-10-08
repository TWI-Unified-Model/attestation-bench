#!/usr/bin/env python3
"""A table of runs: what each one tested, on which platform, in which RATS model, and its verdict.

    python3 scripts/report.py [RUN_DIR ...]        (make report; default: every run in RUNS_DIR, else BENCH_HOME/runs)

A run that kept its verdict (verdict.txt) is reported by it; a run made before verdicts existed is judged again from
its files by scripts/verdict.py, and marked so. A run that stopped before its results, or whose files are of an earlier
format, is listed as not judged. A bank's directory gives one row per payment. A directory that is not a run of the
bench's make commands (an earlier experiment, an endorsement record) is listed, not judged. Prints a Markdown table
and a count of the verdicts.
"""

import os
import re
import sys
from pathlib import Path

import verdict

PLATFORMS = {
    "gcp-snp": "GCP SEV-SNP",
    "gcp-sev-snp": "GCP SEV-SNP",
    "gcp-tdx": "GCP TDX",
    "aws-snp": "AWS SEV-SNP",
    "aws-sev-snp": "AWS SEV-SNP",
}
MODELS = {"passport": "Passport", "background-check": "Background Check"}
SCENARIOS = {
    "": "end to end",
    "cas-outside": "end to end, the CAS Client outside the guest",
    "unapproved": "refusal: a launch not approved",
    "other-platform": "refusal: Targets of another platform (N24)",
}
PAYMENTS = {  # a bank's payment run: what it is, its platform, what its verdict expects
    "gcp-snp": ("payment", "GCP SEV-SNP", "pay"),
    "gcp-tdx": ("payment", "GCP TDX", "pay"),
    "aws-snp": ("payment", "AWS SEV-SNP", "pay"),
    "ordinary": ("control: an ordinary VM", "GCP, no TEE", "ordinary"),
    "unapproved": ("control: an unapproved launch", "GCP SEV-SNP", "unapproved"),
}
E2E = re.compile(
    r"(?P<plat>gcp-sev-snp|gcp-tdx|aws-sev-snp)-e2e(?:-(?P<model>passport|background-check))?"
    r"(?:-(?P<scen>cas-outside|unapproved|other-platform))?"
    r"(?:-conduit-(?P<attack>seal|swap|hint|hint-group))?"  # the conduit's drills (docs/attacks.md, section 6)
)
ATTACKS = re.compile(r"(?P<hw>gcp-sev-snp|gcp-tdx|aws-sev-snp)")
REDIRECT = re.compile(r"(?P<plat>gcp-snp|gcp-tdx|aws-snp)-redirect(?:-passport)?")
STAMP = re.compile(r"\d{8}T\d{6}Z-(?P<name>.+)")
# the attack results of the current format: the bench's own checks, and the builds of Veraison it compares with
OWN_CHECKS = ("rrpverify-veraison-v015", "rrpverify-tdx")
KNOWN_CHECKS = {*OWN_CHECKS, "rrpverify-service", *verdict.COMPARED_BUILDS}
EARLIER = "an earlier format"
STOPPED = "no results: the run stopped before it finished"
NO_RESULTS = "no results; the run's own notes say why"


def recorded_model(run, default=""):
    f = run / "rats-model.txt"
    return MODELS.get(f.read_text().strip(), default) if f.exists() else default


def judged(run, judge, results, current=True):
    """The run's verdict: the one it kept; or verdict.py's on its results (files matching one of `results`), marked *,
    if they are there and of the current format."""
    kept = run / "verdict.txt"
    if kept.exists():
        m = re.match(r"VERDICT (PASS|FAIL): (.*)", kept.read_text().strip().splitlines()[-1])
        if m:
            return m.group(1), m.group(2)
    if not any(any(run.glob(pattern)) for pattern in results):  # sealed: it finished, without results
        return "not judged", NO_RESULTS if (run / "sha256sums.txt").exists() else STOPPED
    if not current:
        return "not judged", EARLIER
    try:
        _, ok, summary = judge()
    except (OSError, ValueError, KeyError, TypeError):
        return "not judged", EARLIER
    return ("PASS*" if ok else "FAIL*"), summary


def rows(run):
    """The table's rows for one directory: (run, what, platform, RATS model, verdict, summary)."""
    m = STAMP.fullmatch(run.name)
    name = m.group("name") if m else ""
    if (run / "runs").is_dir():  # a bank: one row per payment
        bank = name or run.name
        for pay in sorted(p for p in (run / "runs").iterdir() if p.is_dir()):
            what, plat, expect = PAYMENTS.get(pay.name[17:], (pay.name[17:], "", ""))
            v = (
                judged(pay, lambda p=pay, e=expect: verdict.bank_pay(p, e), ["report.json"])
                if expect
                else ("not judged", "")
            )
            yield f"{run.name}/runs/{pay.name}", f"{bank}: {what}", plat, recorded_model(run), *v
        return
    if e := E2E.fullmatch(name):
        scen = e.group("scen") or ""
        model = MODELS.get(e.group("model") or "", "") or recorded_model(run, "Passport")
        if attack := e.group("attack"):
            v = judged(run, lambda: verdict.conduit(run, attack), ["results.json"])
            yield run.name, f"the conduit's drill: {attack}", PLATFORMS[e.group("plat")], model, *v
            return
        expect = "refused" if scen in ("unapproved", "other-platform") else "admitted"
        v = judged(run, lambda: verdict.demo(run, expect, ""), ["results.json"])
        yield run.name, SCENARIOS[scen], PLATFORMS[e.group("plat")], model, *v
    elif name.startswith("bench-mtls"):
        model = recorded_model(run, "Background Check" if "background-check" in name else "Passport")
        yield (
            run.name,
            "mutual TLS (N23)",
            "trust zone, no TEE",
            model,
            *judged(run, lambda: verdict.mtls(run), ["mtls.json", "checks.json"]),
        )
    elif a := ATTACKS.fullmatch(name):
        plat = PLATFORMS[a.group("hw")]
        checks = {f.stem for f in run.glob("rrpverify-*.json")}
        current = checks <= KNOWN_CHECKS and any(c in checks for c in OWN_CHECKS)
        yield (
            run.name,
            "substitution attacks",
            plat,
            "",
            *judged(run, lambda: verdict.attacks(run), ["rrpverify-*.json"], current),
        )
    elif r := REDIRECT.fullmatch(name):
        plat = PLATFORMS[r.group("plat")]
        yield (
            run.name,
            "#20 redirection",
            plat,
            recorded_model(run, "Passport" if name.endswith("-passport") else "Background Check"),
            *judged(run, lambda: verdict.redirect(run), ["results.jsonl"]),
        )
    else:
        yield run.name, "not a run of the make commands", "", "", "not judged", ""


def default_runs():
    home = os.environ.get("BENCH_HOME") or os.environ.get("TACRA_BENCH") or str(Path.home() / ".attestation-bench")
    return Path(os.environ.get("RUNS_DIR") or Path(home) / "runs")


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    runs = (
        [p for p in map(Path, args) if p.is_dir()]
        if args
        else sorted(p for p in default_runs().iterdir() if p.is_dir())
    )
    table = [r for run in runs for r in rows(run)]
    print("| Run | What | Platform | RATS model | Verdict |")
    print("|---|---|---|---|---|")
    for run, what, plat, model, v, summary in table:
        cell = f"{v}: {summary}" if summary else v
        print(f"| `{run}` | {what} | {plat} | {model} | {cell.replace('|', '/')} |")
    count = {v: sum(1 for r in table if r[4].rstrip("*") == v) for v in ("PASS", "FAIL", "not judged")}
    print(f"\n{len(table)} runs: {count['PASS']} PASS, {count['FAIL']} FAIL, {count['not judged']} not judged")
    if any(r[4].endswith("*") for r in table):
        print(
            "\n* judged again by scripts/verdict.py from the run's files: the run was made before runs kept a verdict"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
