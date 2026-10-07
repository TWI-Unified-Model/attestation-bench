"""Tests of scripts/verdict.py: every run of gate 5 and gate 6 passes, every run of a refusal scenario passes as a
refusal for its own reason, and a run changed in one place, or judged against another expectation, fails.

    python3 -m unittest discover -s scripts/tests        (make test)

The runs are the committed ones under e2e/evidence and hwcheck/evidence; a changed run is a copy in a temporary
directory, so the evidence is only read.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VERDICT = REPO / "scripts" / "verdict.py"
E2E = REPO / "e2e" / "evidence"
HW = REPO / "hwcheck" / "evidence"
BANK = E2E / "20261006T230714Z-demo-bank" / "runs"

DEMO_RUNS = [
    "20261006T222601Z-gcp-sev-snp-e2e-passport",
    "20261006T222921Z-gcp-tdx-e2e-passport",
    "20261006T223210Z-aws-sev-snp-e2e-passport",
    "20261006T223452Z-gcp-sev-snp-e2e-background-check",
    "20261006T223835Z-gcp-tdx-e2e-background-check",
    "20261006T224133Z-aws-sev-snp-e2e-background-check",
]
ATTACK_RUNS = ["20261006T224346Z-gcp-sev-snp", "20261006T225040Z-gcp-tdx", "20261006T225323Z-aws-sev-snp"]
REDIRECT_RUNS = [
    "20261006T225552Z-gcp-snp-redirect",
    "20261006T225943Z-gcp-tdx-redirect",
    "20261006T230316Z-aws-snp-redirect",
]
# the refusal scenarios on hardware (make demo with UNAPPROVED=1 or OTHER_PLATFORM=1), each with the reason it expects
REFUSAL_RUNS = {
    "20261007T140959Z-gcp-sev-snp-e2e-passport-unapproved": "ear: not affirming: SEVSNP is",
    "20261007T141302Z-aws-sev-snp-e2e-passport-unapproved": "ear: not affirming: SEVSNP is",
    "20261007T012220Z-gcp-sev-snp-e2e-passport-other-platform": "none of the verifiers this RRP takes for the Target",
    "20261007T012516Z-aws-sev-snp-e2e-passport-other-platform": "none of the verifiers this RRP takes for the Target",
    "20261007T012715Z-gcp-tdx-e2e-passport-other-platform": "none of the verifiers this RRP takes for the Target",
    "20261007T015243Z-gcp-tdx-e2e-background-check-other-platform": "none of the verifiers this RRP takes for the Target",
}
UNAPPROVED = "20261007T140959Z-gcp-sev-snp-e2e-passport-unapproved"
OTHER_PLATFORM = "20261007T012220Z-gcp-sev-snp-e2e-passport-other-platform"
# the run whose SSH session broke on 7 October 2026: it stopped before it wrote its results (its README)
STOPPED = "20261007T045819Z-gcp-sev-snp-e2e-background-check"
BANK_RUNS = {
    "20261006T231902Z-gcp-snp": "pay",
    "20261006T232202Z-gcp-tdx": "pay",
    "20261006T232439Z-aws-snp": "pay",
    "20261006T232651Z-ordinary": "ordinary",
    "20261006T232917Z-unapproved": "unapproved",
}


def verdict(*args):
    """Runs verdict.py; returns its exit status and its last line."""
    p = subprocess.run([sys.executable, str(VERDICT), *map(str, args)], capture_output=True, text=True, check=False)
    return p.returncode, p.stdout.splitlines()[-1]


class CommittedRuns(unittest.TestCase):
    def test_demo(self):
        for run in DEMO_RUNS:
            with self.subTest(run=run):
                self.assertEqual(
                    verdict("demo", E2E / run),
                    (0, "VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party"),
                )

    def test_refusal_scenarios(self):
        for run, reason in REFUSAL_RUNS.items():
            with self.subTest(run=run):
                n = len(json.loads((E2E / run / "results.json").read_text()))
                self.assertEqual(
                    verdict("demo", E2E / run, "--expect", "refused", "--reason", reason),
                    (0, f"VERDICT PASS: {n} of {n} Targets refused, no credential issued, each with '{reason}'"),
                )

    def test_attacks(self):
        for run in ATTACK_RUNS:
            with self.subTest(run=run):
                code, last = verdict("attacks", HW / run)
                self.assertEqual(code, 0, last)
                self.assertRegex(last, r"^VERDICT PASS: \d+ checks: the honest Evidence passed")

    def test_redirect(self):
        for run in REDIRECT_RUNS:
            with self.subTest(run=run):
                code, last = verdict("redirect", HW / run)
                self.assertEqual(code, 0, last)

    def test_bank_pay(self):
        for run, expect in BANK_RUNS.items():
            with self.subTest(run=run):
                code, last = verdict("bank-pay", BANK / run, "--expect", expect)
                self.assertEqual(code, 0, last)
                self.assertTrue(last.startswith("VERDICT PASS: "), last)


class ChangedRuns(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def copy(self, src, *names):
        for name in names:
            shutil.copy(src / name, self.tmp / name)
        return self.tmp

    def edit_json(self, name, change):
        p = self.tmp / name
        data = json.loads(p.read_text())
        change(data)
        p.write_text(json.dumps(data))

    def test_demo_one_target_not_admitted(self):
        run = self.copy(E2E / DEMO_RUNS[0], "results.json")
        self.edit_json("results.json", lambda r: r[3].update(ok=False, rup_status=403))
        self.assertEqual(verdict("demo", run), (1, "VERDICT FAIL: 1 of 10 Targets not admitted"))

    def test_demo_no_target(self):
        run = self.copy(E2E / DEMO_RUNS[0], "results.json")
        self.edit_json("results.json", lambda r: r.clear())
        self.assertEqual(verdict("demo", run), (1, "VERDICT FAIL: the workload asked for no Target"))

    def test_refusal_run_is_not_a_demo(self):
        self.assertEqual(verdict("demo", E2E / UNAPPROVED), (1, "VERDICT FAIL: 10 of 10 Targets not admitted"))

    def test_refusal_scenario_that_issued(self):
        run = self.copy(E2E / DEMO_RUNS[0], "results.json")
        code, last = verdict("demo", run, "--expect", "refused")
        self.assertEqual(code, 1)
        self.assertTrue(last.startswith("VERDICT FAIL: a credential was issued for https://"), last)

    def test_refused_for_another_reason(self):
        unapproved, other = REFUSAL_RUNS[UNAPPROVED], REFUSAL_RUNS[OTHER_PLATFORM]
        # the unapproved launch's run judged against the other platform's reason: its Targets are named
        code, last = verdict("demo", E2E / UNAPPROVED, "--expect", "refused", "--reason", other)
        self.assertEqual(code, 1)
        self.assertTrue(last.startswith(f"VERDICT FAIL: refused, but not with '{other}': https://db-nonce."), last)
        # one of its Targets refused for the other platform's reason, as that run recorded it: that Target is named
        run = self.copy(E2E / UNAPPROVED, "results.json")
        error = json.loads((E2E / OTHER_PLATFORM / "results.json").read_text())[0]["error"]
        self.edit_json("results.json", lambda r: r[6].update(error=error))
        self.assertEqual(
            verdict("demo", run, "--expect", "refused", "--reason", unapproved),
            (1, f"VERDICT FAIL: refused, but not with '{unapproved}': https://ledger-epoch.tacra.example"),
        )

    def test_attack_not_refused(self):
        run = self.copy(HW / ATTACK_RUNS[0], "rrpverify-veraison-v015.json", "rrpverify-service.json")
        self.edit_json("rrpverify-veraison-v015.json", lambda d: d["results"][1].update(got="pass", ok=False))
        self.assertEqual(verdict("attacks", run), (1, "VERDICT FAIL: 1 of 212 checks not as expected"))

    def test_compared_build_is_not_judged(self):
        run = self.copy(HW / ATTACK_RUNS[0], "rrpverify-veraison-fork.json", "rrpverify-veraison-v015.json")
        self.edit_json("rrpverify-veraison-fork.json", lambda d: d["results"][0].update(ok=False))
        code, last = verdict("attacks", run)
        self.assertEqual(code, 0, last)

    def test_no_attack_results(self):
        # an attack run with only the results of the builds the bench compares with
        run = self.copy(HW / ATTACK_RUNS[0], "rrpverify-veraison-fork.json", "rrpverify-veraison-fixed.json")
        self.assertEqual(
            verdict("attacks", run), (1, "VERDICT FAIL: no results of the bench's own checks (rrpverify-*.json)")
        )

    def test_redirect_refused_without_rrp_id(self):
        run = self.copy(HW / REDIRECT_RUNS[0], "results.jsonl")
        rows = [json.loads(x) for x in (run / "results.jsonl").read_text().splitlines()]
        for r in rows:
            if (r["pass"], r["kind"], r["rrp"]) == ("no-rrp-id", "absent-none", "ca2"):
                r["result"] = {"issued": False, "status": 403}
        (run / "results.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        self.assertEqual(verdict("redirect", run), (1, "VERDICT FAIL: 1 of 20 outcomes not as expected"))

    def test_redirect_missing_outcome(self):
        run = self.copy(HW / REDIRECT_RUNS[0], "results.jsonl")
        lines = (run / "results.jsonl").read_text().splitlines()
        (run / "results.jsonl").write_text("\n".join(lines[1:]) + "\n")
        self.assertEqual(verdict("redirect", run), (1, "VERDICT FAIL: 1 of 20 outcomes not as expected"))

    def test_bank_unapproved_with_credential(self):
        run = self.copy(BANK / "20261006T232917Z-unapproved", "report.json")
        self.edit_json(
            "report.json", lambda r: [s.update(ok=True) for s in r["steps"] if s["step"].startswith("TACRA:")]
        )
        code, last = verdict("bank-pay", run, "--expect", "unapproved")
        self.assertEqual(code, 1)
        self.assertTrue(last.startswith("VERDICT FAIL: a credential was issued (TACRA:"), last)

    def test_bank_payment_is_not_ordinary(self):
        code, last = verdict("bank-pay", BANK / "20261006T231902Z-gcp-snp", "--expect", "ordinary")
        self.assertEqual(code, 1)
        self.assertTrue(last.startswith("VERDICT FAIL: the payment went through; a credential was issued"), last)

    def test_run_that_stopped_early(self):
        code, last = verdict("demo", E2E / STOPPED)
        self.assertEqual(code, 1)
        self.assertTrue(last.startswith(f"VERDICT FAIL: cannot read the run in {E2E / STOPPED}: "), last)

    def test_out_holds_what_was_printed(self):
        out = self.tmp / "verdict.txt"
        p = subprocess.run(
            [sys.executable, str(VERDICT), "redirect", str(HW / REDIRECT_RUNS[0]), "--out", str(out)],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(out.read_text(), p.stdout)


if __name__ == "__main__":
    unittest.main()
