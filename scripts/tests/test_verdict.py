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
# the attack runs of plan R3: the guest's clock recorded, and the pre-play check
PREPLAY_RUNS = ["20261007T165412Z-gcp-sev-snp", "20261007T170259Z-aws-sev-snp", "20261007T170913Z-gcp-tdx"]
# the attack runs of the release check R6: the RRPs' platform rule on the honest Attestation Results
# (rrpverify-platform.json), under the rule the run kept (platform-rule.json)
PLATFORM_RULE_RUNS = ["20261007T180531Z-gcp-sev-snp", "20261007T181406Z-aws-sev-snp", "20261007T182023Z-gcp-tdx"]
WAIVER = "the honest Evidence admitted under the bench's waiver: Milan bit 4: admitted without bit 4, AMD-SB-3034"
# the attack runs whose pre-play moves the guest's clock both ways (7 October 2026, EST patch 0012), and the one
# before that patch, which found the EST server's fault (its README)
CLOCK_RUNS = ["20261007T212531Z-gcp-sev-snp", "20261007T213607Z-aws-sev-snp", "20261007T214424Z-gcp-tdx"]
EST_FAULT_RUN = "20261007T211305Z-gcp-sev-snp"
# the conduit experiment (7 October 2026): #20 in Background Check and in Passport, and the conduit's #19 rewrites
CONDUIT_RUNS = [
    "20261007T204444Z-gcp-snp-redirect",
    "20261007T204937Z-gcp-tdx-redirect",
    "20261007T205428Z-aws-snp-redirect",
    "20261007T205826Z-gcp-snp-redirect-passport",
    "20261007T210314Z-gcp-tdx-redirect-passport",
    "20261007T210728Z-aws-snp-redirect-passport",
]
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
# the Demo Bank of the release check R6 (7 October 2026): its pack waives no mitigation bit, so it refuses the SEV-SNP
# hosts for AMD-SB-3034's bit 4 and pays from TDX only
BANK_R6 = E2E / "20261007T183914Z-demo-bank" / "runs"
BANK_R6_RUNS = {
    "20261007T184709Z-gcp-tdx": "pay",
    "20261007T184927Z-gcp-snp": "platform",
    "20261007T185218Z-aws-snp": "platform",
    "20261007T185428Z-ordinary": "ordinary",
    "20261007T185700Z-unapproved": "unapproved",
}
# the same rule after the release check, at v0.1.0: the Demo Bank in Background Check, and a bank of one's own
# (make bank-new NAME=acme-bank)
BANKS_AFTER_R6 = {
    E2E / "20261007T193224Z-demo-bank" / "runs": {
        "20261007T194000Z-gcp-tdx": "pay",
        "20261007T194222Z-gcp-snp": "platform",
        "20261007T194516Z-aws-snp": "platform",
        "20261007T194721Z-ordinary": "ordinary",
        "20261007T194951Z-unapproved": "unapproved",
    },
    E2E / "20261007T195519Z-acme-bank" / "runs": {
        "20261007T200406Z-gcp-tdx": "pay",
        "20261007T200627Z-gcp-snp": "platform",
    },
}
BANK_RUNS = {
    "20261006T231902Z-gcp-snp": "pay",
    "20261006T232202Z-gcp-tdx": "pay",
    "20261006T232439Z-aws-snp": "pay",
    "20261006T232651Z-ordinary": "ordinary",
    "20261006T232917Z-unapproved": "unapproved",
}


def verdict_lines(*args):
    """Runs verdict.py; returns its exit status and every line it printed."""
    p = subprocess.run([sys.executable, str(VERDICT), *map(str, args)], capture_output=True, text=True, check=False)
    return p.returncode, p.stdout.splitlines()


def verdict(*args):
    """Runs verdict.py; returns its exit status and its last line."""
    code, lines = verdict_lines(*args)
    return code, lines[-1]


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

    def test_attacks_with_preplay(self):
        for run in PREPLAY_RUNS:
            with self.subTest(run=run):
                code, last = verdict("attacks", HW / run)
                self.assertEqual(code, 0, last)
                self.assertRegex(
                    last,
                    r"; exposure, the guest's clock: https://db-time.tacra.example accepted Evidence 29\d s old or more "
                    r"\(max_age 120 s\); https://ledger-time.tacra.example accepted Evidence 29\d s old or more",
                )

    def test_attacks_with_the_platform_rule(self):
        for run in PLATFORM_RULE_RUNS:
            with self.subTest(run=run):
                code, lines = verdict_lines("attacks", HW / run)
                self.assertEqual(code, 0, lines[-1])
                n = len(json.loads((HW / run / "rrpverify-platform.json").read_text())["results"])
                self.assertIn(f"rrpverify-platform: {n} checks, 0 not as expected", lines)
                if "sev-snp" in run:  # SEV-SNP Milan, admitted only under the bench's waiver: the verdict says so
                    self.assertIn(WAIVER, lines[-1])
                else:
                    self.assertNotIn("waiver", lines[-1])

    def test_attacks_with_the_clock_moved(self):
        for run in CLOCK_RUNS:
            with self.subTest(run=run):
                code, last = verdict("attacks", HW / run)
                self.assertEqual(code, 0, last)
                self.assertRegex(
                    last,
                    r"https://db-time.tacra.example accepted Evidence \d+ s old or more, and again \d+ s old or more "
                    r"\(max_age 120 s\)",
                )
                self.assertIn(
                    "absent-timestamp Evidence made with the clock behind refused; the other four kinds' Evidence made "
                    "with it ahead taken at once",
                    last,
                )

    def test_the_run_that_found_the_est_fault(self):
        why = (
            "VERDICT FAIL: the pre-play check not as expected: ahead enroll-present-epoch: not taken at once "
            "(403 Target, Credential Type or Freshness Kind differ from the attest-initiate)"
        )
        self.assertEqual(verdict("attacks", HW / EST_FAULT_RUN), (1, why))

    def test_conduit(self):
        for run in CONDUIT_RUNS:
            with self.subTest(run=run):
                code, last = verdict("redirect", HW / run)
                self.assertEqual(code, 0, last)
                self.assertIn("of the conduit's 20 rewrites at ca1", last)

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

    def test_bank_pay_release(self):
        for bank, runs in [(BANK_R6, BANK_R6_RUNS), *BANKS_AFTER_R6.items()]:
            for run, expect in runs.items():
                with self.subTest(bank=bank.parent.name, run=run):
                    code, last = verdict("bank-pay", bank / run, "--expect", expect)
                    self.assertEqual(code, 0, last)
                    if expect == "platform":  # the bank's rule names the bit and its bulletin, and the line ends there
                        self.assertRegex(
                            last,
                            r"refused by the bank's platform rule: mitigation bit 4 \(AMD-SB-3034 \(CVE-2025-54510\)\) "
                            r"is not set in LAUNCH_MIT_VECTOR 0x[0-9a-f]+$",
                        )


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

    def test_demo_under_a_waiver(self):
        # real runs, their platform rule with the waiver the bench's pack names, as scripts/trustzone.py writes it: a
        # SEV-SNP run's verdict names it, a TDX run's does not (the waiver is the SEV-SNP rule's)
        waived = {"Milan": {"4": "admitted without bit 4, AMD-SB-3034"}}
        all10 = "VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party"
        for src, want in [
            ("20261007T151521Z-gcp-sev-snp-e2e-passport",
             all10 + "; admitted under the bench's waiver: Milan bit 4: admitted without bit 4, AMD-SB-3034"),
            ("20261007T154450Z-gcp-tdx-e2e-passport", all10),
        ]:  # fmt: skip
            with self.subTest(src):
                run = self.tmp / src
                run.mkdir()
                for name in ("results.json", "platform-rule.json"):
                    shutil.copy(E2E / src / name, run / name)
                rule = json.loads((run / "platform-rule.json").read_text())
                rule["sevsnp"]["mitigation_waivers"] = waived
                (run / "platform-rule.json").write_text(json.dumps(rule))
                self.assertEqual(verdict("demo", run), (0, want))

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

    def test_platform_rule_check_not_as_expected(self):
        # a bank's rule that admitted Evidence the bench admits only under its waiver: the run fails
        run = self.copy(HW / PLATFORM_RULE_RUNS[0], "rrpverify-platform.json", "rrpverify-service.json")

        def admitted(d):
            next(r for r in d["results"] if r["check"] == "a bank's rule, no waiver").update(got="pass", ok=False)

        self.edit_json("rrpverify-platform.json", admitted)
        n = sum(
            len(json.loads((run / f).read_text())["results"])
            for f in ("rrpverify-platform.json", "rrpverify-service.json")
        )
        self.assertEqual(verdict("attacks", run), (1, f"VERDICT FAIL: 1 of {n} checks not as expected"))

    def test_compared_build_is_not_judged(self):
        run = self.copy(HW / ATTACK_RUNS[0], "rrpverify-veraison-fork.json", "rrpverify-veraison-v015.json")
        self.edit_json("rrpverify-veraison-fork.json", lambda d: d["results"][0].update(ok=False))
        code, last = verdict("attacks", run)
        self.assertEqual(code, 0, last)

    def preplay_run(self, change=None, presented=True):
        """A copy of a real R3 attack run's judged files, its pre-play result changed by change."""
        src = HW / PREPLAY_RUNS[0]
        for f in src.glob("rrpverify-*.json"):
            shutil.copy(f, self.tmp / f.name)
        shutil.copytree(src / "preplay", self.tmp / "preplay")
        if presented:
            shutil.copy(src / "preplay.json", self.tmp / "preplay.json")
            if change:
                self.edit_json("preplay.json", change)
        return self.tmp

    def test_preplay_not_as_expected(self):
        for name, change, presented, why in [
            ("accepted at once", lambda d: d["results"][0]["at_once"].update(status=200), True,
             "https://db-time.tacra.example"),
            ("refused later", lambda d: d["results"][1]["later"].update(status=409), True,
             "https://ledger-time.tacra.example"),
            ("made, never presented", None, False, "the Evidence made with the guest's clock ahead was not presented"),
        ]:  # fmt: skip
            with self.subTest(name):
                for f in self.tmp.iterdir():
                    shutil.rmtree(f) if f.is_dir() else f.unlink()
                code, last = verdict("attacks", self.preplay_run(change, presented))
                self.assertEqual((code, last), (1, f"VERDICT FAIL: the pre-play check not as expected: {why}"))

    def clock_run(self, change):
        """A copy of a clock run's judged files, its pre-play changed by change."""
        src = HW / CLOCK_RUNS[0]
        for f in src.glob("rrpverify-*.json"):
            shutil.copy(f, self.tmp / f.name)
        shutil.copytree(src / "preplay", self.tmp / "preplay")
        shutil.copy(src / "preplay.json", self.tmp / "preplay.json")
        self.edit_json("preplay.json", change)
        return self.tmp

    def test_clock_preplay_not_as_expected(self):
        def at(set_, case, edge, status):
            def change(d):
                r = next(r for r in d["results"] if r["set"] == set_ and r["case"] == case)
                r[edge] = {**r[edge], "status": status}

            return change

        for name, change, why in [
            ("the window did not close", at("ahead", "enroll-absent-timestamp", "after_close", 200),
             "ahead enroll-absent-timestamp: not refused at once, taken in its window and refused after it"),
            ("made with the clock behind, taken", at("behind", "retrieve-absent-timestamp", "again", 200),
             "behind retrieve-absent-timestamp: made with the clock behind, not refused for freshness each time"),
            ("another kind not taken at once", at("ahead", "enroll-absent-epoch", "at_once", 409),
             "ahead enroll-absent-epoch: not taken at once"),
        ]:  # fmt: skip
            with self.subTest(name):
                for f in self.tmp.iterdir():
                    shutil.rmtree(f) if f.is_dir() else f.unlink()
                code, last = verdict("attacks", self.clock_run(change))
                self.assertEqual(code, 1, last)
                self.assertTrue(last.startswith(f"VERDICT FAIL: the pre-play check not as expected: {why}"), last)

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

    def test_conduit_rewrite_not_as_expected(self):
        # the Credential Hint of another workload, issued: the CA would have named a workload the Evidence is not
        run = self.copy(HW / CONDUIT_RUNS[3], "results.jsonl")
        rows = [json.loads(x) for x in (run / "results.jsonl").read_text().splitlines()]
        for r in rows:
            if r.get("rewrite") == "Credential Hint of another workload" and r["kind"] == "present-nonce":
                r["result"] = {"issued": True, "status": 200, "cert_subject": "CN=other.workload.tacra.example"}
        (run / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        code, lines = verdict_lines("redirect", run)
        self.assertEqual((code, lines[-1]), (1, "VERDICT FAIL: 1 of 40 outcomes not as expected"))
        self.assertIn(
            "rewrite Credential Hint of another workload, present-nonce: issued (), expected refused credential-hint",
            lines,
        )

    def test_conduit_rewrite_missing(self):
        run = self.copy(HW / CONDUIT_RUNS[0], "results.jsonl")
        rows = (run / "results.jsonl").read_text().splitlines()
        (run / "results.jsonl").write_text("\n".join(x for x in rows if '"made-up Handle"' not in x) + "\n")
        self.assertEqual(verdict("redirect", run), (1, "VERDICT FAIL: 1 of 40 outcomes not as expected"))

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

    def test_bank_refused_for_another_reason(self):
        # an SEV-SNP payment refused, but not by the platform rule: not the refusal the bank expects of SEV-SNP
        run = self.copy(BANK_R6 / "20261007T184927Z-gcp-snp", "report.json")
        self.edit_json(
            "report.json",
            lambda r: [
                s.update(error="cai: EnrollCredential: 403 RRP ca: attestation: ear: not affirming")
                for s in r["steps"]
                if s["step"].startswith("TACRA:")
            ],
        )
        code, last = verdict("bank-pay", run, "--expect", "platform")
        self.assertEqual(code, 1)
        self.assertTrue(last.startswith("VERDICT FAIL: not every credential refused by the platform rule"), last)

    def test_bank_payment_is_not_a_platform_refusal(self):
        code, last = verdict("bank-pay", BANK_R6 / "20261007T184709Z-gcp-tdx", "--expect", "platform")
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
