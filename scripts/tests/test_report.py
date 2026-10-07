"""Tests of scripts/report.py on the committed runs: the reference runs pass, a bank gives a row per payment, a run of
an earlier format is not judged, and a run that failed in its day still fails.

    python3 -m unittest discover -s scripts/tests        (make test)
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REPORT = REPO / "scripts" / "report.py"
E2E = REPO / "e2e" / "evidence"
HW = REPO / "hwcheck" / "evidence"


def report(*runs, env=None):
    """Runs report.py; returns its table rows (the header left out) and its count line."""
    p = subprocess.run(
        [sys.executable, str(REPORT), *map(str, runs)], capture_output=True, text=True, check=True, env=env
    )
    lines = p.stdout.splitlines()
    return [x for x in lines if x.startswith("| `")], next(x for x in lines if " runs: " in x)


class Report(unittest.TestCase):
    def test_reference_runs_pass(self):
        rows, count = report(
            E2E / "20261006T222549Z-bench-mtls",
            E2E / "20261006T222601Z-gcp-sev-snp-e2e-passport",
            HW / "20261006T225040Z-gcp-tdx",
            HW / "20261006T225552Z-gcp-snp-redirect",
        )
        self.assertEqual(count, "4 runs: 4 PASS, 0 FAIL, 0 not judged")
        self.assertIn("| mutual TLS (N23) | stand-in | Passport | PASS*: 47 of 47 checks as expected", rows[0])
        self.assertIn("| end to end | GCP SEV-SNP | Passport | PASS*: all 10 Targets", rows[1])
        self.assertIn("| substitution attacks | GCP TDX |  | PASS*: 82 checks", rows[2])
        self.assertIn("| #20 redirection | GCP SEV-SNP | Background Check | PASS*: with the RRP identifier", rows[3])

    def test_a_bank_gives_a_row_per_payment(self):
        rows, count = report(E2E / "20261006T230714Z-demo-bank")
        self.assertEqual(count, "5 runs: 5 PASS, 0 FAIL, 0 not judged")
        self.assertIn("| demo-bank: control: an unapproved launch | GCP SEV-SNP | Passport | PASS: genuine", rows[4])

    def test_earlier_format_is_not_judged(self):
        rows, count = report(HW / "20260928T192839Z-gcp-tdx")
        self.assertEqual(count, "1 runs: 0 PASS, 0 FAIL, 1 not judged")
        self.assertIn("not judged: an earlier format", rows[0])

    def test_a_failure_of_its_day_still_fails(self):
        rows, count = report(E2E / "20261001T210405Z-bench-mtls-check")
        self.assertEqual(count, "1 runs: 0 PASS, 1 FAIL, 0 not judged")
        self.assertIn("FAIL*: 1 of 40 checks not as expected", rows[0])

    def test_default_is_runs_dir(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        shutil.copytree(HW / "20261006T225552Z-gcp-snp-redirect", tmp / "20261006T225552Z-gcp-snp-redirect")
        rows, count = report(env={**os.environ, "RUNS_DIR": str(tmp)})
        self.assertEqual(count, "1 runs: 1 PASS, 0 FAIL, 0 not judged")
        self.assertIn("`20261006T225552Z-gcp-snp-redirect`", rows[0])


if __name__ == "__main__":
    unittest.main()
