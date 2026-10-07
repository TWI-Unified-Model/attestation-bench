"""Tests of scripts/trustzone.py's platform waivers, on the bench's own files: trust/platform-policy.json and the two
packs. The bench's pack admits SEV-SNP hosts without AMD-SB-3034's mitigation bit 4 under a named waiver; the Demo
Bank's pack, a bank's, names none. A pack can waive a required mitigation bit and nothing else.

    python3 -m unittest discover -s scripts/tests        (make test)
"""

import copy
import importlib.util
import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("trustzone", REPO / "scripts" / "trustzone.py")
trustzone = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trustzone)


def pack(name):
    return trustzone.load_pack(str(REPO / "packs" / name / "pack.json"))


class Waivers(unittest.TestCase):
    def setUp(self):
        self.rule = trustzone.load_platform(str(REPO / "trust" / "platform-policy.json"))

    def test_the_packs(self):
        before = json.dumps(self.rule, sort_keys=True)
        bench = trustzone.with_waivers(self.rule, pack("tacra-bench"))
        self.assertEqual(bench["sevsnp"]["mitigation_waivers"], {"Milan": {"4": "admitted without bit 4, AMD-SB-3034"}})
        self.assertEqual(bench["sevsnp"]["required_mitigation_bits"]["Milan"]["4"], "AMD-SB-3034 (CVE-2025-54510)")
        bank = trustzone.with_waivers(self.rule, pack("demo-bank"))
        self.assertNotIn("mitigation_waivers", bank["sevsnp"])
        self.assertEqual(json.dumps(self.rule, sort_keys=True), before, "the shared rule is left as it was")

    def changed(self, change):
        p = copy.deepcopy(pack("tacra-bench"))
        change(p["platform_waivers"]["sevsnp"])
        return p

    def test_refused(self):
        for name, change, want in [
            ("a bit the rule does not require", lambda w: w["mitigation_waivers"]["Milan"].update({"3": "x"}),
             "Milan bit 3 is waived but the platform rule does not require it"),
            ("a waiver without a name", lambda w: w["mitigation_waivers"]["Milan"].update({"4": " "}),
             "Milan bit 4 has no name"),
            ("another part of the rule", lambda w: w.update({"tcb_floors": {}}),
             "only sevsnp.mitigation_waivers can be waived"),
        ]:  # fmt: skip
            with self.subTest(name):
                with self.assertRaises(trustzone.PackError) as e:
                    trustzone.with_waivers(self.rule, self.changed(change))
                self.assertIn(want, str(e.exception))


if __name__ == "__main__":
    unittest.main()
