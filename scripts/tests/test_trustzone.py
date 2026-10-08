"""Tests of scripts/trustzone.py on the bench's own files: trust/platform-policy.json and the two packs.

The platform waivers: the bench's pack admits SEV-SNP hosts without AMD-SB-3034's mitigation bit 4 under a named
waiver; the Demo Bank's pack, a bank's, names none. A pack can waive a required mitigation bit and nothing else. The
redirection experiment's variants: the second Credential Authority with an epoch marker of its own, the Credential
Authorities without the RRP identifier in the binding.

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


class RedirectionVariants(unittest.TestCase):
    """The bench's pack has a copy of its Credential Authority, ca-2, and of its Secret Vault, vault-2, another bank's,
    which the redirection experiment offers Evidence made for ca or vault to (hwcheck/scripts/redirect.sh). Each RRP
    starts with the deployment's epoch file."""

    def configs(self, **variant):
        p = pack("tacra-bench")
        rrps = {r["name"]: {"rrp_id": r["rrp_id"], "epoch_file": "/bench/epoch.hex"} for r in p["rrps"]}
        trustzone.redirection_variants(p, rrps, **variant)
        return rrps

    def test_as_configured(self):
        for name, c in self.configs().items():
            self.assertEqual(c["epoch_file"], "/bench/epoch.hex", name)
            self.assertNotIn("omit_rrp_id_in_binding", c, name)

    def test_own_epochs(self):
        c = self.configs(own_epochs=True)
        self.assertNotIn("epoch_file", c["ca-2"], "the copy keeps an epoch marker of its own")
        self.assertNotIn("epoch_file", c["vault-2"], "the copy keeps an epoch marker of its own")
        self.assertEqual(c["ca"]["epoch_file"], "/bench/epoch.hex")
        self.assertEqual(c["vault"]["epoch_file"], "/bench/epoch.hex")
        self.assertFalse(any("omit_rrp_id_in_binding" in x for x in c.values()))

    def test_omit_rrp_id(self):
        c = self.configs(omit_rrp_id=True)
        self.assertEqual(sorted(c), ["ca", "ca-2", "vault", "vault-2"])
        for name, x in c.items():
            self.assertTrue(x["omit_rrp_id_in_binding"], f"{name}: every RRP, Credential Authority and Secret Vault")
        self.assertTrue(all(x["epoch_file"] == "/bench/epoch.hex" for x in c.values()))

    def test_omit_rrp_id_reaches_the_est_server(self):
        p = pack("tacra-bench")
        rrps = {r["name"]: {"rrp_id": r["rrp_id"], "epoch_file": "/bench/epoch.hex"} for r in p["rrps"]}
        est = {"ca": {"rrp_id": "x"}, "vault": {"rrp_id": "y"}}
        trustzone.redirection_variants(p, rrps, omit_rrp_id=True, est_rrps=est)
        self.assertTrue(all(e["omit_rrp_id_in_binding"] for e in est.values()), "the EST server's Passport nonce")
        kept = {"ca": {"rrp_id": "x"}}
        trustzone.redirection_variants(p, rrps, est_rrps=kept)
        self.assertNotIn("omit_rrp_id_in_binding", kept["ca"])

    def test_both(self):
        c = self.configs(omit_rrp_id=True, own_epochs=True)
        self.assertNotIn("epoch_file", c["ca-2"])
        self.assertTrue(c["ca-2"]["omit_rrp_id_in_binding"])
        self.assertEqual(c["ca"]["epoch_file"], "/bench/epoch.hex")


if __name__ == "__main__":
    unittest.main()
