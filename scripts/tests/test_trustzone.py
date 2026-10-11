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

    def test_own_epochs(self):
        c = self.configs(own_epochs=True)
        self.assertNotIn("epoch_file", c["ca-2"], "the copy keeps an epoch marker of its own")
        self.assertNotIn("epoch_file", c["vault-2"], "the copy keeps an epoch marker of its own")
        self.assertEqual(c["ca"]["epoch_file"], "/bench/epoch.hex")
        self.assertEqual(c["vault"]["epoch_file"], "/bench/epoch.hex")

    def test_no_identifier_anywhere(self):
        """No RRP binds an identifier, and no configuration names a switch for it: ripped out on 11 October 2026."""
        for name, c in self.configs(own_epochs=True).items():
            self.assertFalse([k for k in c if "bind" in k or "omit" in k], f"{name}: {sorted(c)}")

    def test_copies_own_keys(self):
        p = pack("tacra-bench")
        rrps = {r["name"]: {"rrp_id": r["rrp_id"], "epoch_file": "/bench/epoch.hex"} for r in p["rrps"]}
        for n in ("vault", "vault-2"):
            rrps[n].update(kem_keys="/h/gateways/vault-kem.json", sign_key="/h/gateways/vault-sign.key")
        trustzone.redirection_variants(p, rrps, own_keys=True, home="/h")
        self.assertEqual(
            rrps["vault-2"]["kem_keys"], "/h/gateways/vault-2-kem.json", "the copy seals under keys of its own"
        )
        self.assertEqual(rrps["vault-2"]["sign_key"], "/h/gateways/vault-2-sign.key")
        self.assertEqual(rrps["vault"]["kem_keys"], "/h/gateways/vault-kem.json", "the first Vault keeps its keys")
        self.assertNotIn("kem_keys", rrps["ca-2"], "a Credential Authority has no Vault keys")

    def test_redirect_to_copies(self):
        """The redirect drill: every Target the EST server serves is routed to the copy of its RRP, with the copy's URL."""
        p = pack("tacra-bench")
        est_rrps = {
            "ca": {"url": "https://127.0.0.1:9101", "mode": "enroll"},
            "vault": {"url": "https://127.0.0.1:9102", "mode": "retrieve"},
        }
        est_targets = {t["target"]: t["rrp"] for t in p["targets"]}
        routed = trustzone.redirect_to_copies(p, est_rrps, est_targets, "passport", ["veraison"], "/h/root.crt")
        self.assertEqual(set(est_targets.values()), {"ca-2", "vault-2"}, "every Target goes to a copy")
        self.assertEqual(est_rrps["ca-2"]["url"], "https://127.0.0.1:9103")
        self.assertEqual(est_rrps["vault-2"]["url"], "https://127.0.0.1:9104")
        self.assertEqual(est_rrps["ca-2"]["mode"], "enroll")
        self.assertEqual(routed, est_targets)


if __name__ == "__main__":
    unittest.main()
