"""Tests of scripts/verdict.py: every run of gate 5 and gate 6 passes, every run of a refusal scenario passes as a
refusal for its own reason, and a run changed in one place, or judged against another expectation, fails.

    python3 -m unittest discover -s scripts/tests        (make test)

The runs are the committed ones under e2e/evidence and hwcheck/evidence; a changed run is a copy in a temporary
directory, so the evidence is only read.
"""

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VERDICT = REPO / "scripts" / "verdict.py"
spec = importlib.util.spec_from_file_location("verdict_mod", VERDICT)
verdict_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verdict_mod)
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
# the attest-* wire as proposed for the EST draft (EST patch 0014), 8 October 2026: the demos at 6bf2b37 and, after the
# check against what the group asked, at bee2ae9, each with its EST wire log, and the media type each message of the
# wire carries (e2e/scripts/est-wire-cddl.py); the attack runs at dae1fb0 and at bee2ae9, and the one before them, whose
# pre-play stopped at a Target with two credential groups (its README)
WIRE_DEMO_RUNS = [
    "20261008T134108Z-gcp-sev-snp-e2e-passport",
    "20261008T134423Z-aws-sev-snp-e2e-passport",
    "20261008T134640Z-gcp-tdx-e2e-passport",
    "20261008T134939Z-gcp-sev-snp-e2e-background-check",
    "20261008T135240Z-aws-sev-snp-e2e-background-check",
    "20261008T135441Z-gcp-tdx-e2e-background-check",
    "20261008T153259Z-gcp-sev-snp-e2e-passport",
    "20261008T153608Z-aws-sev-snp-e2e-passport",
    "20261008T153811Z-gcp-tdx-e2e-passport",
    "20261008T154103Z-gcp-sev-snp-e2e-background-check",
    "20261008T154400Z-aws-sev-snp-e2e-background-check",
    "20261008T154603Z-gcp-tdx-e2e-background-check",
]
WIRE_TYPES = {
    ("GET", "attest-initiate", "response"): "application/est-attest-initiate+json",
    ("POST", "attest-enroll", "request"): "application/est-attest-enroll+json",
    ("POST", "attest-enroll", "response"): "application/pkcs7-mime",
    ("POST", "attest-retrieve", "request"): "application/est-attest-retrieve+json",
    ("POST", "attest-retrieve", "response"): "application/est-attest-bundle+json",
}
WIRE_ATTACK_RUNS = [
    "20261008T141202Z-gcp-sev-snp",
    "20261008T142240Z-aws-sev-snp",
    "20261008T143101Z-gcp-tdx",
    "20261008T154907Z-gcp-sev-snp",
    "20261008T155945Z-aws-sev-snp",
    "20261008T160809Z-gcp-tdx",
]
PREPLAY_HINT_FAULT_RUN = "20261008T135750Z-gcp-sev-snp"
# the replay variants (hwcheck/scripts/redirect.sh, REDIRECT_VARIANT=replay, replay-vault), 8 October 2026 at 4a5c270:
# the same request twice at ca1 and at vault1, on the three platforms, in Background Check and in Passport
REPLAY_RUNS = {
    "20261008T184000Z-gcp-snp-redirect-replay": "replay",
    "20261008T184330Z-gcp-snp-redirect-passport-replay": "replay",
    "20261008T184656Z-gcp-snp-redirect-replay-vault": "replay-vault",
    "20261008T185010Z-gcp-snp-redirect-passport-replay-vault": "replay-vault",
    "20261008T185320Z-aws-snp-redirect-replay": "replay",
    "20261008T185545Z-aws-snp-redirect-passport-replay": "replay",
    "20261008T185807Z-aws-snp-redirect-replay-vault": "replay-vault",
    "20261008T190023Z-aws-snp-redirect-passport-replay-vault": "replay-vault",
    "20261008T190244Z-gcp-tdx-redirect-replay": "replay",
    "20261008T190548Z-gcp-tdx-redirect-passport-replay": "replay",
    "20261008T190855Z-gcp-tdx-redirect-replay-vault": "replay-vault",
    "20261008T191151Z-gcp-tdx-redirect-passport-replay-vault": "replay-vault",
}
# the protocol without the RRP identifier (OMIT_RRP_ID=1 end to end at the time: the CAI, the EST server and the RRPs;
# since 11 October 2026 the default, after the group's decision of 6 October), the same
# events as with it, 8 October 2026: the replay variants in both passes and the Passport demos at 153eb2f; the
# substitution attacks on GCP, the conduit's container drills and the Background Check demos at c3909630, after the
# first attack run found that rrpverify's service path still made the RRP identifier case; the AWS attacks at
# 1c1df049, after their first run found the AWS script's verify line without the empty identifiers (both runs are
# kept, with their READMEs)
REPLAY_BOTH_PASSES_RUNS = {
    "20261008T194057Z-gcp-snp-redirect-replay": "replay",
    "20261008T194502Z-gcp-snp-redirect-passport-replay": "replay",
    "20261008T194859Z-gcp-snp-redirect-replay-vault": "replay-vault",
    "20261008T195250Z-gcp-snp-redirect-passport-replay-vault": "replay-vault",
    "20261008T195636Z-aws-snp-redirect-replay": "replay",
    "20261008T195930Z-aws-snp-redirect-passport-replay": "replay",
    "20261008T200229Z-aws-snp-redirect-replay-vault": "replay-vault",
    "20261008T200516Z-aws-snp-redirect-passport-replay-vault": "replay-vault",
    "20261008T200806Z-gcp-tdx-redirect-replay": "replay",
    "20261008T201133Z-gcp-tdx-redirect-passport-replay": "replay",
    "20261008T201457Z-gcp-tdx-redirect-replay-vault": "replay-vault",
    "20261008T201816Z-gcp-tdx-redirect-passport-replay-vault": "replay-vault",
}
NO_RRP_ID_DEMO_RUNS = [
    "20261008T202206Z-gcp-sev-snp-e2e-passport-no-rrp-id",
    "20261008T202505Z-aws-sev-snp-e2e-passport-no-rrp-id",
    "20261008T202708Z-gcp-tdx-e2e-passport-no-rrp-id",
    "20261008T215102Z-gcp-sev-snp-e2e-background-check-no-rrp-id",
    "20261008T215357Z-aws-sev-snp-e2e-background-check-no-rrp-id",
    "20261008T215602Z-gcp-tdx-e2e-background-check-no-rrp-id",
]
NO_RRP_ID_ATTACK_RUNS = [
    "20261008T205230Z-gcp-sev-snp-no-rrp-id",
    "20261008T211132Z-gcp-tdx-no-rrp-id",
    "20261008T220040Z-aws-sev-snp-no-rrp-id",
]
NO_RRP_ID_DRILL_RUNS = {
    "20261008T212014Z-gcp-sev-snp-e2e-passport-no-rrp-id-conduit-seal": "seal",
    "20261008T212315Z-aws-sev-snp-e2e-passport-no-rrp-id-conduit-seal": "seal",
    "20261008T212519Z-gcp-tdx-e2e-passport-no-rrp-id-conduit-seal": "seal",
    "20261008T212753Z-gcp-sev-snp-e2e-passport-no-rrp-id-conduit-swap": "swap",
    "20261008T213051Z-aws-sev-snp-e2e-passport-no-rrp-id-conduit-swap": "swap",
    "20261008T213253Z-gcp-tdx-e2e-passport-no-rrp-id-conduit-swap": "swap",
    "20261008T213537Z-gcp-sev-snp-e2e-passport-no-rrp-id-conduit-hint": "hint",
    "20261008T213840Z-aws-sev-snp-e2e-passport-no-rrp-id-conduit-hint": "hint",
    "20261008T214046Z-gcp-tdx-e2e-passport-no-rrp-id-conduit-hint": "hint",
    "20261008T214316Z-gcp-sev-snp-e2e-passport-no-rrp-id-conduit-hint-group": "hint-group",
    "20261008T214614Z-aws-sev-snp-e2e-passport-no-rrp-id-conduit-hint-group": "hint-group",
    "20261008T214815Z-gcp-tdx-e2e-passport-no-rrp-id-conduit-hint-group": "hint-group",
}
SERVICE_CASE_GAP_RUN = "20261008T202943Z-gcp-sev-snp-no-rrp-id"
AWS_VERIFY_FLAGS_GAP_RUN = "20261008T210307Z-aws-sev-snp-no-rrp-id"
# the conduit experiment (7 October 2026): #20 in Background Check and in Passport, and the conduit's #19 rewrites
CONDUIT_RUNS = [
    "20261007T204444Z-gcp-snp-redirect",
    "20261007T204937Z-gcp-tdx-redirect",
    "20261007T205428Z-aws-snp-redirect",
    "20261007T205826Z-gcp-snp-redirect-passport",
    "20261007T210314Z-gcp-tdx-redirect-passport",
    "20261007T210728Z-aws-snp-redirect-passport",
]
# the EST server built from the transfer branch for the group's repository (TWI-Unified-Model/globalsign-est: the mock
# CA kept beside the TACRA backend), in the bench's trust zone, 9 October 2026, transfer commit 96a919cfece9: the demo
# on the three platforms in Passport, and the substitution suite on GCP SEV-SNP; each run's EST source record
# (code-revs.txt, veraison-revs.txt) names that tree
G1_TRANSFER_RUNS = [
    "20261009T004707Z-gcp-sev-snp-e2e-passport",
    "20261009T005009Z-aws-sev-snp-e2e-passport",
    "20261009T005217Z-gcp-tdx-e2e-passport",
    "20261009T005500Z-gcp-sev-snp",
]
# no RRP identifier in the binding, the default since 11 October 2026 (the group's decision of 6 October, rats-tacra#20): the
# EST server built from the transfer branch at 7e4224ce421d (no identifier, no server_id) in the trust zone on the new default,
# the demo on the three platforms in both RATS models and the substitution suite on the three platforms; then the bench's own
# tree (patch 0017, tree 3b2cb1f71b2a, the tested tree), the demo in Passport on the three platforms. Each run's EST source
# record names its tree; the workload's configuration binds no identifier; the attack runs' cases bound none
NO_ID_DEFAULT_RUNS = [
    "20261011T132003Z-gcp-sev-snp-e2e-passport",
    "20261011T132258Z-aws-sev-snp-e2e-passport",
    "20261011T132505Z-gcp-tdx-e2e-passport",
    "20261011T132808Z-gcp-sev-snp-e2e-background-check",
    "20261011T133105Z-aws-sev-snp-e2e-background-check",
    "20261011T133326Z-gcp-tdx-e2e-background-check",
    "20261011T133625Z-gcp-sev-snp",
    "20261011T134703Z-aws-sev-snp",
    "20261011T135526Z-gcp-tdx",
]
NO_ID_BENCH_TREE_RUNS = [
    "20261011T140418Z-gcp-sev-snp-e2e-passport",
    "20261011T140722Z-aws-sev-snp-e2e-passport",
    "20261011T140930Z-gcp-tdx-e2e-passport",
]
# the identifiers ripped out (11 October 2026, Mark Novak 14:31Z; rats-tacra#20): the EST server built from the transfer branch at
# b5315560178f (a three-field binding, no rrp_id anywhere) in the trust zone binding the same three fields; the demo on the three
# platforms in both RATS models (the AWS Background Check run once more on a fresh instance after a host's fault, below) and the
# substitution suite on the three platforms, every attack run recording binding_layout = freshness-target-subject; then the bench's
# own tree (patch 0018, tree 09762d19ebc6, the tested tree), the Passport demo on the three platforms
RIPOUT_RUNS = [
    "20261011T150339Z-gcp-sev-snp-e2e-passport",
    "20261011T150637Z-aws-sev-snp-e2e-passport",
    "20261011T150841Z-gcp-tdx-e2e-passport",
    "20261011T151137Z-gcp-sev-snp-e2e-background-check",
    "20261011T161559Z-aws-sev-snp-e2e-background-check",
    "20261011T151633Z-gcp-tdx-e2e-background-check",
    "20261011T151929Z-gcp-sev-snp",
    "20261011T153014Z-aws-sev-snp",
    "20261011T153829Z-gcp-tdx",
]
RIPOUT_BENCH_TREE_RUNS = [
    "20261011T154708Z-gcp-sev-snp-e2e-passport",
    "20261011T155003Z-aws-sev-snp-e2e-passport",
    "20261011T155209Z-gcp-tdx-e2e-passport",
]
# the bench on the group's master (11 October 2026, late evening; 8a000861): TWI-Unified-Model/globalsign-est master 6f80871, Mark
# Novak's merge of pull request #4, with the bench's two patches, tree bfd8d3aa3ec6, the tested tree; the demo on the three
# platforms in both RATS models and the substitution suite on the three platforms, each run's record naming that tree
G3_MASTER_RUNS = [
    "20261011T191449Z-gcp-sev-snp-e2e-passport",
    "20261011T191754Z-aws-sev-snp-e2e-passport",
    "20261011T191952Z-gcp-tdx-e2e-passport",
    "20261011T192237Z-gcp-sev-snp-e2e-background-check",
    "20261011T192535Z-aws-sev-snp-e2e-background-check",
    "20261011T192727Z-gcp-tdx-e2e-background-check",
    "20261011T193017Z-gcp-sev-snp",
    "20261011T194051Z-aws-sev-snp",
    "20261011T194919Z-gcp-tdx",
]
# a host's fault, kept with its README: the guest could not read the report's auxblob (the certificate table) on one AWS
# instance; every Target failed before the protocol began; the run above on a fresh instance came out 10 of 10
AWS_AUXBLOB_HOST_RUN = "20261011T151431Z-aws-sev-snp-e2e-background-check"
# the conduit's redirect drill (docs/attacks.md, section 6): the EST server routed every request to the second Credential
# Authority and the second Secret Vault; with the copies sharing the first RRPs' PKI and keys the CAI admits what they return,
# with the second Vault's own keys (COPIES_OWN_KEYS=1) it refuses the container for its origin
REDIRECT_DRILL_RUNS = {
    "20261011T155450Z-gcp-sev-snp-e2e-passport-conduit-redirect": False,
    "20261011T155756Z-aws-sev-snp-e2e-passport-conduit-redirect": False,
    "20261011T160001Z-gcp-tdx-e2e-passport-conduit-redirect": False,
    "20261011T160255Z-gcp-sev-snp-e2e-background-check-conduit-redirect": False,
    "20261011T160608Z-gcp-sev-snp-e2e-passport-conduit-redirect-own-keys": True,
    "20261011T160900Z-aws-sev-snp-e2e-passport-conduit-redirect-own-keys": True,
    "20261011T161104Z-gcp-tdx-e2e-passport-conduit-redirect-own-keys": True,
}
# the conduit's verifier drill (docs/attacks.md, section 6): the EST server, as the attacking conduit in Passport, signed
# each Enrollment's Attestation Results again with a key of its own; 8 October 2026 at 3b6a74ba
VERIFIER_DRILL_RUNS = [
    "20261008T234813Z-gcp-sev-snp-e2e-passport-conduit-verifier",
    "20261008T235252Z-aws-sev-snp-e2e-passport-conduit-verifier",
    "20261008T235455Z-gcp-tdx-e2e-passport-conduit-verifier",
]
# the conduit's drills on the Retrieval container (docs/attacks.md, section 6), at af909f4, in Passport
CONTAINER_DRILL_RUNS = {
    "20261008T003630Z-gcp-sev-snp-e2e-passport-conduit-seal": "seal",
    "20261008T003924Z-aws-sev-snp-e2e-passport-conduit-seal": "seal",
    "20261008T004125Z-gcp-tdx-e2e-passport-conduit-seal": "seal",
    "20261008T004403Z-gcp-sev-snp-e2e-passport-conduit-swap": "swap",
    "20261008T004710Z-aws-sev-snp-e2e-passport-conduit-swap": "swap",
    "20261008T004908Z-gcp-tdx-e2e-passport-conduit-swap": "swap",
    "20261008T005144Z-gcp-sev-snp-e2e-passport-conduit-hint": "hint",
    "20261008T005438Z-aws-sev-snp-e2e-passport-conduit-hint": "hint",
    "20261008T005645Z-gcp-tdx-e2e-passport-conduit-hint": "hint",
    "20261008T005910Z-gcp-sev-snp-e2e-passport-conduit-hint-group": "hint-group",
    "20261008T010204Z-aws-sev-snp-e2e-passport-conduit-hint-group": "hint-group",
    "20261008T010403Z-gcp-tdx-e2e-passport-conduit-hint-group": "hint-group",
}
REDIRECT_RUNS = [
    "20261006T225552Z-gcp-snp-redirect",
    "20261006T225943Z-gcp-tdx-redirect",
    "20261006T230316Z-aws-snp-redirect",
]
# the redirection experiment's variants (hwcheck/scripts/redirect.sh, REDIRECT_VARIANT), 8 October 2026, own-epochs and
# start-ca2 from c0f02ac, vault from 1a751f6: each on GCP SEV-SNP, GCP TDX and AWS SEV-SNP, in Background Check and in
# Passport
REDIRECT_VARIANT_RUNS = {
    "20261008T031349Z-gcp-snp-redirect-own-epochs": "own-epochs",
    "20261008T032215Z-gcp-snp-redirect-passport-own-epochs": "own-epochs",
    "20261008T032611Z-gcp-tdx-redirect-own-epochs": "own-epochs",
    "20261008T032934Z-gcp-tdx-redirect-passport-own-epochs": "own-epochs",
    "20261008T033255Z-aws-snp-redirect-own-epochs": "own-epochs",
    "20261008T033608Z-aws-snp-redirect-passport-own-epochs": "own-epochs",
    "20261008T031807Z-gcp-snp-redirect-start-ca2": "start-ca2",
    "20261008T033907Z-gcp-snp-redirect-passport-start-ca2": "start-ca2",
    "20261008T034309Z-gcp-tdx-redirect-start-ca2": "start-ca2",
    "20261008T034636Z-gcp-tdx-redirect-passport-start-ca2": "start-ca2",
    "20261008T035017Z-aws-snp-redirect-start-ca2": "start-ca2",
    "20261008T035308Z-aws-snp-redirect-passport-start-ca2": "start-ca2",
    "20261008T041327Z-gcp-snp-redirect-vault": "vault",
    "20261008T041741Z-gcp-snp-redirect-passport-vault": "vault",
    "20261008T042128Z-gcp-tdx-redirect-vault": "vault",
    "20261008T042456Z-gcp-tdx-redirect-passport-vault": "vault",
    "20261008T042814Z-aws-snp-redirect-vault": "vault",
    "20261008T043101Z-aws-snp-redirect-passport-vault": "vault",
}
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

    def test_demo_on_the_proposed_wire(self):
        for run in WIRE_DEMO_RUNS:
            with self.subTest(run=run):
                code, last = verdict("demo", E2E / run)
                self.assertEqual(code, 0, last)
                self.assertTrue(last.startswith("VERDICT PASS: all 10 Targets: credential acquired and admitted"), last)
                lines = (E2E / run / "bench-logs" / "est-wire.log").read_text().splitlines()
                self.assertEqual(len(lines), 20)  # attest-initiate and the second leg, for each of 10 Targets
                for rec in map(json.loads, lines):
                    resource = rec["path"].rsplit("/", 1)[-1]
                    self.assertEqual(rec["status"], 200, rec["path"])
                    for part in ("request", "response") if rec["method"] == "POST" else ("response",):
                        got = rec[f"{part}_content_type"].split(";")[0]
                        self.assertEqual(got, WIRE_TYPES[(rec["method"], resource, part)], f"{rec['path']} {part}")
                    if resource == "attest-initiate":  # what the wire no longer carries
                        members = set(json.loads(rec["response_body"]))
                        self.assertFalse(members & {"rrp_id", "required_bindings", "server_id"}, members)

    def test_attacks_on_the_proposed_wire(self):
        for run in WIRE_ATTACK_RUNS:
            with self.subTest(run=run):
                code, last = verdict("attacks", HW / run)
                self.assertEqual(code, 0, last)
                self.assertIn(
                    "absent-timestamp Evidence made with the clock behind refused; the other four kinds' Evidence made "
                    "with it ahead taken at once",
                    last,
                )

    def test_the_run_that_found_the_preplay_hint(self):
        why = "VERDICT FAIL: the pre-play check not as expected: the Evidence made with the guest's clock ahead was not presented"
        self.assertEqual(verdict("attacks", HW / PREPLAY_HINT_FAULT_RUN), (1, why))

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

    def test_conduit_container_drills(self):
        for run, attack in CONTAINER_DRILL_RUNS.items():
            with self.subTest(run=run):
                code, last = verdict("conduit", E2E / run, "--attack", attack)
                self.assertEqual(code, 0, last)
                self.assertTrue(last.endswith("; the 5 other Targets admitted"), last)

    def test_the_transfer_branch_in_the_trust_zone(self):
        for run in G1_TRANSFER_RUNS:
            with self.subTest(run=run):
                if "-e2e-" in run:
                    code, last = verdict("demo", E2E / run)
                    self.assertTrue(
                        last.startswith("VERDICT PASS: all 10 Targets: credential acquired and admitted"), last
                    )
                    record = (E2E / run / "code-revs.txt").read_text()
                else:
                    code, last = verdict("attacks", HW / run)
                    self.assertIn("every attack refused for its own reason", last)
                    record = (HW / run / "veraison-revs.txt").read_text()
                self.assertEqual(code, 0, last)
                self.assertIn("estserver built from", record)
                self.assertIn("globalsign-est-transfer", record)
                self.assertIn("96a919cfece9", record)
                self.assertIn("worktree clean", record)

    def test_no_rrp_identifier_is_the_default(self):
        """The runs of 11 October 2026 on the new default: no identifier bound anywhere, the group's EST tree and the bench's own."""
        for run in NO_ID_DEFAULT_RUNS + NO_ID_BENCH_TREE_RUNS:
            with self.subTest(run=run):
                if "-e2e-" in run:
                    code, last = verdict("demo", E2E / run)
                    self.assertTrue(
                        last.startswith("VERDICT PASS: all 10 Targets: credential acquired and admitted"), last
                    )
                    record = (E2E / run / "code-revs.txt").read_text()
                    cfg = json.loads((E2E / run / "e2e-attester.json").read_text())
                    self.assertFalse(cfg.get("bind_rrp_id", False), "the workload binds no RRP identifier")
                    self.assertNotIn("omit_rrp_id_binding", cfg, "the switch of 8 October is gone")
                else:
                    code, last = verdict("attacks", HW / run)
                    self.assertIn("every attack refused for its own reason", last)
                    revs = HW / run / "veraison-revs.txt"
                    record = (revs if revs.exists() else HW / run / "est-source.txt").read_text()
                    cases = json.loads((HW / run / "cases.json").read_text())
                    self.assertEqual({m["relying_party"] for m in cases}, {""}, "every case bound no identifier")
                self.assertEqual(code, 0, last)
                self.assertIn("estserver built from", record)
                if run in NO_ID_DEFAULT_RUNS:
                    self.assertIn("globalsign-est-transfer", record)
                    self.assertIn("7e4224ce421d", record)
                    self.assertIn("worktree clean", record)
                else:
                    self.assertIn("third_party/globalsign-est/src", record)
                    self.assertIn("+ 17 patch(es), tree 3b2cb1f71b2a: tested tree", record)

    def test_passes_made(self):
        """A redirection run is judged on the passes it made: both until 11 October 2026, the one without the identifier
        from 12 October (the identifier was ripped out of the code)."""
        both = {("with-rrp-id", "present-nonce", "ca1"): True, ("no-rrp-id", "present-nonce", "ca1"): True}
        self.assertEqual(verdict_mod.passes_made(both), ["with-rrp-id", "no-rrp-id"])
        self.assertEqual(verdict_mod.passes_made({("no-rrp-id", "absent-none", "ca2"): True}), ["no-rrp-id"])
        self.assertEqual(verdict_mod.passes_made({}), [])

    def test_conduit_redirect_drill(self):
        """The redirect drill is judged from the routing the run recorded and the CAI's results: with the copies sharing
        the first RRPs' PKI and keys the CAI admits what they return; with the second Vault's own keys it refuses the
        container for its origin; a certificate refused for its issuer would be the own-PKI regime, not measured yet."""
        import tempfile

        def run_dir(own_keys, results):
            d = Path(tempfile.mkdtemp())
            (d / "bench-logs").mkdir()
            routing = {
                "attack": "redirect",
                "copies_own_keys": own_keys,
                "targets": {
                    "https://db-nonce.tacra.example": {"rrp": "ca-2", "url": "https://127.0.0.1:9103"},
                    "https://ledger-nonce.tacra.example": {"rrp": "vault-2", "url": "https://127.0.0.1:9104"},
                },
            }
            (d / "bench-logs" / "est-routing.json").write_text(json.dumps(routing))
            (d / "results.json").write_text(json.dumps(results))
            return d

        cert = {
            "target": "https://db-nonce.tacra.example",
            "type": "x509",
            "ok": True,
            "cert_issuer": "TACRA bench CA Intermediate CA",
        }
        shared = run_dir(False, [cert, {"target": "https://ledger-nonce.tacra.example", "type": "api-key", "ok": True}])
        code, last = verdict("conduit", shared, "--attack", "redirect")
        self.assertEqual(code, 0, last)
        self.assertIn("each admitted: it issues under the PKI the first shares", last)
        own = run_dir(
            True,
            [
                cert,
                {
                    "target": "https://ledger-nonce.tacra.example",
                    "type": "api-key",
                    "ok": False,
                    "error": "cai: bundle: not signed by the trusted Vault key",
                },
            ],
        )
        code, last = verdict("conduit", own, "--attack", "redirect")
        self.assertEqual(code, 0, last)
        self.assertIn("refused by the CAI for its origin", last)
        wrong = run_dir(True, [cert, {"target": "https://ledger-nonce.tacra.example", "type": "api-key", "ok": True}])
        code, last = verdict("conduit", wrong, "--attack", "redirect")
        self.assertNotEqual(code, 0)
        self.assertIn("expected refused for the Vault key", last)

    def test_the_identifiers_ripped_out(self):
        """The runs of 11 October 2026 on the trees with the identifiers ripped out: a three-field binding, the group's EST tree and
        the bench's own; every attack run's cases record the layout and no identifier."""
        for run in RIPOUT_RUNS + RIPOUT_BENCH_TREE_RUNS:
            with self.subTest(run=run):
                if "-e2e-" in run:
                    code, last = verdict("demo", E2E / run)
                    self.assertTrue(
                        last.startswith("VERDICT PASS: all 10 Targets: credential acquired and admitted"), last
                    )
                    record = (E2E / run / "code-revs.txt").read_text()
                    cfg = json.loads((E2E / run / "e2e-attester.json").read_text())
                    self.assertFalse(
                        [k for k in cfg if "rrp_id" in k], "no identifier switch in the workload's configuration"
                    )
                else:
                    code, last = verdict("attacks", HW / run)
                    self.assertIn("every attack refused for its own reason", last)
                    revs = HW / run / "veraison-revs.txt"
                    record = (revs if revs.exists() else HW / run / "est-source.txt").read_text()
                    cases = json.loads((HW / run / "cases.json").read_text())
                    self.assertEqual({m["binding_layout"] for m in cases}, {"freshness-target-subject"})
                    self.assertFalse([m for m in cases if m.get("relying_party")], "no identifier bound")
                self.assertEqual(code, 0, last)
                self.assertIn("estserver built from", record)
                if run in RIPOUT_RUNS:
                    self.assertIn("globalsign-est-transfer", record)
                    self.assertIn("b5315560178f", record)
                    self.assertIn("worktree clean", record)
                else:
                    self.assertIn("third_party/globalsign-est/src", record)
                    self.assertIn("+ 18 patch(es), tree 09762d19ebc6: tested tree", record)

    def test_the_bench_on_the_group_s_master(self):
        """The runs of 11 October 2026, late evening, on the group's master (6f80871, the merge of pull request #4) with the bench's
        two patches, tree bfd8d3aa3ec6: the demo in both RATS models and the substitution suite, each run naming that tree."""
        for run in G3_MASTER_RUNS:
            with self.subTest(run=run):
                if "-e2e-" in run:
                    code, last = verdict("demo", E2E / run)
                    self.assertTrue(
                        last.startswith("VERDICT PASS: all 10 Targets: credential acquired and admitted"), last
                    )
                    record = (E2E / run / "code-revs.txt").read_text()
                    self.assertIn(
                        "globalsign-est/src upstream 6f8087199539 + 2 patch(es), tree bfd8d3aa3ec6: tested tree", record
                    )
                    cfg = json.loads((E2E / run / "e2e-attester.json").read_text())
                    self.assertFalse(
                        [k for k in cfg if "rrp_id" in k], "no identifier switch in the workload's configuration"
                    )
                else:
                    code, last = verdict("attacks", HW / run)
                    self.assertIn("every attack refused for its own reason", last)
                    revs = HW / run / "veraison-revs.txt"
                    record = (revs if revs.exists() else HW / run / "est-source.txt").read_text()
                    cases = json.loads((HW / run / "cases.json").read_text())
                    self.assertEqual({m["binding_layout"] for m in cases}, {"freshness-target-subject"})
                    self.assertFalse([m for m in cases if m.get("relying_party")], "no identifier bound")
                self.assertEqual(code, 0, last)
                self.assertIn("estserver built from", record)
                self.assertIn("third_party/globalsign-est/src", record)
                self.assertIn("commit 6f8087199539d4206ad96252c08fb945d66c0f79 Merge pull request #4", record)

    def test_aws_auxblob_host_fault_kept(self):
        """The host's fault of 11 October, kept with its README: every Target failed before the protocol began."""
        run = E2E / AWS_AUXBLOB_HOST_RUN
        code, last = verdict("demo", run)
        self.assertNotEqual(code, 0)
        self.assertTrue(last.startswith("VERDICT FAIL: 10 of 10 Targets not admitted"), last)
        results = json.loads((run / "results.json").read_text())
        self.assertTrue(all("could not read report auxblob" in r.get("error", "") for r in results))
        self.assertIn("A host's fault, kept", (run / "README.md").read_text())

    def test_conduit_redirect_drill_runs(self):
        """The redirect drill on hardware: the copies sharing the first RRPs' PKI and keys are admitted; the second Vault's own
        keys are refused for their origin; each run records the routing it ran under."""
        for run, own_keys in REDIRECT_DRILL_RUNS.items():
            with self.subTest(run=run):
                code, last = verdict("conduit", E2E / run, "--attack", "redirect")
                self.assertEqual(code, 0, last)
                self.assertIn("5 Enrollments served by the second Credential Authority, each admitted", last)
                if own_keys:
                    self.assertIn("each refused by the CAI for its origin: the keys are the second Vault's own", last)
                else:
                    self.assertIn("each admitted: the copy seals under the first Vault's keys", last)
                routing = json.loads((E2E / run / "bench-logs" / "est-routing.json").read_text())
                self.assertEqual(routing["copies_own_keys"], own_keys)
                self.assertEqual({v["rrp"] for v in routing["targets"].values()}, {"ca-2", "vault-2"})
                record = (E2E / run / "code-revs.txt").read_text()
                self.assertIn("b5315560178f", record)

    def test_conduit_verifier_drill(self):
        for run in VERIFIER_DRILL_RUNS:
            with self.subTest(run=run):
                code, last = verdict("conduit", E2E / run, "--attack", "verifier")
                self.assertEqual(code, 0, last)
                self.assertTrue(
                    last.startswith(
                        "VERDICT PASS: 5 Enrollments given Attestation Results signed again with the conduit's own verifier key"
                    ),
                    last,
                )
                self.assertTrue(last.endswith("; the 5 other Targets admitted"), last)
                acts = [
                    x
                    for x in (E2E / run / "bench-logs" / "est-conduit.log").read_text().splitlines()
                    if "conduit attack verifier: Enrollment for " in x
                ]
                self.assertEqual(len(acts), 5, "five acts logged")
                self.assertTrue(all("(SPKI SHA-256 " in x for x in acts), "each act names the conduit's key")

    def test_redirect(self):
        for run in REDIRECT_RUNS:
            with self.subTest(run=run):
                code, last = verdict("redirect", HW / run)
                self.assertEqual(code, 0, last)

    def test_redirect_variants(self):
        starts = {
            "own-epochs": "VERDICT PASS: ca2 with an epoch marker of its own: ",
            "start-ca2": "VERDICT PASS: the conduit starting at ca2: ",
            "vault": "VERDICT PASS: the Secret Vaults: ",
        }
        for run, variant in REDIRECT_VARIANT_RUNS.items():
            with self.subTest(run=run):
                code, last = verdict("redirect", HW / run)
                self.assertEqual(code, 0, last)
                self.assertTrue(last.startswith(starts[variant]), last)

    def test_redirect_replay(self):
        ends = {
            "replay": "the credential issued twice",
            "replay-vault": "the credential released twice",
        }
        for run, variant in REPLAY_RUNS.items():
            with self.subTest(run=run):
                code, last = verdict("redirect", HW / run)
                self.assertEqual(code, 0, last)
                self.assertTrue(last.startswith("VERDICT PASS: the same request twice at "), last)
                self.assertIn("the second offer with present-nonce refused for the Handle", last)
                self.assertTrue(last.endswith(ends[variant]), last)

    def test_replay_both_passes(self):
        for run, variant in REPLAY_BOTH_PASSES_RUNS.items():
            with self.subTest(run=run):
                code, last = verdict("redirect", HW / run)
                self.assertEqual(code, 0, last)
                rrp = "vault1" if variant == "replay-vault" else "ca1"
                self.assertTrue(last.startswith(f"VERDICT PASS: the same request twice at {rrp}: "), last)
                self.assertTrue(last.endswith(", with the RRP identifier bound and without it alike"), last)

    def test_demos_without_the_rrp_identifier(self):
        for run in NO_RRP_ID_DEMO_RUNS:
            with self.subTest(run=run):
                code, last = verdict("demo", E2E / run)
                self.assertEqual(code, 0, last)
                self.assertTrue(last.startswith("VERDICT PASS: all 10 Targets: credential acquired and admitted"), last)
                cfg = json.loads((E2E / run / "e2e-attester.json").read_text())
                self.assertTrue(cfg["omit_rrp_id_binding"], "the workload bound no RRP identifier")

    def test_attacks_without_the_rrp_identifier(self):
        for run in NO_RRP_ID_ATTACK_RUNS:
            with self.subTest(run=run):
                code, last = verdict("attacks", HW / run)
                self.assertEqual(code, 0, last)
                self.assertIn("every attack refused for its own reason", last)
                in_process = (
                    "rrpverify-tdx.json"
                    if (HW / run / "rrpverify-tdx.json").is_file()
                    else "rrpverify-veraison-v015.json"
                )
                for name in ("rrpverify-service.json", in_process):
                    report = json.loads((HW / run / name).read_text())
                    self.assertEqual((report["rrp_ca"], report["rrp_vault"]), ("", ""), name)
                    self.assertFalse(any(r["check"] == "other RRP identifier" for r in report["results"]), name)
                service = json.loads((HW / run / "rrpverify-service.json").read_text())["results"]
                self.assertEqual(len(service), 40, "four cases per request: no identifier to substitute")

    def test_the_runs_that_found_the_gaps_without_the_identifier(self):
        why = "VERDICT FAIL: 10 of 242 checks not as expected"
        self.assertEqual(verdict("attacks", HW / SERVICE_CASE_GAP_RUN), (1, why))
        why = "VERDICT FAIL: 120 of 212 checks not as expected"
        self.assertEqual(verdict("attacks", HW / AWS_VERIFY_FLAGS_GAP_RUN), (1, why))

    def test_drills_without_the_rrp_identifier(self):
        for run, attack in NO_RRP_ID_DRILL_RUNS.items():
            with self.subTest(run=run):
                code, last = verdict("conduit", E2E / run, "--attack", attack)
                self.assertEqual(code, 0, last)
                self.assertTrue(last.endswith("; the 5 other Targets admitted"), last)

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

    def test_clock_preplay_refused_with_400(self):
        # an RRP refuses a freshness element that is not valid now with 400; the committed run answered 409, and the
        # verdict judges a run with either answer the same way
        def every_409_is_400(d):
            for r in d["results"]:
                for edge in r.values():
                    if isinstance(edge, dict) and edge.get("status") == 409:
                        edge["status"] = 400

        as_committed = verdict("attacks", self.clock_run(lambda d: None))
        self.assertEqual(as_committed[0], 0, as_committed[1])
        for f in self.tmp.iterdir():
            shutil.rmtree(f) if f.is_dir() else f.unlink()
        self.assertEqual(verdict("attacks", self.clock_run(every_409_is_400)), as_committed)

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

    def drill(self, attack):
        run = next(r for r, a in CONTAINER_DRILL_RUNS.items() if a == attack)
        return self.copy(E2E / run, "results.json", "caapi-est.log")

    def test_conduit_seal_secret_taken(self):
        run = self.drill("seal")
        self.edit_json("results.json", lambda rs: rs[5].update(ok=True, secret_sha256="0" * 64))
        code, last = verdict("conduit", run, "--attack", "seal")
        self.assertEqual(code, 1, last)
        self.assertIn("a secret taken from what the conduit returned", last)

    def test_conduit_refused_for_another_reason(self):
        run = self.drill("hint-group")
        self.edit_json("results.json", lambda rs: rs[6].update(error="403 RRP vault: credential-hint: no group"))
        code, last = verdict("conduit", run, "--attack", "hint-group")
        self.assertEqual(code, 1, last)
        self.assertIn("refused, but not for", last)

    def test_conduit_swap_first_refused(self):
        run = self.drill("swap")
        first = next(
            line.split("Retrieval for ", 1)[1].split(": ", 1)[0]
            for line in (run / "caapi-est.log").read_text().splitlines()
            if "the first Retrieval" in line
        )
        self.edit_json("results.json", lambda rs: [r.update(ok=False) for r in rs if r["target"] == first])
        code, last = verdict("conduit", run, "--attack", "swap")
        self.assertEqual(code, 1, last)
        self.assertIn("the first Retrieval, given its own container, not admitted", last)

    def test_conduit_enrollment_not_admitted(self):
        run = self.drill("seal")
        self.edit_json("results.json", lambda rs: rs[0].update(ok=False))
        code, last = verdict("conduit", run, "--attack", "seal")
        self.assertEqual(code, 1, last)
        self.assertIn("not acted on, and not admitted", last)

    def test_conduit_judged_as_another_drill(self):
        run = self.drill("seal")
        code, last = verdict("conduit", run, "--attack", "hint")
        self.assertEqual(code, 1, last)
        self.assertIn("names no Retrieval it acted on in the drill 'hint'", last)

    def test_conduit_without_its_log(self):
        run = self.drill("swap")
        (run / "caapi-est.log").unlink()
        code, last = verdict("conduit", run, "--attack", "swap")
        self.assertEqual(code, 1, last)
        self.assertIn("names no Retrieval it acted on", last)

    def test_redirect_missing_outcome(self):
        run = self.copy(HW / REDIRECT_RUNS[0], "results.jsonl")
        lines = (run / "results.jsonl").read_text().splitlines()
        (run / "results.jsonl").write_text("\n".join(lines[1:]) + "\n")
        self.assertEqual(verdict("redirect", run), (1, "VERDICT FAIL: 1 of 20 outcomes not as expected"))

    def variant_run(self, variant):
        run = next(r for r, v in REDIRECT_VARIANT_RUNS.items() if v == variant)
        return self.copy(HW / run, "results.jsonl", "variant.txt")

    def change_cell(self, run, cell, result):
        rows = [json.loads(x) for x in (run / "results.jsonl").read_text().splitlines()]
        for r in rows:
            if (r["pass"], r["kind"], r["rrp"]) == cell:
                r["result"] = result
        (run / "results.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    def test_redirect_variant_issued(self):
        # start-ca2: ca2 issues on a Handle it minted, though the binding names ca1
        run = self.variant_run("start-ca2")
        self.change_cell(run, ("with-rrp-id", "present-nonce", "ca2"), {"issued": True, "status": 200})
        code, lines = verdict_lines("redirect", run)
        self.assertEqual((code, lines[-1]), (1, "VERDICT FAIL: 1 of 20 outcomes not as expected"))
        self.assertIn("with-rrp-id present-nonce ca2: ISSUED, expected refused for the binding", lines)

    def test_redirect_variant_refused_for_another_reason(self):
        # own-epochs: ca2 refuses present-epoch, for a Handle instead of its epoch marker
        run = self.variant_run("own-epochs")
        handle = "freshness fresh: freshness element is not valid now: unknown or already used Handle"
        self.change_cell(run, ("no-rrp-id", "present-epoch", "ca2"), {"issued": False, "status": 409, "reason": handle})
        code, lines = verdict_lines("redirect", run)
        self.assertEqual((code, lines[-1]), (1, "VERDICT FAIL: 1 of 20 outcomes not as expected"))
        self.assertIn(f"no-rrp-id present-epoch ca2: refused ({handle}), expected refused for the epoch", lines)

    def test_redirect_vault_released_with_the_rrp_id(self):
        # vault: vault2 releases on Evidence that binds vault1
        run = self.variant_run("vault")
        self.change_cell(run, ("with-rrp-id", "absent-none", "vault2"), {"issued": True, "status": 200})
        code, lines = verdict_lines("redirect", run)
        self.assertEqual((code, lines[-1]), (1, "VERDICT FAIL: 1 of 20 outcomes not as expected"))
        self.assertIn("with-rrp-id absent-none vault2: ISSUED, expected refused for the binding", lines)

    def test_redirect_variant_judged_as_the_other(self):
        run = self.variant_run("own-epochs")
        (run / "variant.txt").write_text("start-ca2\n")
        code, last = verdict("redirect", run)
        self.assertEqual(code, 1, last)

    def test_redirect_variant_without_its_name(self):
        # without variant.txt a run is judged as the default experiment, whose table a variant's run does not match
        run = self.variant_run("own-epochs")
        (run / "variant.txt").unlink()
        code, last = verdict("redirect", run)
        self.assertEqual(code, 1, last)

    def test_redirect_unknown_variant(self):
        run = self.variant_run("own-epochs")
        (run / "variant.txt").write_text("own-nonces\n")
        self.assertEqual(verdict("redirect", run), (1, "VERDICT FAIL: unknown variant 'own-nonces' (variant.txt)"))

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
