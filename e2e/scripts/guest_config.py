#!/usr/bin/env python3
"""The workload's configuration for an end-to-end run in a confidential guest, one file for every cloud script
(gcp-snp-e2e.sh, aws-snp-e2e.sh). Two copies of this block drifted: the AWS one lacked vault_signers, the
hpke-base-signed container's trust anchor, from 01.10 on, so Retrieval on AWS failed (evidence
20261006T160234Z-aws-sev-snp-e2e). Public material only: trust anchors, the Vault's public keys, the epoch marker.

    TEE=sev-snp|tdx B=$BENCH_HOME BIN=<dir holding origin-keys.json> [TARGETS=all|other-platform] \
        python3 e2e/scripts/guest_config.py

The Targets, the RRP identifiers and the workload's name come from the bench's pack (packs/tacra-bench/pack.json).
TARGETS=all (the default): the Targets every platform's verifier serves. TARGETS=other-platform: the Targets that
take other platforms' verifiers only, which must refuse this platform's Evidence (tacra-est N24). Each Target is
asked for the credential its RRP issues. The workload's Evidence binds the freshness element, the Target and the subject,
no identifier of any party (the group's decision of 6 and 11 October 2026, TheBankster/rats-tacra#20); the RRP names in
relying_parties key the trust anchors the workload holds.
"""

import json
import os
from pathlib import Path

B, BIN = Path(os.environ["B"]), Path(os.environ["BIN"])
VERIFIER = {"sev-snp": "veraison", "tdx": "tdx"}[os.environ["TEE"]]  # the verifier of this platform
SELECT = {
    "all": lambda verifiers: verifiers == "all",
    "other-platform": lambda verifiers: verifiers != "all" and VERIFIER not in verifiers,
}[os.environ.get("TARGETS") or "all"]
pack = json.loads((Path(__file__).resolve().parents[2] / "packs" / "tacra-bench" / "pack.json").read_text())
rrps = {r["name"]: r for r in pack["rrps"] if "same_as" not in r}
ca = next(r["rrp_id"] for r in rrps.values() if r["kind"] == "credential-authority")
vault = next(r["rrp_id"] for r in rrps.values() if r["kind"] == "secret-vault")
issues = {"credential-authority": "x509", "secret-vault": "api-key"}
targets = [
    {"target": t["target"], "type": issues[rrps[t["rrp"]]["kind"]]} for t in pack["targets"] if SELECT(t["verifiers"])
]
rp = {t["target"]: ({"enroll": ca} if t["type"] == "x509" else {"retrieve": vault}) for t in targets}
keys = json.loads((BIN / "origin-keys.json").read_text())
cfg = {
    "tee": os.environ["TEE"],
    "caapi": "127.0.0.1:50061",
    "hint": pack["workload"]["hint"],
    "targets": targets,
    "relying_parties": rp,
    "vault_origins": {vault: {k: v for k, v in keys.items() if k.startswith("DHKEM")}},
    # the hpke-base-signed container's trust anchor: the Vault's signature key, held for its RRP identifier
    "vault_signers": {vault: keys["ECDSA-P256-SHA256"]},
    # tacra-est N15: the CA the CAI holds for Enrollment, the bench's step-ca intermediate (public)
    "ca_anchors": {ca: (B / "step" / "certs" / "intermediate_ca.crt").read_text()},
    "local_epoch_hex": (B / "epoch.hex").read_text().strip(),
    "rup": {"url": "https://localhost:19443", "anchor_pem": (B / "tls" / "root.crt").read_text()},
}
(BIN / "e2e-attester.json").write_text(json.dumps(cfg, indent=1))
