#!/usr/bin/env python3
"""The workload's configuration for an end-to-end run in a confidential guest, one file for every cloud script
(gcp-snp-e2e.sh, aws-snp-e2e.sh). Two copies of this block drifted: the AWS one lacked vault_signers, the
hpke-base-signed container's trust anchor, from 01.10 on, so Retrieval on AWS failed (evidence
20261006T160234Z-aws-sev-snp-e2e). Public material only: trust anchors, the Vault's public keys, the epoch marker.

    TEE=sev-snp|tdx|sim B=$BENCH_HOME BIN=<dir holding origin-keys.json> python3 e2e/scripts/guest_config.py

The Targets, the RRP identifiers and the workload's name come from the bench's pack (packs/tacra-bench/pack.json):
the Targets every platform's verifier serves, each asked for the credential its RRP issues.
"""
import json, os
B, BIN = os.environ["B"], os.environ["BIN"]
pack = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "packs", "tacra-bench", "pack.json")))
rrps = {r["name"]: r for r in pack["rrps"] if "same_as" not in r}
ca = next(r["rrp_id"] for r in rrps.values() if r["kind"] == "credential-authority")
vault = next(r["rrp_id"] for r in rrps.values() if r["kind"] == "secret-vault")
issues = {"credential-authority": "x509", "secret-vault": "api-key"}
targets = [{"target": t["target"], "type": issues[rrps[t["rrp"]]["kind"]]} for t in pack["targets"] if t["verifiers"] == "all"]
rp = {t["target"]: ({"enroll": ca} if t["type"] == "x509" else {"retrieve": vault}) for t in targets}
keys = json.load(open(f"{BIN}/origin-keys.json"))
cfg = {"tee": os.environ["TEE"], "caapi": "127.0.0.1:50061", "hint": pack["workload"]["hint"],
       "targets": targets, "relying_parties": rp,
       "vault_origins": {vault: {k: v for k, v in keys.items() if k.startswith("DHKEM")}},
       # the hpke-base-signed container's trust anchor: the Vault's signature key, held for its RRP identifier
       "vault_signers": {vault: keys["ECDSA-P256-SHA256"]},
       # tacra-est N15: the CA the CAI holds for Enrollment, the bench's step-ca intermediate (public)
       "ca_anchors": {ca: open(f"{B}/step/certs/intermediate_ca.crt").read()},
       "local_epoch_hex": open(f"{B}/epoch.hex").read().strip(),
       "rup": {"url": "https://localhost:19443", "anchor_pem": open(f"{B}/tls/root.crt").read()}}
json.dump(cfg, open(f"{BIN}/e2e-attester.json", "w"), indent=1)
