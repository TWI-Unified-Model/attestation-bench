#!/usr/bin/env python3
"""The workload's configuration for an end-to-end run in a confidential guest, one file for every cloud script
(gcp-snp-e2e.sh, aws-snp-e2e.sh). Two copies of this block drifted: the AWS one lacked vault_signers, the
hpke-base-signed container's trust anchor, from 01.10 on, so Retrieval on AWS failed (evidence
20261006T160234Z-aws-sev-snp-e2e). Public material only: trust anchors, the Vault's public keys, the epoch marker.

    TEE=sev-snp|tdx B=$BENCH_HOME BIN=<dir holding origin-keys.json> python3 e2e/scripts/guest_config.py
"""
import json, os
B, BIN = os.environ["B"], os.environ["BIN"]
kinds = ["nonce", "epoch", "lepoch", "time", "none"]
targets = [{"target": f"https://db-{k}.tacra.example", "type": "x509"} for k in kinds] + \
          [{"target": f"https://ledger-{k}.tacra.example", "type": "api-key"} for k in kinds]
rp = {t["target"]: ({"enroll": "https://ca1.tacra.example"} if "/db-" in t["target"] else {"retrieve": "https://vault1.tacra.example"}) for t in targets}
cfg = {"tee": os.environ["TEE"], "caapi": "127.0.0.1:50061", "hint": "payments.workload.tacra.example",
       "targets": targets, "relying_parties": rp,
       "vault_origins": {"https://vault1.tacra.example": {k: v for k, v in json.load(open(f"{BIN}/origin-keys.json")).items()
                                                          if k.startswith("DHKEM")}},
       # the hpke-base-signed container's trust anchor: the Vault's signature key, held for its RRP identifier
       "vault_signers": {"https://vault1.tacra.example": json.load(open(f"{BIN}/origin-keys.json"))["ECDSA-P256-SHA256"]},
       # tacra-est N15: the CA the CAI holds for Enrollment, the bench's step-ca intermediate (public)
       "ca_anchors": {"https://ca1.tacra.example": open(f"{B}/step/certs/intermediate_ca.crt").read()},
       "local_epoch_hex": open(f"{B}/epoch.hex").read().strip(),
       "rup": {"url": "https://localhost:19443", "anchor_pem": open(f"{B}/tls/root.crt").read()}}
json.dump(cfg, open(f"{BIN}/e2e-attester.json", "w"), indent=1)
