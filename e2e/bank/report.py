#!/usr/bin/env python3
"""Write README.md for a Demo Bank evidence directory from what the run left there: the machines, the code revisions,
each run's steps, verdict and receipt, the servers' own log lines for that run, the ledger audit and the teardown.

    python3 e2e/bank/report.py e2e/evidence/<stamp>-demo-bank
"""

import json
import os
import re
import sys
from pathlib import Path

E = sys.argv[1]
out = []
w = out.append


def read(*p, default=""):
    try:
        return open(os.path.join(E, *p)).read()
    except OSError:
        return default


w("# Demo Bank: TACRA end to end on real hardware\n")
w(
    "Demo Bank is fictional: its names, accounts and amounts are made up. Every server of the bank ran in the cloud; the "
    "operator's machine only built the programs, created the VMs and collected this evidence.\n"
)
bank = read("bank.txt").split()
if bank:
    w(f"The bank: `{bank[0]}`, from its pack `{bank[1]}` (SHA-256 `{bank[2][:16]}…`).\n")
w("## Machines\n")
w("```\n" + read("up", "machines.txt").strip() + "\n```\n")
w(
    "Trust zone: Veraison (sevsnp scheme, reference values for the approved launches), step-ca, Vault, the Credential "
    "Authority and Secret Vault gateways, the TDX verifier, the EST server (the only port workloads reach). Core: the "
    "ledger (PostgreSQL; the payment service's role logs in only by a client certificate from the bank's workload CA) "
    "and the fraud-scoring service (pre-shared API key). The payment service holds no credential of its own.\n"
)
w(
    "Configuration: written by the bench's own program, `scripts/trustzone.py`, from `packs/demo-bank` and the approved "
    "launches, as on the bench: mutual TLS between the components (tacra-est N23), the verifiers' EAR keys given to the "
    "gateways as files (N24), the API key released in the signed container (MLKEM768-P256, signed by the Vault). "
    f"RATS model: {read('rats-model.txt').strip() or '(not recorded)'}.\n"
)
fa = read("up", "failed-attempts.txt").strip()
if fa:
    w("Attempts that failed before the bank came up (`up/failed-attempts.txt`):\n\n```\n" + fa + "\n```\n")
w("## Code\n")
w("```\n" + read("code-revs.txt").strip() + "\n```\n")

runs_dir = os.path.join(E, "runs")
runs = sorted(os.listdir(runs_dir)) if os.path.isdir(runs_dir) else []
w("## Runs\n")


def what_happened(r):
    rep = read("runs", r, "report.json")
    if not rep:
        return ""
    rj = json.loads(rep)
    if rj.get("receipt"):
        return f"transfer {rj['receipt']['transfer_id']} committed"
    bad = [s for s in rj["steps"] if not s["ok"]]
    if rj["mode"] == "imposter":
        out = [bad[0]["step"] + ": no attestation provider"] if bad else []
        for s in rj["steps"]:
            m = re.search(r"(FATAL: [^(]*|HTTP \d+: [a-z ]+)", s.get("note") or "")
            if s["ok"] and m:
                out.append(s["step"] + ": " + m.group(1).strip())
        return "; ".join(out)
    if bad:
        err = " ".join(bad[0].get("error", "").split())
        m = re.search(r"(403 .*)", err)
        summary = bad[0]["step"] + ": " + (m.group(1) if m else err)[:110]
        if "TDX" in err:
            mm = re.search(r"MRTD ([0-9a-f]{16})", read("runs", r, "trust-logs", "tdx-verifier.log"))
            summary += f" (MRTD {mm.group(1)}… not approved yet)" if mm else " (the verifier did not log the MRTD yet)"
        return summary
    return ""


w("| run | expected | verdict | what happened |\n|---|---|---|---|")
for r in runs:
    v = read("runs", r, "verdict.txt")
    m = re.search(r"^VERDICT (.*)$", v, re.MULTILINE)
    kind = r.split("-", 1)[1]
    exp = {
        "gcp-snp": "payment",
        "gcp-tdx": "payment",
        "aws-snp": "payment",
        "ordinary": "refusal",
        "unapproved": "refusal",
    }.get(kind, "?")
    w(f"| `{r}` | {exp} | {m.group(1) if m else 'no verdict'} | {what_happened(r).replace('|', '/')} |")
w("")
unpaid = [
    r
    for r in runs
    if r.split("-", 1)[-1] in ("gcp-snp", "gcp-tdx", "aws-snp") and "VERDICT PASS" not in read("runs", r, "verdict.txt")
]
if unpaid:
    w(
        f"{len(unpaid)} run(s) on a confidential VM did not pay: "
        + ", ".join(f"`{r}`" for r in unpaid)
        + ". The reason "
        "is in each run's section below; a firmware build approved during the run is under the reference values.\n"
    )
for r in runs:
    w(f"### {r}\n")
    inst = read("runs", r, "instance.yaml") or read("runs", r, "instance.txt")
    if inst:
        w("```\n" + inst.strip() + "\n```\n")
    rep = read("runs", r, "report.json")
    if rep:
        rj = json.loads(rep)
        w("| step | ok | ms | note |\n|---|---|---|---|")
        for s in rj["steps"]:
            note = " ".join(((s.get("note") or "") + ((" — " + s["error"]) if s.get("error") else "")).split())
            w(f"| {s['step']} | {'yes' if s['ok'] else 'no'} | {s['ms']:.1f} | {note.replace('|', '/')} |")
        w("")
        if rj.get("receipt"):
            w("Receipt (as the ledger returned it):\n\n```json\n" + json.dumps(rj["receipt"], indent=1) + "\n```\n")
    tl = os.path.join(runs_dir, r, "trust-logs")
    cl = os.path.join(runs_dir, r, "core-logs")
    picks = []
    vts = os.path.join(tl, "veraison-vts.log")
    if os.path.exists(vts):
        with open(vts, errors="replace") as fh:
            lines = list(fh)
        for line in lines:
            if "evaluated attestation result" in line:
                try:
                    j = json.loads(line.split('"attestation-result": ', 1)[1].rstrip()[:-1])
                    sm = j["submods"]["SEVSNP"]
                    tv = {k: v for k, v in sm.get("ear.trustworthiness-vector", {}).items() if v}
                    picks.append(f"veraison: SEVSNP {sm['ear.status']} {tv}")
                except (ValueError, KeyError, IndexError):
                    pass
    for d, names, pat in (
        (tl, ("ca-gateway", "vault-gateway", "tdx-verifier"), r"enrolled|released|refus|denied|appraisal"),
        (cl, ("postgresql", "fraud-api"), r"authenticated|authorized|FATAL|score|refused|certificate"),
    ):
        for n in names:
            p = os.path.join(d, n + ".log")
            if os.path.exists(p):
                with open(p, errors="replace") as fh:
                    lines = list(fh)
                for line in lines:
                    if re.search(pat, line, re.IGNORECASE):
                        picks.append(f"{n}: {line.rstrip()[:260]}")
    if picks:
        w(
            "Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):\n\n```\n"
            + "\n".join(picks[:60])
            + "\n```\n"
        )
    gone = read("runs", r, "vm-deleted.txt").strip()
    if gone:
        w("Deleted after the run: " + gone.replace("\n", "; ") + "\n")

w("## Reference values: Google's signed firmware endorsements\n")
rv = os.path.join(E, "refvals")
if os.path.isdir(rv):
    w(
        "Each approved GCP launch measurement was checked with `rrp/cmd/gce-endorsement` (google/gce-tcb-verifier) against "
        "Google's signed VMLaunchEndorsement, verified to the pinned root GCE-cc-tcb-root "
        "(SHA-256 e876bc69…f18c, fetched from https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt).\n"
    )
    w("| technology | measurement | endorsed | firmware built | SVN | launch | note |\n|---|---|---|---|---|---|---|")
    for f in sorted(os.listdir(rv)):
        if not f.endswith(".json"):
            continue
        j = json.loads(Path(rv, f).read_text())
        launch = f"{j['launch_vmsas']} vCPUs" if j.get("launch_vmsas") else ""
        note = "approved during the run" if not f.startswith("initial-") else "approved at start"
        if not j["endorsed"]:
            note = j.get("reason", "") + (
                "; approved at start on an earlier run's observation (trust on first use)"
                if f.startswith("initial-")
                else ""
            )
        w(
            f"| {j['technology']} | `{j['measurement'][:16]}…` | {'yes' if j['endorsed'] else 'no'} | {j.get('timestamp', '')} | "
            f"{j.get('svn', '')} | {launch} | {note} |"
        )
    w("")
    pc = read("refvals", "policy-changes.txt")
    if pc:
        w("Policy change applied on the trust zone:\n\n```\n" + pc.strip() + "\n```\n")

w("## Ledger audit\n")
w("```\n" + (read("audit", "ledger.txt").strip() or "(not taken)") + "\n```\n")
w("## Teardown\n")
w("```\n" + (read("teardown.txt").strip() or "(not yet)") + "\n```\n")
w("## Notes\n")
w(
    "- Provisioning, not the protocol: the fraud service's API key was handed from the core VM to the trust zone by "
    "piping it through the operator's console (`gcloud compute ssh ... | gcloud compute ssh ...`), on each provisioning, "
    "never written to the console's disk; the file on the trust zone was deleted after loading into Vault. Every payment "
    "then got the key only through TACRA.\n"
    "- step-ca logs the one-time token of each signing request; `demo-bank.sh` redacts the tokens in "
    "`trust-logs/step-ca.log` (single-use and expired) before the per-run `sha256sums.txt` is computed.\n"
    "- `TLS handshake error from 127.0.0.1` lines in the fraud service's log are the start script's port checks.\n"
)
w("## Limits of this demonstration\n")
w(
    "- GCP reference values are Google-endorsed (above); the AWS launch measurement is still the value observed in an "
    "earlier run (trust on first use): Google does not endorse AWS firmware, and AWS's own firmware measurements were "
    "not computed here.\n"
    "- Approving a newly endorsed firmware is an operator step (`demo-bank.sh approve`); the verifier does not yet "
    "consult the endorsements by itself.\n"
    "- The TDX path uses our own verifier (go-tdx-guest against Intel PCS); Veraison in the SIG's fork has no TDX scheme.\n"
    "- The trust zone runs in a SEV-SNP confidential VM, but in this demonstration it does not attest itself to anyone.\n"
    "- Vault runs with a single unseal key on the trust-zone disk; a bank would use an HSM or cloud KMS auto-unseal.\n"
)
Path(E, "README.md").write_text("\n".join(out) + "\n")
print(os.path.join(E, "README.md"))
