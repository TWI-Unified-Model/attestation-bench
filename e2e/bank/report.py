#!/usr/bin/env python3
"""Write README.md for a Demo Bank evidence directory from what the run left there: the machines, the code revisions,
each run's steps, verdict and receipt, the servers' own log lines for that run, the ledger audit and the teardown.

    python3 e2e/bank/report.py e2e/evidence/<stamp>-demo-bank
"""
import json, os, re, sys

E = sys.argv[1]
out = []
w = out.append


def read(*p, default=""):
    try:
        return open(os.path.join(E, *p)).read()
    except OSError:
        return default


w("# Demo Bank: TACRA end to end on real hardware\n")
w("Demo Bank is fictional: its names, accounts and amounts are made up. Every server of the bank ran in the cloud; the "
  "operator's machine only built the programs, created the VMs and collected this evidence.\n")
w("## Machines\n")
w("```\n" + read("up", "machines.txt").strip() + "\n```\n")
w("Trust zone: Veraison (sevsnp scheme, reference values for the approved launches), step-ca, Vault, the Credential "
  "Authority and Secret Vault gateways, the TDX verifier, the EST server (the only port workloads reach). Core: the "
  "ledger (PostgreSQL; the payment service's role logs in only by a client certificate from the bank's workload CA) "
  "and the fraud-scoring service (pre-shared API key). The payment service holds no credential of its own.\n")
w("## Code\n")
w("```\n" + read("code-revs.txt").strip() + "\n```\n")

runs_dir = os.path.join(E, "runs")
runs = sorted(os.listdir(runs_dir)) if os.path.isdir(runs_dir) else []
w("## Runs\n")
w("| run | expected | verdict |\n|---|---|---|")
for r in runs:
    v = read("runs", r, "verdict.txt")
    m = re.search(r"^VERDICT (.*)$", v, re.M)
    kind = r.split("-", 1)[1]
    exp = {"gcp-snp": "payment", "gcp-tdx": "payment", "aws-snp": "payment", "ordinary": "refusal",
           "unapproved": "refusal"}.get(kind, "?")
    w(f"| `{r}` | {exp} | {m.group(1) if m else 'no verdict'} |")
w("")
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
            note = (s.get("note") or "") + ((" — " + s["error"]) if s.get("error") else "")
            w(f"| {s['step']} | {'yes' if s['ok'] else 'no'} | {s['ms']:.1f} | {note.replace('|', '/')} |")
        w("")
        if rj.get("receipt"):
            w("Receipt (as the ledger returned it):\n\n```json\n" + json.dumps(rj["receipt"], indent=1) + "\n```\n")
    tl = os.path.join(runs_dir, r, "trust-logs")
    cl = os.path.join(runs_dir, r, "core-logs")
    picks = []
    for d, names, pat in ((tl, ("ca-gateway", "vault-gateway", "tdx-verifier", "est-server", "est"),
                           r"issued|released|refus|denied|admit|enroll|retriev|initiate|affirm|EAR|nonce|error"),
                          (cl, ("postgresql", "fraud-api"), r"authenticated|authorized|FATAL|score|refused|certificate")):
        for n in names:
            p = os.path.join(d, n + ".log")
            if os.path.exists(p):
                for line in open(p, errors="replace"):
                    if re.search(pat, line, re.I):
                        picks.append(f"{n}: {line.rstrip()[:260]}")
    if picks:
        w("Server log lines for this run (full slices in `trust-logs/` and `core-logs/`):\n\n```\n" +
          "\n".join(picks[:60]) + "\n```\n")
    gone = read("runs", r, "vm-deleted.txt").strip()
    if gone:
        w("Deleted after the run: " + gone.replace("\n", "; ") + "\n")

w("## Ledger audit\n")
w("```\n" + (read("audit", "ledger.txt").strip() or "(not taken)") + "\n```\n")
w("## Teardown\n")
w("```\n" + (read("teardown.txt").strip() or "(not yet)") + "\n```\n")
w("## Limits of this demonstration\n")
w("- Reference values for the approved launches are the measurements of earlier runs of the same machine types "
  "(trust on first use), not values signed by the firmware vendor.\n"
  "- The TDX path uses our own verifier (go-tdx-guest against Intel PCS); Veraison in the SIG's fork has no TDX scheme.\n"
  "- The trust zone runs in a SEV-SNP confidential VM, but in this demonstration it does not attest itself to anyone.\n"
  "- Vault runs with a single unseal key on the trust-zone disk; a bank would use an HSM or cloud KMS auto-unseal.\n")
open(os.path.join(E, "README.md"), "w").write("\n".join(out) + "\n")
print(os.path.join(E, "README.md"))
