#!/usr/bin/env python3
"""The pre-play check of an attack run: Evidence a guest made with its wall clock moved, presented to the running
bench's RRPs through the EST server, as a workload reaches them.

An RRP accepts an absent-timestamp element ts when now - max_age <= ts <= now + clock_skew (rrp/internal/fresh), with
max_age and clock_skew from the Target's policy, and keeps no record of it: the same Evidence is taken as often as it
is offered inside that window. The guest (hwcheck/scripts/preplay-guest.sh) made two sets:

- ahead: its clock OFFSET seconds ahead, Evidence of all five Freshness Kinds, an Enrollment at the Credential
  Authority and a Retrieval at the Secret Vault each, with the Handles the live RRPs minted for it (prepare);
- behind: its clock OFFSET seconds behind, absent-timestamp Evidence of both modes.

present offers every one at once; then each absent-timestamp Evidence of the ahead set two seconds into its window,
two seconds before the window closes, and two seconds after; then the behind set again. What the kinds other than
absent-timestamp get at once shows whether they rest on the guest's clock; the absent-timestamp answers measure the
window, which is not a pass: it is the exposure of a freshness that rests on the guest's clock, which the guest's root
and the host that serves the guest its time can set (docs/limits.md, "Time"). scripts/verdict.py judges the answers.

    hwcheck/scripts/preplay.py prepare RUN_DIR [--home BENCH_HOME]    before the guest's step
    hwcheck/scripts/preplay.py present RUN_DIR [--home BENCH_HOME]    after it, as soon as its Evidence is back

prepare mints the Handles through the EST server (attest-initiate) and writes RUN_DIR/preplay/handles.json,
ca-targets.json and vault-targets.json, for the guest. present reads RUN_DIR/preplay/{ahead,behind} and
rrp-clock-window.txt (this machine's clock around the guest's step) and the live policies (BENCH_HOME/config), and
writes RUN_DIR/preplay.json.
"""

import argparse
import base64
import http.client
import json
import os
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

PROFILE = "application/vnd.veraison.tsm-report+cbor"
KINDS = ("present-nonce", "present-epoch", "absent-epoch", "absent-timestamp", "absent-none")
SHORT = {"present-nonce": "nonce", "present-epoch": "epoch", "absent-epoch": "lepoch", "absent-timestamp": "time",
         "absent-none": "none"}  # fmt: skip
# per guest directory: the mode, the Targets' prefix, the gateway whose policy applies, the credential type, the
# request's subject field and the resource's media type
SIDES = {
    "ca": ("enroll", "db", "ca-gateway", "x509", "csr", "application/est-attest-enroll+json"),
    "vault": ("retrieve", "ledger", "vault-gateway", "api-key", "cek_pub", "application/est-attest-retrieve+json"),
}
MARGIN = 2  # seconds inside or outside a window edge, by this machine's clock, which is the RRPs'


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def target(side, kind):
    return f"https://{SIDES[side][1]}-{SHORT[kind]}.tacra.example"


class EST:
    """The bench's EST server, over TLS 1.3 under the bench's TLS root, as a workload reaches it."""

    def __init__(self, home):
        cfg = json.loads(Path(home, "config", "est-server.json").read_text())
        host, port = cfg["tls"]["listen_address"].rsplit(":", 1)
        self.host, self.port = host, int(port)
        self.ctx = ssl.create_default_context(cafile=str(Path(home, "tls", "root.crt")))
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    def call(self, method, path, body=None, ctype=None):
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=120)
        try:
            conn.request(method, "/.well-known/est" + path, body=body, headers={"Content-Type": ctype} if ctype else {})
            resp = conn.getresponse()
            return resp.status, resp.read().decode(errors="replace").strip()
        finally:
            conn.close()

    def initiate(self, tgt, ctype):
        return self.call("GET", "/attest-initiate?" + urlencode({"target": tgt, "credential_type": ctype}))


def prepare(run, home):
    """The Handles the live RRPs mint for the ahead set: present-nonce, one per mode; the epoch, which present-epoch and
    absent-epoch both take and both RRPs share."""
    est, pre = EST(home), run / "preplay"
    pre.mkdir(parents=True, exist_ok=True)
    answers, handles, epochs = {}, {}, set()
    for side, (mode, _, _, ctype, _, _) in SIDES.items():
        for kind in ("present-nonce", "present-epoch"):
            st, answer = est.initiate(target(side, kind), ctype)
            answers[target(side, kind)] = {"status": st, "answer": answer[:400]}
            if st != 200:
                sys.exit(f"attest-initiate {target(side, kind)}: HTTP {st}: {answer[:200]}")
            handle = unb64u(json.loads(answer)["handle"])
            if kind == "present-nonce":
                handles[f"nonce_{mode}"] = base64.b64encode(handle).decode()
            else:
                epochs.add(handle)
    if len(epochs) != 1:
        sys.exit(f"the RRPs answered {len(epochs)} different epochs; the guest's Evidence takes one")
    handles["epoch"] = base64.b64encode(epochs.pop()).decode()
    handles["minted_at"] = int(time.time())
    (pre / "handles.json").write_text(json.dumps(handles) + "\n")
    (pre / "initiate.json").write_text(json.dumps(answers, indent=1) + "\n")
    for side in SIDES:
        (pre / f"{side}-targets.json").write_text(json.dumps({k: target(side, k) for k in KINDS}) + "\n")
    print(f"Handles minted through the EST server for {', '.join(answers)}")


def entries_of(pre, home, set_name):
    """The Evidence of one set, with what each request carries and the policy that judges it."""
    out = []
    for side, (mode, _, gateway, ctype, field, media) in SIDES.items():
        d = pre / set_name / side
        if not d.exists():
            continue
        for case_dir in sorted(p for p in d.iterdir() if p.is_dir()):
            meta = json.loads((case_dir / "meta.json").read_text())
            kind, tgt = meta["freshness_kind"], meta["target"]
            policy = json.loads(Path(home, "config", f"{gateway}.json").read_text())["targets"][tgt]
            # the Credential Hint, as the bench's workload sends it: the Target's one identity (a Credential Authority)
            # or credential group (a Secret Vault)
            names = list(policy.get("identities") or policy.get("groups") or {})
            if len(names) != 1:
                sys.exit(f"{tgt}: {len(names)} identities or credential groups in the policy; the check needs one")
            element = unb64u(meta.get("freshness_element_b64") or "")
            body = {"target": tgt, "credential_type": ctype, "freshness_kind": kind,
                    field: b64u((case_dir / "subject.der").read_bytes()),
                    "evidence": b64u((case_dir / "evidence.tsm.cbor").read_bytes()),
                    "binding": {"method": "binding-input", "hash": "sha512"}, "profile": PROFILE,
                    "credential_hint": names[0]}  # fmt: skip
            if element:
                body["handle"] = b64u(element)
            e = {"set": set_name, "target": tgt, "rrp": gateway, "mode": mode, "kind": kind, "case": meta["case"],
                 "body": json.dumps(body).encode(), "media": media}  # fmt: skip
            if kind == "absent-timestamp":
                e |= {"timestamp": int.from_bytes(element, "big"), "max_age_s": policy["max_age"],
                      "clock_skew_s": policy["clock_skew"]}  # fmt: skip
            out.append(e)
    return out


def present(run, home):
    pre = run / "preplay"
    made_from, made_to = (int(x) for x in (pre / "rrp-clock-window.txt").read_text().split())
    est = EST(home)
    entries = entries_of(pre, home, "ahead") + entries_of(pre, home, "behind")
    if not entries:
        sys.exit(f"no Evidence in {pre}/ahead or {pre}/behind")
    # the RRPs' own record of what they did with the Evidence: their log lines from now on (BENCH_HOME/<rrp>.log),
    # the platform rule's waivers among them
    logs = {r: Path(home, f"{r}.log") for r in {e["rrp"] for e in entries}}
    marks = {r: len(f.read_bytes().splitlines()) if f.exists() else 0 for r, f in logs.items()}

    def offer(e, name):
        at = time.time()
        st, answer = est.call("POST", f"/attest-{e['mode']}", e["body"], e["media"])
        e[name] = {"at": round(at, 3), "status": st, "answer": answer[:300]}
        print(f"{e['set']:6} {e['case']:26} {name:12} {st} {max(0, at - made_to):5.0f} s after it was made", flush=True)

    def wait_until(t):
        if (d := t - time.time()) > 0:
            print(f"waiting {d:.0f} s", flush=True)
            time.sleep(d)

    for e in entries:  # every one at once: a present-nonce Handle lives expires_in seconds from its minting
        offer(e, "at_once")
    windows = [e for e in entries if e["set"] == "ahead" and e["kind"] == "absent-timestamp"]
    for edge, at in (("opened", lambda e: e["timestamp"] - e["clock_skew_s"] + MARGIN),
                     ("before_close", lambda e: e["timestamp"] + e["max_age_s"] - MARGIN),
                     ("after_close", lambda e: e["timestamp"] + e["max_age_s"] + MARGIN)):  # fmt: skip
        for e in sorted(windows, key=at):
            wait_until(at(e))
            offer(e, edge)
    for e in entries:
        if e["set"] == "behind":
            offer(e, "again")
    for e in entries:
        f = logs[e["rrp"]]
        lines = f.read_text(errors="replace").splitlines()[marks[e["rrp"]] :] if f.exists() else []
        e["rrp_log"] = [x for x in lines if f"target={e['target']}" in x]
    clock = {s: (pre / s / "clock-offset-set.txt").read_text() for s in ("ahead", "behind") if (pre / s).exists()}
    out = {"made": {"not_before": made_from, "not_after": made_to}, "guest_clock": clock,
           "results": [{k: v for k, v in e.items() if k not in ("body", "media")} for e in entries]}  # fmt: skip
    (run / "preplay.json").write_text(json.dumps(out, indent=1) + "\n")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("step", choices=("prepare", "present"))
    ap.add_argument("run", type=Path, help="the attack run's directory")
    ap.add_argument("--home", default=os.environ.get("BENCH_HOME", str(Path.home() / ".attestation-bench")))
    a = ap.parse_args(argv)
    return prepare(a.run, a.home) if a.step == "prepare" else present(a.run, a.home)


if __name__ == "__main__":
    sys.exit(main())
