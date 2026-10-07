#!/usr/bin/env python3
"""The pre-play check of an attack run: absent-timestamp Evidence that a guest made with its wall clock set ahead,
presented to the running bench's RRPs through the EST server, at once and again when their clock reaches it.

The guest (hwcheck/scripts/preplay-guest.sh) set its clock AHEAD seconds ahead, made Evidence for an Enrollment at
db-time (the Credential Authority) and a Retrieval at ledger-time (the Secret Vault), and put its clock back. An RRP
accepts an absent-timestamp element ts when now - max_age <= ts <= now + clock_skew (rrp/internal/fresh), with
max_age and clock_skew from the Target's policy. So at once it refuses the Evidence as too new (409, freshness), and
from ts - clock_skew on it accepts Evidence made AHEAD seconds earlier, older than max_age. That is not a pass: it is
the exposure of a freshness that rests on the guest's clock, which the guest's root and the host that serves the
guest its time can set (docs/limits.md, "Time"). scripts/verdict.py expects both answers and reports the exposure.

    hwcheck/scripts/preplay.py RUN_DIR [--home BENCH_HOME]

Reads RUN_DIR/preplay (what the guest made, and rrp-clock-window.txt, this machine's clock around it) and the live
policies (BENCH_HOME/config); writes RUN_DIR/preplay.json.
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
# the guest's directory, its case, the Target, the gateway whose policy applies, the credential type, the request's
# subject field and the resource's media type
PRESENTED = [
    ("ca", "enroll-absent-timestamp", "https://db-time.tacra.example", "ca-gateway", "x509", "csr",
     "application/est-attest-enroll+json"),
    ("vault", "retrieve-absent-timestamp", "https://ledger-time.tacra.example", "vault-gateway", "api-key", "cek_pub",
     "application/est-attest-retrieve+json"),
]  # fmt: skip


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


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


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("run", type=Path, help="the attack run's directory")
    ap.add_argument("--home", default=os.environ.get("BENCH_HOME", str(Path.home() / ".attestation-bench")))
    a = ap.parse_args(argv)
    pre = a.run / "preplay"
    made_from, made_to = (int(x) for x in (pre / "rrp-clock-window.txt").read_text().split())
    est = EST(a.home)
    # first every presentation at once, then, when the RRPs' clock has reached every timestamp, every one again: one
    # Target's wait must not make another's first presentation a late one
    entries = []
    for guest_dir, case, target, gateway, ctype_, field, media in PRESENTED:
        d = pre / guest_dir / case
        meta = json.loads((d / "meta.json").read_text())
        element = unb64u(meta["freshness_element_b64"])
        policy = json.loads(Path(a.home, "config", f"{gateway}.json").read_text())["targets"][target]
        # the Credential Hint, as the bench's workload sends it: the Target's one identity (a Credential Authority) or
        # credential group (a Secret Vault)
        names = list(policy.get("identities") or policy.get("groups") or {})
        if len(names) != 1:
            sys.exit(f"{target}: {len(names)} identities or credential groups in the policy; the check needs one")
        body = json.dumps({"target": target, "credential_type": ctype_, "freshness_kind": "absent-timestamp",
                           "handle": b64u(element), field: b64u((d / "subject.der").read_bytes()),
                           "evidence": b64u((d / "evidence.tsm.cbor").read_bytes()),
                           "binding": {"method": "binding-input", "hash": "sha512"},
                           "profile": PROFILE, "credential_hint": names[0]}).encode()  # fmt: skip
        st, answer = est.call("GET", "/attest-initiate?" + urlencode({"target": target, "credential_type": ctype_}))
        entries.append({"target": target, "rrp": gateway, "mode": meta["mode"], "case": case,
                        "timestamp": int.from_bytes(element, "big"), "max_age_s": policy["max_age"],
                        "clock_skew_s": policy["clock_skew"], "initiate": {"status": st, "answer": answer[:300]},
                        "body": body, "media": media})  # fmt: skip

    # the RRPs' own record of what they did with the Evidence: their log lines from now on (BENCH_HOME/<rrp>.log), the
    # platform rule's waivers among them
    logs = {e["rrp"]: Path(a.home, f"{e['rrp']}.log") for e in entries}
    marks = {r: len(f.read_bytes().splitlines()) if f.exists() else 0 for r, f in logs.items()}

    def present(e):
        at = time.time()
        st, answer = est.call("POST", f"/attest-{e['mode']}", e["body"], e["media"])
        return {"at": round(at, 3), "status": st, "answer": answer[:300]}

    for e in entries:
        e["at_once"] = present(e)
        print(f"{e['target']}: timestamp {e['timestamp']}; at once {e['at_once']['status']}", flush=True)
    # two seconds into every window, by this machine's clock: the RRPs'
    wait = max(e["timestamp"] - e["clock_skew_s"] + 2 for e in entries) - time.time()
    if wait > 0:
        print(f"waiting {wait:.0f} s for the RRPs' clock to reach the timestamps", flush=True)
        time.sleep(wait)
    for e in entries:
        e["later"] = present(e)
        print(f"{e['target']}: at {e['later']['at']:.0f} {e['later']['status']}: "
              f"{max(0, e['later']['at'] - made_to):.0f} s or more after the Evidence was made "
              f"(max_age {e['max_age_s']} s)")  # fmt: skip
    for e in entries:
        f = logs[e["rrp"]]
        lines = f.read_text(errors="replace").splitlines()[marks[e["rrp"]] :] if f.exists() else []
        e["rrp_log"] = [x for x in lines if f"target={e['target']}" in x]
    results = [{k: v for k, v in e.items() if k not in ("body", "media")} for e in entries]
    ahead = (pre / "clock-ahead.txt").read_text()
    out = {"made": {"not_before": made_from, "not_after": made_to}, "guest_clock": ahead, "results": results}
    (a.run / "preplay.json").write_text(json.dumps(out, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
