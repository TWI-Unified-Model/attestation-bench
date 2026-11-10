#!/usr/bin/env python3
"""Says whether a run came out as its experiment expects.

    python3 scripts/verdict.py demo RUN_DIR [--expect admitted|refused] [--reason TEXT] [--out FILE]
    python3 scripts/verdict.py attacks RUN_DIR [--out FILE]
    python3 scripts/verdict.py redirect RUN_DIR [--out FILE]
    python3 scripts/verdict.py bank-pay RUN_DIR --expect pay|ordinary|unapproved|platform [--out FILE]
    python3 scripts/verdict.py mtls RUN_DIR [--out FILE]
    python3 scripts/verdict.py conduit RUN_DIR --attack seal|swap|hint|hint-group [--out FILE]

Every run script calls it before it seals its run directory, with --out RUN_DIR/verdict.txt. It prints what the run
did and a last line, "VERDICT PASS: ..." or "VERDICT FAIL: ...", writes the same to FILE if given, and exits 1 on
FAIL. It reads nothing but the run directory, so it judges any earlier run as well, those under e2e/evidence and
hwcheck/evidence included.

  demo      results.json. admitted (the default): every Target's credential acquired and admitted by the RATS-unaware
            Relying Party. refused: no credential issued for any Target, and each refusal's error contains the
            --reason TEXT. A SEV-SNP run whose platform rule (platform-rule.json) admits hosts under a named waiver
            says so in its verdict.
  attacks   rrpverify-*.json. Every check as expected: the honest Evidence passed, each attack refused for its own
            reason. The builds of Veraison the bench compares with (rrpverify-veraison-fork and -fixed) are reported,
            not judged: what they get wrong is the reason the bench runs its own build. And, in a run that made it,
            the pre-play check (preplay.json, hwcheck/scripts/preplay.py): absent-timestamp Evidence made with the
            guest's clock ahead, refused by each RRP at once for freshness (FRESHNESS_REFUSALS) and accepted later,
            older than the Target's max_age. That is reported as an exposure, not as a pass; any other outcome fails
            the run. The
            RRPs' platform rule on the honest Attestation Results is one of the files (rrpverify-platform.json); a
            SEV-SNP run that keeps the rule (platform-rule.json) names its waivers in the verdict, as a demo does.
  redirect  results.jsonl. ca1 issues for every Freshness Kind in both passes. With the RRP identifier in the binding,
            ca2 refuses every kind; without it, ca2 refuses present-nonce alone. A run of a variant (variant.txt:
            own-epochs, start-ca2, vault, replay, replay-vault; hwcheck/scripts/redirect.sh) is judged by that variant's table, each refusal
            for its own reason: the Handle, the epoch marker or the binding (redirect_variant_expected).
  bank-pay  report.json, from the Demo Bank's payment service. pay: the payment went through. ordinary: no
            attestation, no credential, and the ledger and the fraud service refused the workload. unapproved:
            genuine hardware Evidence, and no credential. platform: genuine hardware Evidence, no credential, each
            refused by the bank's platform rule (an SEV-SNP host without a mitigation bit the bank requires).
  mtls      mtls.json (checks.json in the runs of 1 October 2026), from make check-mtls. Every check as expected: on
            each channel only the allowed components, over TLS 1.3, got through.
  conduit   results.json and the conduit's log (caapi-est.log, or caapi-est-outside.log), from a demo run whose CAS
            Client was the attacker of a drill (CONDUIT_ATTACK, docs/attacks.md, section 6). Every Target the conduit
            did not act on admitted; each Retrieval it acted on refused by the CAI, or by the Vault, for the drill's
            reason, and no secret taken from it. seal: the conduit's own container, refused for its origin. swap: the
            first Retrieval, given its own container, admitted; each later one, given the container of the one
            before, refused for its associated data. hint: asked with the hint of a workload the Target serves no
            group to, refused by the Vault. hint-group: asked with the hint of another group the Target serves to the
            same launches; the Vault releases that group's secret, refused by the CAI for its associated data.
            verifier: the EST server was the attacker (CONDUIT_ATTACK=verifier make config): it signed the Attestation
            Results of each Enrollment again with a key of its own, and the conduit's log is bench-logs/est-conduit.log;
            each Enrollment refused by the Credential Authority, none of the verifiers it takes having signed them.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

FRESHNESS_KINDS = ("present-nonce", "present-epoch", "absent-epoch", "absent-timestamp", "absent-none")
REDIRECT_PASSES = ("with-rrp-id", "no-rrp-id")
# Why a gateway refused, from its message: the code it begins with and a part of the detail (rrp/internal/fresh, the
# verifier's verdict on the binding in Background Check, the RRP's own check of eat_nonce in Passport)
REDIRECT_REFUSALS = {
    "Handle": ("freshness ", ("unknown or already used Handle",)),  # a Handle the RRP never minted, or used
    "epoch": ("freshness ", ("the epoch marker is not the current one",)),  # another RRP's epoch marker
    "binding": ("attestation ", ('"contraindicated"', "eat_nonce is not the binding value")),  # another RRP's binding
}


def passes_made(got):
    """The passes a redirection run made, in REDIRECT_PASSES order: both until 11 October 2026 (with the RRP identifier
    bound, and without it); from 12 October the one without (the identifier was ripped out of the code, rats-tacra#20)."""
    return [p for p in REDIRECT_PASSES if any(key[0] == p for key in got)]


REDIRECT_VARIANT_RRPS = {"own-epochs": ("ca1", "ca2"), "start-ca2": ("ca1", "ca2"), "vault": ("vault1", "vault2")}
# the replay variants: the same request offered twice at the first RRP, and what a second offer gets there
REPLAY_RRP = {"replay": ("ca1", "issued"), "replay-vault": ("vault1", "released")}


def redirect_variant_expected(variant):
    """What each RRP does in a variant of the redirection experiment (hwcheck/scripts/redirect.sh, REDIRECT_VARIANT):
    {(pass, kind, rrp): True for an issuance (in vault, a release), or the reason of the refusal (REDIRECT_REFUSALS)}.
    own-epochs and start-ca2: ca2 keeps an epoch marker of its own. own-epochs: the Evidence is made for ca1, with
    ca1's Handles. start-ca2: the conduit starts at ca2, whose present-* Handles the Evidence carries; the Attester
    holds the deployment's epoch marker (absent-epoch), ca1's, and binds ca1 in the pass with the RRP identifier.
    vault: the default run on the Secret Vaults, which share the epoch marker; Evidence made for vault1."""
    first, second = REDIRECT_VARIANT_RRPS[variant]
    want = {}
    for p in REDIRECT_PASSES:
        bound = p == "with-rrp-id"
        for k in FRESHNESS_KINDS:
            if variant == "own-epochs":
                one = True
                two = {"present-nonce": "Handle", "present-epoch": "epoch", "absent-epoch": "epoch"}.get(k)
                two = two or ("binding" if bound else True)
            elif variant == "start-ca2":
                one = {"present-nonce": "Handle", "present-epoch": "epoch"}.get(k, True)
                two = "epoch" if k == "absent-epoch" else ("binding" if bound else True)
            else:  # vault
                one = True
                two = "Handle" if k == "present-nonce" else ("binding" if bound else True)
            want[(p, k, first)], want[(p, k, second)] = one, two
    return want


# the conduit's rewrites at ca1 (#19), on Evidence made for ca1, and what each gets by the gateways' code
# (rrp/internal/gateway, rrp/cmd/ca-gateway): a refusal and its code, or an issuance
REWRITES = {
    "made-up Handle": ("refused", "freshness"),  # present-nonce only: the RRP knows its Handles
    "Freshness Kind absent-none": ("refused", "freshness-kind-mismatch"),  # the kind is the Target's, by policy
    "credential type not offered": (
        "refused",
        "unsupported-credential-type",
    ),  # 422, after the appraisal; not sent under present-nonce: the Handle binding refuses first and spends the Handle
    "Credential Hint of another workload": ("refused", "credential-hint"),  # the CA names the attested workload
    "the other credential type offered": ("issued", None),  # nothing binds it, but a present-nonce Handle: below
}
COMPARED_BUILDS = ("rrpverify-veraison-fork", "rrpverify-veraison-fixed")


def clock_lines(run):
    """The guest's clock against the RRP's, when the run measured it (clock-offset.txt)."""
    offset = run / "clock-offset.txt"
    return [x for x in offset.read_text().splitlines() if x.startswith("guest minus RRP")] if offset.exists() else []


def waivers_in_force(run):
    """The named waivers of the platform rule a SEV-SNP run ran under (platform-rule.json, as the RRPs applied it):
    the mitigation bits the bench's own pack admits hosts without."""
    rule = run / "platform-rule.json"
    if "sev-snp" not in run.name or not rule.exists():
        return []
    named = ((json.loads(rule.read_text()) or {}).get("sevsnp") or {}).get("mitigation_waivers") or {}
    return [
        f"{product} bit {bit}: {name}" for product, bits in sorted(named.items()) for bit, name in sorted(bits.items())
    ]


def demo(run, expect, reason):
    results = json.loads((run / "results.json").read_text())
    admitted = [r for r in results if r["ok"]]
    lines = [f"{len(admitted)} of {len(results)} Targets: credential acquired and admitted by the relying party"]
    for r in results:
        cells = ["ok " if r["ok"] else "no ", r["target"].ljust(38), r["type"].ljust(8), f"{r['acquire_ms']:8.1f} ms"]
        lines.append(" ".join([*cells, str(r["rup_status"]), r.get("error", "")[:120]]).rstrip())
    if not results:
        return lines, False, "the workload asked for no Target"
    waivers = waivers_in_force(run)
    lines += [f"the platform rule's waiver: {w}" for w in waivers] + clock_lines(run)
    under = f"; admitted under the bench's waiver: {'; '.join(waivers)}" if waivers else ""
    if expect == "admitted":
        if len(admitted) < len(results):
            return lines, False, f"{len(results) - len(admitted)} of {len(results)} Targets not admitted"
        return lines, True, f"all {len(results)} Targets: credential acquired and admitted by the relying party{under}"
    issued = [r["target"] for r in results if r.get("cert_serial") or r.get("secret_sha256")]
    if issued:
        return lines, False, f"a credential was issued for {', '.join(issued)}"
    other = [r["target"] for r in results if reason not in r.get("error", "")]
    if other:
        return lines, False, f"refused, but not with {reason!r}: {', '.join(other)}"
    because = f", each with {reason!r}" if reason else ""
    return lines, True, f"{len(results)} of {len(results)} Targets refused, no credential issued{because}"


def preplay(run):
    """The pre-play check, if the run made one: returns its lines, the Targets not as expected, and the exposures."""
    p = run / "preplay.json"
    if not p.exists():
        # Evidence made with the clock ahead and never presented is a check not done
        return (
            [],
            (
                ["the Evidence made with the guest's clock ahead was not presented"]
                if (run / "preplay").is_dir()
                else []
            ),
            [],
        )
    d = json.loads(p.read_text())
    if any("set" in r for r in d["results"]):
        return preplay_moved(d)
    lines, bad, exposures = [], [], []
    for r in d["results"]:
        once, later = r["at_once"], r["later"]
        age = later["at"] - d["made"]["not_after"]
        lines.append(
            f"pre-play {r['target']}: at once {once['answer'][:110]}; {age:.0f} s or more after the Evidence was made: "
            f"{later['status']}"
        )
        if refused_for_freshness(once) and later["status"] == 200 and age > r["max_age_s"]:
            exposures.append(f"{r['target']} accepted Evidence {age:.0f} s old or more (max_age {r['max_age_s']} s)")
        else:
            bad.append(r["target"])
    return lines, bad, exposures


# An RRP refuses a freshness element that is not valid now with 400 Bad Request: a timestamp outside the window, a
# Handle not issued, expired or used before, an epoch marker that moved. Runs kept in this repository that answered
# 409 Conflict are judged as well.
FRESHNESS_REFUSALS = (400, 409)


def refused_for_freshness(answer):
    return answer.get("status") in FRESHNESS_REFUSALS and "freshness" in answer.get("answer", "")


def preplay_moved(d):
    """The pre-play of runs from 8 October 2026 on (hwcheck/scripts/preplay.py): Evidence of every Freshness Kind made
    with the guest's clock ahead, each offered at once, absent-timestamp's also at its window's edges; and
    absent-timestamp Evidence made with the clock behind. Ages are from the end of the guest's step, so each is the
    least the Evidence's age can have been."""
    made = d["made"]["not_after"]
    lines, bad, exposures, taken = [], [], [], []
    for r in d["results"]:
        name, once = f"{r['set']} {r['case']}", r["at_once"]
        if r["set"] == "behind":
            again = r.get("again", {})
            lines.append(f"pre-play {name}: at once {once['status']}; {again.get('at', made) - made:.0f} s or more "
                         f"after it was made {again.get('status')}")  # fmt: skip
            if not (refused_for_freshness(once) and refused_for_freshness(again)):
                bad.append(f"{name}: made with the clock behind, not refused for freshness each time")
        elif r["kind"] != "absent-timestamp":
            lines.append(f"pre-play {name}: at once {once['status']}")
            if once["status"] == 200:
                taken.append(r["case"])
            else:  # a kind that does not rest on the guest's clock must not care where the clock was
                bad.append(f"{name}: not taken at once ({' '.join(once['answer'].split())[:80]})")
        else:
            o, b, c = r.get("opened", {}), r.get("before_close", {}), r.get("after_close", {})
            ages = [x.get("at", made) - made for x in (o, b, c)]
            lines.append(f"pre-play {name}: at once {once['status']}; {ages[0]:.0f} s or more after it was made "
                         f"{o.get('status')}, {ages[1]:.0f} s {b.get('status')}, {ages[2]:.0f} s {c.get('status')} "
                         f"(max_age {r['max_age_s']} s, clock_skew {r['clock_skew_s']} s)")  # fmt: skip
            if (refused_for_freshness(once) and o.get("status") == 200 and b.get("status") == 200
                    and refused_for_freshness(c) and ages[0] > r["max_age_s"]):  # fmt: skip
                exposures.append(f"{r['target']} accepted Evidence {ages[0]:.0f} s old or more, and again "
                                 f"{ages[1]:.0f} s old or more (max_age {r['max_age_s']} s)")  # fmt: skip
            else:
                bad.append(f"{name}: not refused at once, taken in its window and refused after it")
    if exposures and not bad:
        exposures.append("absent-timestamp Evidence made with the clock behind refused; the other four kinds' Evidence "
                         "made with it ahead taken at once")  # fmt: skip
    return lines, bad, exposures


def attacks(run):
    lines, judged, failed = [], 0, 0
    files = sorted(run.glob("rrpverify-*.json"))
    for f in files:
        results = json.loads(f.read_text())["results"]
        bad = [r for r in results if not r["ok"]]
        compared = f.stem in COMPARED_BUILDS
        note = " (a build the bench compares with: reported, not judged)" if compared else ""
        lines.append(f"{f.stem}: {len(results)} checks, {len(bad)} not as expected{note}")
        if compared:
            continue
        judged += len(results)
        failed += len(bad)
        for r in bad:
            lines.append(f"  {r['case']}: {r['check']}: want {r['want']}, got {r['got']} {r.get('error', '')}".rstrip())
    pre_lines, pre_bad, exposures = preplay(run)
    lines += pre_lines
    waivers = waivers_in_force(run)
    lines += [f"the platform rule's waiver: {w}" for w in waivers] + clock_lines(run)
    if not judged:
        return lines, False, "no results of the bench's own checks (rrpverify-*.json)"
    if failed:
        return lines, False, f"{failed} of {judged} checks not as expected"
    if pre_bad:
        return lines, False, f"the pre-play check not as expected: {', '.join(pre_bad)}"
    summary = f"{judged} checks: the honest Evidence passed, every attack refused for its own reason"
    if waivers:
        summary += f"; the honest Evidence admitted under the bench's waiver: {'; '.join(waivers)}"
    if exposures:
        summary += "; exposure, the guest's clock: " + "; ".join(exposures)
    return lines, True, summary


def rewrite_expected(name, kind):
    """What a rewrite at ca1 must get: a present-nonce Handle is minted for one Target and credential type, so the other
    credential type is refused there for freshness; elsewhere no check covers it, and the CA issues its X.509."""
    if name == "the other credential type offered" and kind == "present-nonce":
        return "refused", "freshness"
    return REWRITES[name]


def sent_rewrites(rows):
    """The (rewrite, kind) pairs a run made."""
    return {(r["rewrite"], r["kind"]) for r in rows}


def rewrites_wanted(sent=frozenset()):
    """The rewrites the experiment makes: (name, kind), in the order it makes them. Under present-nonce the credential
    type the Target does not offer is sent only by the runs made while the gateways checked the Credential Type before
    the Handle; sent says what the run made, and those runs keep that row."""
    out = []
    for k in FRESHNESS_KINDS:
        if k == "present-nonce":
            out.append(("made-up Handle", k))
        if k != "absent-none":
            out.append(("Freshness Kind absent-none", k))
        if k != "present-nonce" or ("credential type not offered", k) in sent:
            out.append(("credential type not offered", k))
        out.append(("Credential Hint of another workload", k))
    return out + [("the other credential type offered", k) for k in FRESHNESS_KINDS]


def rewrite_lines(rows):
    """The conduit's rewrites (runs from 7 October 2026 on): a table, and each one not as expected."""
    got = {(r["rewrite"], r["kind"]): r["result"] for r in rows}
    lines, wrong = [f"{'rewrite at ca1':38} {'kind':18} outcome"], []
    for name, kind in rewrites_wanted(sent_rewrites(rows)):
        res, (want, code) = got.get((name, kind)), rewrite_expected(name, kind)
        if res is None:
            lines.append(f"{name:38} {kind:18} missing")
            wrong.append(f"rewrite {name}, {kind}: missing")
            continue
        reason = res.get("reason", "")
        issued = "issued" if res["issued"] else "refused"
        lines.append(
            f"{name:38} {kind:18} {'ISSUED ' + res.get('cert_subject', '') if res['issued'] else 'refused ' + reason[:70]}"
        )
        if issued != want or (code and not reason.startswith(code + " ")):
            wrong.append(f"rewrite {name}, {kind}: {issued} ({reason[:70]}), expected {want} {code or ''}".rstrip())
    return lines, wrong


def redirect(run):
    variant_file = run / "variant.txt"
    variant = variant_file.read_text().strip() if variant_file.exists() else "default"
    if variant in REPLAY_RRP:
        return redirect_replay(run, variant)
    if variant != "default":
        return redirect_variant(run, variant)
    rows = [json.loads(x) for x in (run / "results.jsonl").read_text().splitlines() if x.strip()]
    rewrites = [r for r in rows if "rewrite" in r]
    rows = [r for r in rows if "rewrite" not in r]
    got = {(r["pass"], r["kind"], r["rrp"]): r["result"]["issued"] for r in rows}
    passes = passes_made(got)
    lines, wrong = [f"{'pass':12} {'kind':18} {'ca1':8} ca2"], []
    for p in passes:
        for k in FRESHNESS_KINDS:
            want = {"ca1": True, "ca2": p == "no-rrp-id" and k != "present-nonce"}
            cells = []
            for rrp in ("ca1", "ca2"):
                issued = got.get((p, k, rrp))
                cells.append({True: "ISSUED", False: "refused", None: "missing"}[issued])
                if issued is not want[rrp]:
                    wrong.append(f"{p} {k} {rrp}: {cells[-1]}, expected {'ISSUED' if want[rrp] else 'refused'}")
            lines.append(f"{p:12} {k:18} {cells[0]:8} {cells[1]}")
    outcomes = len(passes) * len(FRESHNESS_KINDS) * 2
    if rewrites:
        more, bad = rewrite_lines(rewrites)
        lines += more
        wrong += bad
        outcomes += len(rewrites_wanted(sent_rewrites(rewrites)))
    lines += clock_lines(run)
    if wrong:
        return lines + wrong, False, f"{len(wrong)} of {outcomes} outcomes not as expected"
    summary = "without the RRP identifier, ca2 issued for every Freshness Kind but present-nonce"
    if "with-rrp-id" in passes:
        summary = "with the RRP identifier, ca2 refused all 5 Freshness Kinds; " + summary
    if rewrites:
        summary += (
            f"; of the conduit's {len(rewrites_wanted(sent_rewrites(rewrites)))} rewrites at ca1, the other credential type the Target "
            "offers was issued for every kind but present-nonce, and every other was refused for its own reason"
        )
    return lines, True, summary


def redirect_variant(run, variant):
    """A variant of the redirection experiment: every outcome as redirect_variant_expected says, each refusal for its
    own reason (REDIRECT_REFUSALS)."""
    if variant not in REDIRECT_VARIANT_RRPS:
        return [], False, f"unknown variant {variant!r} (variant.txt)"
    rows = [json.loads(x) for x in (run / "results.jsonl").read_text().splitlines() if x.strip()]
    got = {(r["pass"], r["kind"], r["rrp"]): r["result"] for r in rows if "rewrite" not in r}
    want = redirect_variant_expected(variant)
    first, second = REDIRECT_VARIANT_RRPS[variant]
    passes = passes_made(got)
    want = {k: v for k, v in want.items() if k[0] in passes}
    lines, wrong = [f"variant {variant}", f"{'pass':12} {'kind':18} {first:20} {second}"], []
    extra = [f"a #19 rewrite, which a variant's run does not make: {r['rewrite']}" for r in rows if "rewrite" in r]
    for p in passes:
        for k in FRESHNESS_KINDS:
            cells = []
            for rrp in (first, second):
                res, w = got.get((p, k, rrp)), want[(p, k, rrp)]
                if res is None:
                    cells.append("missing")
                    wrong.append(f"{p} {k} {rrp}: missing")
                    continue
                reason = res.get("reason", "")
                why = next(
                    (n for n, (code, parts) in REDIRECT_REFUSALS.items()
                     if reason.startswith(code) and any(x in reason for x in parts)),
                    None,
                )  # fmt: skip
                cells.append("ISSUED" if res["issued"] else f"refused ({why or reason[:40]})")
                if w is True and not res["issued"]:
                    wrong.append(f"{p} {k} {rrp}: refused ({reason[:90]}), expected ISSUED")
                elif w is not True and (res["issued"] or why != w):
                    was = "ISSUED" if res["issued"] else f"refused ({reason[:90]})"
                    wrong.append(f"{p} {k} {rrp}: {was}, expected refused for the {w}")
            lines.append(f"{p:12} {k:18} {cells[0]:20} {cells[1]}")
    lines += clock_lines(run)
    if wrong or extra:
        failed = [f"{len(wrong)} of {len(want)} outcomes not as expected"] if wrong else []
        failed += [f"{len(extra)} #19 rewrites in a variant's run"] if extra else []
        return lines + wrong + extra, False, "; ".join(failed)
    if variant == "own-epochs":
        summary = (
            "ca2 with an epoch marker of its own: with the RRP identifier, ca2 refused all 5 Freshness Kinds; without "
            "it, it issued for absent-timestamp and absent-none alone, refusing present-nonce for the Handle and "
            "present-epoch and absent-epoch for the epoch marker"
        )
    elif variant == "start-ca2":
        summary = (
            "the conduit starting at ca2: with the RRP identifier, ca2 refused all 5 Freshness Kinds, the two whose "
            "Handles it minted itself for the binding; without it, ca2 issued for every kind but absent-epoch, whose "
            "marker the Attester holds, present-nonce included"
        )
    else:
        summary = (
            "the Secret Vaults: with the RRP identifier, vault2 refused all 5 Freshness Kinds; without it, it released "
            "the workload's group's key for every kind but present-nonce"
        )
    return lines, True, summary


def redirect_replay(run, variant):
    """A replay variant of the redirection experiment (hwcheck/scripts/redirect.sh, REDIRECT_VARIANT=replay or
    replay-vault): the same request offered twice at the first RRP, in the pass with the RRP identifier. The first
    offer is served. The second is refused for the Handle with present-nonce, which the RRP deletes on its first use
    (rrp/internal/fresh), and served again with every other Freshness Kind: an epoch marker serves while it is current,
    a timestamp while its window holds, absent-none always, and the RRP keeps no record of a CSR or CEKpub it served."""
    rrp, verb = REPLAY_RRP[variant]
    rows = [json.loads(x) for x in (run / "results.jsonl").read_text().splitlines() if x.strip()]
    got = {
        (r["pass"], r["kind"], r.get("offer")): r["result"]
        for r in rows
        if "rewrite" not in r and r.get("pass") in REDIRECT_PASSES and r.get("rrp") == rrp
    }
    extra = [
        f"an outcome a replay run does not make: {r.get('pass')} {r.get('kind')} {r.get('rrp')} {r.get('rewrite', '')}"
        for r in rows
        if "rewrite" in r or r.get("pass") not in REDIRECT_PASSES or r.get("rrp") != rrp
    ]
    # the runs of 8 October before 4a5c270 made the pass with the identifier alone; later ones both
    passes = passes_made(got)
    served = verb.upper()
    lines, wrong = [f"variant {variant}", f"{'pass':12} {'kind':18} {'first offer':28} second offer at {rrp}"], []
    for p, k in ((p, k) for p in passes for k in FRESHNESS_KINDS):
        cells = []
        for n in (1, 2):
            res = got.get((p, k, n))
            if res is None:
                cells.append("missing")
                wrong.append(f"{p} {k} offer {n}: missing")
                continue
            reason = res.get("reason", "")
            why = next(
                (name for name, (code, parts) in REDIRECT_REFUSALS.items()
                 if reason.startswith(code) and any(x in reason for x in parts)),
                None,
            )  # fmt: skip
            cells.append(served if res["issued"] else f"refused ({why or reason[:40]})")
            want = "Handle" if n == 2 and k == "present-nonce" else True
            if want is True and not res["issued"]:
                wrong.append(f"{p} {k} offer {n}: refused ({reason[:90]}), expected {served}")
            elif want is not True and (res["issued"] or why != want):
                was = served if res["issued"] else f"refused ({reason[:90]})"
                wrong.append(f"{p} {k} offer {n}: {was}, expected refused for the {want}")
        lines.append(f"{p:12} {k:18} {cells[0]:28} {cells[1]}")
    lines += clock_lines(run)
    if wrong or extra:
        failed = [f"{len(wrong)} of {len(passes) * len(FRESHNESS_KINDS) * 2} outcomes not as expected"] if wrong else []
        failed += [f"{len(extra)} outcomes a replay run does not make"] if extra else []
        return lines + wrong + extra, False, "; ".join(failed)
    summary = (
        f"the same request twice at {rrp}: the second offer with present-nonce refused for the Handle; with "
        f"present-epoch, absent-epoch, absent-timestamp and absent-none the credential {verb} twice"
    )
    if len(passes) == 2:
        summary += ", with the RRP identifier bound and without it alike"
    return lines, True, summary


def bank_pay(run, expect):
    report = json.loads((run / "report.json").read_text())
    steps = {s["step"]: s for s in report["steps"]}
    lines = []
    for s in report["steps"]:
        mark = "ok " if s["ok"] else "NO "
        lines.append(f"{mark}{s['step']:38}{s['ms']:9.1f} ms  {s.get('note') or ''} {s.get('error') or ''}".rstrip())
    paid = bool(steps.get("ledger: transfer", {}).get("ok") and report.get("receipt"))
    credentials = [n for n, s in steps.items() if n.startswith("TACRA:") and s["ok"]]
    if expect == "pay":
        if paid:
            return lines, True, "the payment went through, with credentials acquired by attestation"
        return lines, False, "no payment"
    wrong = ["the payment went through"] if paid else []
    wrong += [f"a credential was issued ({n})" for n in credentials]
    if expect == "ordinary":
        refusals = ("ledger: login without a certificate", "fraud service: call without the key")
        wrong += [f"not refused: {n}" for n in refusals if not steps.get(n, {}).get("ok")]
        summary = "no attestation, no credential; the ledger and the fraud service refused it"
    elif expect == "platform":
        if steps.get("attestation plug-in and CAI", {}).get("ok") is not True:
            wrong.append("no hardware Evidence (the attestation plug-in and CAI step failed)")
        tacra = {n: s for n, s in steps.items() if n.startswith("TACRA:")}
        why = [s.get("error") or "" for s in tacra.values()]
        if not tacra or not all("platform-policy" in e for e in why):
            wrong.append("not every credential refused by the platform rule: " + "; ".join(e[:120] for e in why))
        reason = why[0].split("accepts: ", 1)[-1].strip() if why else ""
        summary = f"genuine hardware evidence, refused by the bank's platform rule: {reason[:160]}"
    else:
        if steps.get("attestation plug-in and CAI", {}).get("ok") is not True:
            wrong.append("no hardware Evidence (the attestation plug-in and CAI step failed)")
        summary = "genuine hardware evidence, unapproved launch: no credential issued"
    if wrong:
        return lines, False, "; ".join(wrong)
    return lines, True, summary


def mtls(run):
    results = json.loads((run / "mtls.json" if (run / "mtls.json").exists() else run / "checks.json").read_text())
    bad = [r for r in results if not r["ok"]]
    lines = [
        f"not as expected: {r['channel']}, {r['caller']} over TLS {r['tls']}: want {r['expected']}, got {r['got']}"
        for r in bad
    ]
    if not results:
        return lines, False, "no check ran"
    if bad:
        return lines, False, f"{len(bad)} of {len(results)} checks not as expected"
    summary = f"{len(results)} of {len(results)} checks as expected: only the allowed components, over TLS 1.3"
    return lines, True, summary


# the conduit's drills on the Retrieval container (caapi-est -attack) and the error each Retrieval it acted on must
# end in: from the CAI's container checks (bundle), or the Vault's refusal (rrp/cmd/vault-gateway)
# the key the seal drill's conduit puts in its own container (e2e/cmd/caapi-est), as the workload records a secret
CONDUIT_KEY_SHA256 = hashlib.sha256(b"a key the conduit chose").hexdigest()

CONDUIT = {
    "seal": ("not signed by the trusted Vault key", "not sealed by the trusted Vault key"),
    "swap": ("associated data does not name what the Evidence bound",),
    "hint": ("credential-hint",),
    "hint-group": ("associated data does not name what the Evidence bound",),
    "verifier": ("not signed by the verifier's key",),
    "redirect": (
        "is not issued under a CA the CAI holds for",
        "not signed by the trusted Vault key",
        "not sealed by the trusted Vault key",
    ),
}


def conduit_redirect(run):
    """The redirect drill: the EST server routed every request to the second Credential Authority and the second Secret
    Vault (bench-logs/est-routing.json, written by the run from the trust zone's configuration). What the CAI does with
    what comes back is the measurement: with the copies sharing the first RRPs' PKI and keys (the default), the CAI
    cannot tell the credentials apart and admits them; with keys of their own (COPIES_OWN_KEYS=1), the second Vault's
    container is refused for its origin, and a certificate under another PKI would be refused for its issuer."""
    results = json.loads((run / "results.json").read_text())
    routing = json.loads((run / "bench-logs" / "est-routing.json").read_text())
    routed, own_keys = routing["targets"], routing.get("copies_own_keys", False)
    lines = [
        f"the conduit's drill: redirect; the EST server routed {len(routed)} Targets to the copies {sorted({v['rrp'] for v in routed.values()})}"
        + ("; the copies with keys of their own" if own_keys else "; the copies sharing the first RRPs' PKI and keys")
    ]
    bad = []
    for r in results:
        copy = routed.get(r["target"])
        err = r.get("error", "")
        lines.append(" ".join(["ok " if r["ok"] else "no ", r["target"].ljust(38), r["type"].ljust(8), (r.get("cert_issuer") or "")[:40].ljust(40), err[:90]]).rstrip())  # fmt: skip
        if copy is None:
            bad.append(f"{r['target']}: not routed to a copy")
            continue
        if r["type"] == "x509":  # a certificate: the CAI judges the issuer against the CA it holds for the RRP it asked
            if not r["ok"]:
                bad.append(
                    f"{r['target']}: refused ({err[:80]}); the copy signs under the first CA's PKI, so the CAI admits"
                )
        elif own_keys:  # a container sealed under the second Vault's own keys: refused for its origin
            if r["ok"] or not any(
                x in err for x in ("not signed by the trusted Vault key", "not sealed by the trusted Vault key")
            ):
                bad.append(
                    f"{r['target']}: {'admitted' if r['ok'] else 'refused for ' + err[:80]}, expected refused for the Vault key"
                )
        elif not r["ok"]:
            bad.append(
                f"{r['target']}: refused ({err[:80]}); the copy seals under the first Vault's keys, so the CAI admits"
            )
    if bad:
        return lines, False, "; ".join(bad)
    certs = sum(1 for r in results if r["type"] == "x509")
    conts = len(results) - certs
    say = (
        f"{certs} Enrollments served by the second Credential Authority, each admitted: it issues under the PKI the first "
        f"shares, and a certificate names its issuer, not the RRP; {conts} Retrievals served by the second Secret Vault, "
        + (
            "each refused by the CAI for its origin: the keys are the second Vault's own"
            if own_keys
            else "each admitted: the copy seals under the first Vault's keys"
        )
    )
    return lines, True, say


def conduit(run, attack, origin_auth="on"):
    """origin_auth off (ORIGIN_AUTH=off): the Vault released its containers without origin authentication and the workload
    holds no Vault key, the EST draft's accepted risk; the seal drill's container is then admitted, which is the
    measurement."""
    if attack == "redirect":
        return conduit_redirect(run)
    results = json.loads((run / "results.json").read_text())
    acts = {}  # Target -> what the conduit did to each Retrieval for it, in order
    first = None
    for log in (run / "caapi-est.log", run / "caapi-est-outside.log", run / "bench-logs" / "est-conduit.log"):
        if not log.exists():
            continue
        for line in log.read_text().splitlines():
            mark = f"conduit attack {attack}: "  # then "Retrieval for TARGET: …", or the EST server's "Enrollment for TARGET: …"
            if mark not in line or " for " not in line.split(mark, 1)[1]:
                continue
            target, _, what = line.split(mark, 1)[1].split(" for ", 1)[1].partition(": ")
            acts.setdefault(target, []).append(what)
            first = first or target
    lines = [
        f"the conduit's drill: {attack}; it acted on {sum(map(len, acts.values()))} requests, for {len(acts)} Targets"
    ]
    bad = []
    for r in results:
        did = acts.get(r["target"])
        lines.append(" ".join(["ok " if r["ok"] else "no ", r["target"].ljust(38), r["type"].ljust(8),
                               r.get("error", "")[:110]]).rstrip())  # fmt: skip
        if did is None:
            if not r["ok"]:
                bad.append(f"{r['target']}: not acted on, and not admitted")
            continue
        lines.append(f"    the conduit: {did[-1][:150]}")
        if attack == "swap" and r["target"] == first:
            if not r["ok"]:
                bad.append(f"{r['target']}: the first Retrieval, given its own container, not admitted")
            continue
        if attack == "seal" and origin_auth == "off":
            # the accepted risk, measured: the CAI opens the conduit's container and holds the key the conduit chose
            # (caapi-est, "a key the conduit chose"), presents it, and the honest relying party refuses it
            if r.get("secret_sha256") != CONDUIT_KEY_SHA256 or r.get("rup_status") != 403 or r["ok"]:
                bad.append(
                    f"{r['target']}: expected the conduit's key taken and refused by the relying party, got "
                    f"secret {str(r.get('secret_sha256'))[:12]}, rup {r.get('rup_status')}, {r.get('error', '')[:60]}"
                )
            continue
        if r["ok"] or r.get("secret_sha256"):
            bad.append(f"{r['target']}: a secret taken from what the conduit returned")
        elif not any(reason in r.get("error", "") for reason in CONDUIT[attack]):
            bad.append(f"{r['target']}: refused, but not for {' or '.join(map(repr, CONDUIT[attack]))}")
    if not acts:
        return lines, False, f"the conduit's log names no Retrieval it acted on in the drill {attack!r}"
    if missing := sorted(set(acts) - {r["target"] for r in results}):
        bad.append(f"acted on Targets the workload has no result for: {', '.join(missing)}")
    if bad:
        return lines, False, "; ".join(bad)
    others = len(results) - len(acts)
    refused = len(acts) - (attack == "swap")
    say = {
        "seal": f"{refused} Retrievals given the conduit's own container, each refused by the CAI for its origin"
        if origin_auth == "on"
        else f"{refused} Retrievals given the conduit's own container, without origin authentication: the CAI, holding "
        "no Vault key for the Target, opened each and took the key the conduit chose, and the relying party refused "
        "that key, 403: the EST draft's accepted risk, measured",
        "swap": f"the first Retrieval admitted with its own container; {refused} given the container of the one "
        "before, each refused by the CAI for its associated data",
        "hint": f"{refused} Retrievals asked with the Credential Hint of a workload the Target serves no group to, "
        "each refused by the Vault",
        "hint-group": f"{refused} Retrievals asked with the Credential Hint of another group the Target serves to the "
        "same launches: the Vault released that group's secret, and the CAI refused each for its associated data",
        "verifier": f"{refused} Enrollments given Attestation Results signed again with the conduit's own verifier key, "
        "each refused by the Credential Authority: none of the verifiers it takes signed them",
    }[attack]
    return lines, True, f"{say}; the {others} other Targets admitted"


JUDGES = {
    "demo": lambda a: demo(a.run, a.expect, a.reason),
    "attacks": lambda a: attacks(a.run),
    "redirect": lambda a: redirect(a.run),
    "bank-pay": lambda a: bank_pay(a.run, a.expect),
    "mtls": lambda a: mtls(a.run),
    "conduit": lambda a: conduit(a.run, a.attack, a.origin_auth),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Says whether a run came out as its experiment expects.")
    kinds = parser.add_subparsers(dest="kind", required=True)
    for kind in JUDGES:
        p = kinds.add_parser(kind)
        p.add_argument("run", type=Path, help="the run directory")
        p.add_argument("--out", type=Path, help="also write the verdict to this file")
        if kind == "demo":
            p.add_argument("--expect", choices=("admitted", "refused"), default="admitted")
            p.add_argument("--reason", default="", help="refused: the text every refusal's error must contain")
        if kind == "bank-pay":
            p.add_argument("--expect", choices=("pay", "ordinary", "unapproved", "platform"), required=True)
        if kind == "conduit":
            p.add_argument("--attack", choices=tuple(CONDUIT), required=True)
            p.add_argument(
                "--origin-auth",
                choices=("on", "off"),
                default="on",
                help="off: the run's Vault signed nothing and the workload held no Vault key (ORIGIN_AUTH=off)",
            )
    args = parser.parse_args(argv)
    try:
        lines, ok, summary = JUDGES[args.kind](args)
    except (OSError, ValueError, KeyError, TypeError) as e:
        lines, ok, summary = [], False, f"cannot read the run in {args.run}: {e!r}"
    text = "\n".join([*lines, f"VERDICT {'PASS' if ok else 'FAIL'}: {summary}"]) + "\n"
    sys.stdout.write(text)
    if args.out:
        args.out.write_text(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
