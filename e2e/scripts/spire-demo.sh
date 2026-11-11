#!/usr/bin/env bash
# The demo of the SPIRE proof of concept of TACRA, for the TAC: one end-to-end run on a confidential guest, narrated,
# recorded as a typescript, and written up from the run's record as a walkthrough the audience can read.
#
#   SPIRE_REPO=<checkout of the fork> e2e/scripts/spire-demo.sh [sev-snp|tdx|aws]   (default sev-snp: a Google
#                                                        Cloud SEV-SNP guest; SPIRE_REPO as the run scripts read it)
#   DEMO_RUN=<run directory> e2e/scripts/spire-demo.sh   narrates an existing record instead of running (for checking)
#
# Roles, in the words of draft-novak-rats-tacra-03: the attested workload is the Attester, with the Credential
# Acquisition Interface built in; SPIRE Agent is the CAS Client and SPIRE Server the CAS Server, conduits that hold no
# RATS role and no credential; SPIRE Server's CA is the Credential Authority, the Relying Party for enrollment, which
# recomputes the binding value and appraises the Attestation Results by its own policy; the bench's Secret Vault is the
# Relying Party for retrieval, in the Passport model from the Attestation Results the CAS Server forwards, in the
# Background Check model by asking the Verifier itself; the bench's Veraison is the Verifier.
#
# Output: DEMO_DIR (default BENCH_HOME/demo/<stamp>-spire-<platform>) with demo.typescript (the recording),
# demo.txt (the same without terminal control sequences), run.log, run-directory.txt and walkthrough.md.
# The AWS recording names instance identifiers; audit it before it goes outward.
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"
PLATFORM="${1:-sev-snp}"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
B="$BENCH_HOME"

if [ -n "${DEMO_RUN:-}" ]; then
  [ -d "$DEMO_RUN" ] || bench_die "no such run directory: $DEMO_RUN"
else
  bench_spire_repo
fi

if [ "${DEMO_RECORDED:-}" != 1 ]; then
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  DEMO_DIR="${DEMO_DIR:-$B/demo/${STAMP}-spire-${PLATFORM}}"
  export DEMO_DIR
  mkdir -p "$DEMO_DIR"
  # record this script's own session as a typescript: the narration runs under a pseudo-terminal whose output is
  # copied to the file byte for byte (script(1) needs a terminal on its stdin; this works from any shell). The
  # recorder is the here-document: python3 reads it from its standard input.
  set +e
  DEMO_RECORDED=1 python3 - "$DEMO_DIR/demo.typescript" "$0" "$PLATFORM" <<'PYREC'
import os, pty, sys
out = open(sys.argv[1], "wb")
def read(fd):
    data = os.read(fd, 4096)
    out.write(data)
    out.flush()
    return data
status = pty.spawn(sys.argv[2:], read)
out.close()
sys.exit(os.waitstatus_to_exitcode(status))
PYREC
  set -e
  perl -pe 's/\e\[[0-9;?]*[a-zA-Z]//g; s/\r//g' "$DEMO_DIR/demo.typescript" > "$DEMO_DIR/demo.txt"
  if [ -s "$DEMO_DIR/walkthrough.md" ]; then echo "== demo: $DEMO_DIR"; exit 0; fi
  echo "== demo did not complete: $DEMO_DIR" >&2; exit 1
fi
DEMO_DIR="${DEMO_DIR:?}"
# under the pseudo-terminal git would open its pager and wait for a key
export GIT_PAGER=cat PAGER=cat

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
show() { printf '\033[2m$ %s\033[0m\n' "$*"; "$@"; }

say "The SPIRE proof of concept of TACRA: an attested workload on $PLATFORM"
echo "In the words of the draft: the workload is the Attester, with the Credential Acquisition Interface built in."
echo "SPIRE Agent is the CAS Client and SPIRE Server the CAS Server: conduits, holding no RATS role and no credential."
echo "SPIRE Server's CA is the Credential Authority, the Relying Party for enrollment: it recomputes the binding value"
echo "and appraises the Attestation Results by its own policy; the conduit only forwards Evidence to the Verifier."
echo "The bench's Secret Vault is the Relying Party for retrieval; the bench's Veraison is the Verifier."

say "The bench on this machine"
show "$HERE/e2e/scripts/bench.sh" status
echo "vault: $(python3 -c "import json,sys; v=json.load(open(sys.argv[1])); print('rats_model=' + str(v.get('rats_model') or 'passport'))" "$B/config/vault-gateway.json")"

say "The code under demonstration"
if [ -n "${DEMO_RUN:-}" ]; then
  show cat "$DEMO_RUN/spire-source.txt"
else
  show git -C "$SPIRE_REPO" --no-pager log --oneline -3
  show grep -E '^replace' "$SPIRE_REPO/go.mod"
fi

if [ -n "${DEMO_RUN:-}" ]; then
  say "Narrated from an existing record, no new run: $DEMO_RUN"
  RUN="$DEMO_RUN"; [ -d "$RUN" ] || bench_die "no such run directory: $RUN"
else
  say "The run: a fresh confidential guest, SPIRE Agent, the attested workload"
  RUN_LOG="$DEMO_DIR/run.log"
  set +e
  case "$PLATFORM" in
    sev-snp | tdx) TEE="$PLATFORM" "$HERE/e2e/scripts/spire-gcp-snp-e2e.sh" 2>&1 | tee "$RUN_LOG"; rc=${PIPESTATUS[0]} ;;
    aws) "$HERE/e2e/scripts/spire-aws-snp-e2e.sh" 2>&1 | tee "$RUN_LOG"; rc=${PIPESTATUS[0]} ;;
    *) bench_die "platform: sev-snp, tdx or aws" ;;
  esac
  set -e
  RUN="$(grep -E '^== run directory: ' "$RUN_LOG" | tail -1 | sed 's/^== run directory: //' || true)"
  [ -n "$RUN" ] && [ -d "$RUN" ] || bench_die "no run directory in $RUN_LOG"
  [ "$rc" = 0 ] || bench_die "the run refused (exit $rc); its record is $RUN"
fi
echo "$RUN" > "$DEMO_DIR/run-directory.txt"

say "The server's configuration for the Targets (paths and policy; no secrets)"
show sed -n '/credential_acquisition {/,/^        }$/p' "$RUN/config/server.conf"

say "The X509-SVID the workload enrolled: its own key, the entry's SPIFFE ID, the trust domain's CA"
show openssl x509 -in "$RUN/workload/svid.pem" -noout -subject -issuer -dates -ext subjectAltName
echo "the workload's record of the enrollment:"
python3 - "$RUN/workload/result.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
for k in ("target", "credential_type", "mode", "freshness_kind", "handle_hex", "binding_value_hex", "evidence_media_type", "evidence_bytes", "report_provider", "report_version", "report_signer", "report_measurement_hex", "spiffe_id", "chain_verified", "key_matches", "initiate_ms", "enroll_ms"):
    print(f"  {k}: {r.get(k)}")
PY

say "What the Credential Authority recorded (SPIRE Server's audit log): the Verifier, the measurement, a waiver if any"
{ grep -E 'Enrolled an attested X509-SVID|API accessed.*method=EnrollCredential|admitted under a waiver' "$RUN/server.log" || true; } | sed -E 's/ caller_addr="[^"]*"//' | fold -w 160

VAULT_MODE="$(cat "$RUN/config/vault-mode.txt" 2>/dev/null || true)"
case "$VAULT_MODE" in
  *background-check*) say "The Verifier's sessions: the CAS Server's, with the binding value as the nonce; in Background Check, the Secret Vault's own for the retrieval" ;;
  *) say "The Verifier's sessions, both opened by the CAS Server: in the Passport model it forwards the Attestation Results to the Secret Vault" ;;
esac
{ grep -E 'session requested|challenge-response/v1/newSession|challenge-response/v1/session' "$RUN/bench-logs/veraison-verification.log" || true; } | head -6 | cut -c1-200

say "What the CAS Server recorded for the retrieval (SPIRE Server's audit log)"
{ grep -E 'API accessed.*method=RetrieveCredential|Retrieved an attested credential bundle' "$RUN/server.log" || true; } | sed -E 's/ caller_addr="[^"]*"//' | fold -w 160

say "The credential the workload retrieved from the Secret Vault, sealed to its CEK"
python3 - "$RUN/workload-retrieve/result.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
for k in ("target", "credential_type", "credential_hint", "mode", "freshness_kind", "suite", "cek_pub_bytes", "report_measurement_hex", "group_id", "item_type", "item_kid", "item_purpose", "item_algorithm", "secret_bytes", "secret_sha256", "origin_verified", "initiate_ms", "retrieve_ms"):
    print(f"  {k}: {r.get(k)}")
PY
echo "the container as released (its associated data names the Target, the Handle and the Credential Hint):"
python3 -c "import json,sys; b=json.load(open(sys.argv[1])); print('  container:', b['container'], 'suite:', b['suite']); print('  aad:', b['aad']); print('  origin signature:', (b.get('origin') or {}).get('alg') or 'none')" "$RUN/workload-retrieve/bundle.json"
echo "the Secret Vault's release:"
{ grep -E 'released: target=https://ledger-nonce' "$RUN/bench-logs/vault-gateway.log" || true; } | head -2 | cut -c1-220

say "The verdict"
cat "$RUN/verdict.txt"

say "Writing the walkthrough"
python3 - "$RUN" "$DEMO_DIR" "$PLATFORM" "$HOME" <<'PY'
import json, os, re, subprocess, sys, textwrap
run, demo, platform, home = sys.argv[1:5]
def read(p):
    return open(p, errors="replace").read() if os.path.exists(p) else ""
def tidy(s):
    return s.replace(home, "~")
r = json.load(open(f"{run}/workload/result.json"))
rr = json.load(open(f"{run}/workload-retrieve/result.json"))
verdict = read(f"{run}/verdict.txt")
server = read(f"{run}/server.log").splitlines()
audit = [re.sub(r' caller_addr="[^"]*"', "", l) for l in server if "API accessed" in l and ("method=EnrollCredential" in l or "method=RetrieveCredential" in l)]
enrolled = [re.sub(r' caller_addr="[^"]*"', "", l) for l in server if "Enrolled an attested X509-SVID" in l]
retrieved = [re.sub(r' caller_addr="[^"]*"', "", l) for l in server if "Retrieved an attested credential bundle" in l]
waiver = [l for l in server if "admitted under a waiver" in l]
veraison = [l for l in read(f"{run}/bench-logs/veraison-verification.log").splitlines() if "session requested" in l or "challenge-response/v1/newSession" in l or "challenge-response/v1/session" in l]
vault = [l for l in read(f"{run}/bench-logs/vault-gateway.log").splitlines() if "released: target=https://ledger-nonce" in l]
mode = read(f"{run}/config/vault-mode.txt").strip().removeprefix("vault ")
bc = "background-check" in mode
sessions_intro = (
    "The Verifier's sessions: the first opened by the CAS Server with the enrollment's binding value as the nonce; in the\n"
    "Background Check model the Secret Vault opens the second for the retrieval itself:"
    if bc else
    "The Verifier's sessions, both opened by the CAS Server, the first with the enrollment's binding value as the nonce and\n"
    "the second with the retrieval's; in the Passport model the CAS Server forwards the resulting Attestation Results,\n"
    "unchanged, to the Secret Vault:")
retrieval_model = (
    "In the Background Check model the Secret Vault sent the Evidence to Veraison itself, recomputed the binding value from\n"
    "its Handle, the Target and CEKpub, and appraised the Attestation Results by its own policy."
    if bc else
    "In the Passport model the CAS Server sent the Evidence to Veraison and forwarded the Attestation Results, unchanged, to\n"
    "the Secret Vault, which recomputed the binding value from its Handle, the Target and CEKpub and appraised them by its own\n"
    "policy.")
conf = subprocess.run(["sed", "-n", "/credential_acquisition {/,/^        }$/p", f"{run}/config/server.conf"], capture_output=True, text=True).stdout
cert = subprocess.run(["openssl", "x509", "-in", f"{run}/workload/svid.pem", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"], capture_output=True, text=True).stdout
built_from = re.search(r"commit ([0-9a-f]{40})", read(f"{run}/spire-source.txt"))
built_from = f", built from commit `{built_from.group(1)[:12]}` (`spire-source.txt`)" if built_from else ""
kernel = read(f"{run}/kernel.txt").split()
kernel = kernel[2] if len(kernel) > 2 else " ".join(kernel)
machine = read(f"{run}/machine-type.txt").strip().split("/")[-1]
handle_octets = len(r.get("handle_hex") or "") // 2
signer = r.get("report_signer") or "the platform"
doc = f"""# TACRA on SPIRE: an attested workload on {platform}

A walkthrough of one run of the SPIRE proof of concept of draft-novak-rats-tacra, written from the run's record
`{os.path.basename(run)}`. Every output below is the run's own.

## Roles, in the words of the draft

- The attested workload is the Attester, with the Credential Acquisition Interface built in; it holds CSKpri and CEKpri
  inside the environment its Evidence attests.
- SPIRE Agent is the CAS Client and SPIRE Server the CAS Server: conduits that hold no RATS role and no credential.
  The CAS Server forwards Evidence to the Verifier; it does not appraise Attestation Results.
- SPIRE Server's CA is the Credential Authority, the Relying Party for enrollment: it issued the Freshness Handle,
  recomputes the binding value, appraises the Attestation Results by its own policy and mints the X509-SVID.
- The bench's Secret Vault is the Relying Party for retrieval; the bench's Veraison is the Verifier.
- The vault's mode in this run: {mode or 'passport'}.

## What runs where

- On the computer that runs the bench: SPIRE Server (the TWI-Unified-Model fork of SPIRE{built_from}), Veraison, the
  Secret Vault.
- In a fresh confidential guest ({machine or platform}, kernel {kernel}): SPIRE Agent and the attested workload, which
  generates its keys and obtains its Evidence through the Linux configfs-tsm interface.
- The guest reaches the server through an SSH reverse tunnel; the server reaches Veraison and the vault on that
  computer over mutually authenticated TLS.

## 1. Initiate-Credential-Acquisition

The workload asks the agent for the Target `{r['target']}` and Credential Type `{r['credential_type']}`. The agent
attests the workload (unix selectors), picks its registration entry and forwards the request to the server. The
Credential Authority answers:

- mode: {r.get('mode')}
- Freshness Kind: {r.get('freshness_kind')}; Handle ({handle_octets} octets, single use in this implementation): `{r.get('handle_hex')}`
- acceptable CSK algorithms: {r.get('acceptable_csk')}; acceptable Evidence formats: {r.get('acceptable_evidence')}

## 2. Enroll-Credential

The workload generates a P-256 Credential Signing Key and a PKCS#10 CSR, and the hardware signs Evidence whose
freshness input is the TACRA binding value, SHA-512 over the Handle, the Target and the CSR:

- binding value: `{r.get('binding_value_hex')}`
- Evidence: {r.get('evidence_bytes')} octets of `{r.get('evidence_media_type')}` ({r.get('report_provider')}, report version {r.get('report_version')}, signed by {signer})
- launch measurement: `{r.get('report_measurement_hex')}`

The CAS Server forwards the Evidence to Veraison with the binding value as the session nonce. The Credential
Authority takes the Handle it issued, recomputes the binding value from the Handle, the Target and the CSR, checks the
CSR's proof of possession, appraises the Attestation Results (the nonce they carry, the launch measurement against its
list, the bench's platform rule) and mints the X509-SVID. Timing: initiate {r.get('initiate_ms')} ms, enroll
{r.get('enroll_ms')} ms, Veraison included.

The certificate as the workload received it, its chain verified against the trust domain's bundle, its key the
workload's own:

```
{cert.strip()}
```

The Credential Authority's audit records of the enrollment:

```
{chr(10).join(l for l in audit if 'EnrollCredential' in l)}
{chr(10).join(enrolled)}
```
{('The platform rule admitted the host under a named waiver:' + chr(10) + chr(10) + '```' + chr(10) + chr(10).join(waiver) + chr(10) + '```') if waiver else ''}

{sessions_intro}

```
{chr(10).join(veraison[:8])}
```

## 3. Retrieve-Credential

For the Target `{rr['target']}` (Credential Type {rr['credential_type']}, Credential Hint `{rr.get('credential_hint')}`)
the server answers mode {rr.get('mode')} with the Secret Vault's Handle. The workload generates a Credential Encryption
Key for the suite `{rr.get('suite')}` (CEKpub {rr.get('cek_pub_bytes')} octets), binds it into fresh Evidence, and the
vault, the Relying Party, releases:

- credential group: `{rr.get('group_id')}`
- item: {rr.get('item_type')} `{rr.get('item_kid')}`, purpose {rr.get('item_purpose')}, algorithm {rr.get('item_algorithm')}, {rr.get('secret_bytes')} octets (the record keeps only its SHA-256, `{rr.get('secret_sha256')}`)
- the container's origin signature verified under the vault's key: {rr.get('origin_verified')}
- timing: initiate {rr.get('initiate_ms')} ms, retrieve {rr.get('retrieve_ms')} ms

{retrieval_model} Only the workload's CEK opens the container; the agent and the server carried it sealed.

The CAS Server's audit record of the retrieval, and the Secret Vault's release:

```
{chr(10).join(l for l in audit if 'RetrieveCredential' in l)}
{chr(10).join(retrieved)}
{chr(10).join(vault[:1])}
```

## The server's configuration

```
{textwrap.dedent(conf).strip()}
```

## The verdict

```
{verdict.strip()}
```
"""
open(f"{demo}/walkthrough.md", "w").write(tidy(doc))
print(f"{demo}/walkthrough.md")
PY
say "Done: $DEMO_DIR"
