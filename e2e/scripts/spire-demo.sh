#!/usr/bin/env bash
# The demo of the SPIRE proof of concept of TACRA: one end-to-end run with a confidential VM, narrated, recorded as a
# typescript, and written up from the record of the run as a walkthrough.
#
#   SPIRE_REPO=<checkout of the fork> e2e/scripts/spire-demo.sh [sev-snp|tdx|aws]   (default sev-snp: Google Cloud
#                                                        SEV-SNP; SPIRE_REPO as the run scripts read it)
#   DEMO_RUN=<run directory> e2e/scripts/spire-demo.sh   narrates a run already made, without a new run
#
# The roles are those of doc/attested_credential_acquisition.md of the fork. The Workload is the Attester. SPIRE Agent
# is the Client of the Credential Acquisition System, and SPIRE Server its Server. In Enrollment the Server is the
# Relying Party as well, and its CA mints the X509-SVID. In Retrieval the Relying Party is the Secret Vault of the
# bench, and the Server is the conduit: in the Passport model the Server obtains the Attestation Results from the
# Verifier and forwards them; in the Background Check model the Secret Vault asks the Verifier itself.
#
# Output: DEMO_DIR (default BENCH_HOME/demo/<stamp>-spire-<platform>) with demo.typescript (the recording),
# demo.txt (the same without terminal control sequences), run.log, run-directory.txt and walkthrough.md.
# The recording of an AWS run names instance identifiers.
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"
PLATFORM="${1:-sev-snp}"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
B="$BENCH_HOME"

if [ -n "${DEMO_RUN:-}" ]; then
  [ -d "$DEMO_RUN" ] || bench_die "no such run directory: $DEMO_RUN"
  # the directory of a run already made names its platform
  case "$(basename "$DEMO_RUN")" in
    *-spire-gcp-sev-snp-e2e) PLATFORM=sev-snp ;;
    *-spire-gcp-tdx-e2e) PLATFORM=tdx ;;
    *-spire-aws-sev-snp-e2e) PLATFORM=aws ;;
  esac
else
  bench_spire_repo
fi
case "$PLATFORM" in
  sev-snp) PLATFORM_NAME="Google Cloud SEV-SNP" VERIFIER_NAME="Veraison" ;;
  tdx) PLATFORM_NAME="Google Cloud TDX" VERIFIER_NAME="the TDX Verifier of the bench" ;;
  aws) PLATFORM_NAME="AWS SEV-SNP" VERIFIER_NAME="Veraison" ;;
  *) bench_die "platform: sev-snp, tdx or aws" ;;
esac

if [ "${DEMO_RECORDED:-}" != 1 ]; then
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  DEMO_DIR="${DEMO_DIR:-$B/demo/${STAMP}-spire-${PLATFORM}}"
  export DEMO_DIR
  mkdir -p "$DEMO_DIR"
  # The session of this script is recorded as a typescript: the narration runs under a pseudo-terminal, and its
  # output is copied to the file byte for byte. script(1) needs a terminal on its standard input; this recorder works
  # from any shell. The recorder is the here-document, which python3 reads from its standard input.
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
# without this, git under the pseudo-terminal opens its pager and waits for a key
export GIT_PAGER=cat PAGER=cat

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
show() { printf '\033[2m$ %s\033[0m\n' "$*"; "$@"; }

say "The SPIRE proof of concept of TACRA: an attested Workload on $PLATFORM_NAME"
echo "The Workload is the Attester. SPIRE Agent is the Client of the Credential Acquisition System, and SPIRE Server"
echo "its Server. In Enrollment the Server is the Relying Party as well: it issues the Freshness Handle, sends the"
echo "Evidence to the Verifier, verifies the Attestation Results and the binding, applies the policy for the Target,"
echo "and its CA mints the X509-SVID. In Retrieval the Relying Party is the Secret Vault of the bench, and the Server"
echo "is the conduit. The Verifier is $VERIFIER_NAME."

say "The services of the bench"
show "$HERE/e2e/scripts/bench.sh" status
echo "Secret Vault: $(python3 -c "import json,sys; v=json.load(open(sys.argv[1])); print('rats_model=' + str(v.get('rats_model') or 'passport'))" "$B/config/vault-gateway.json")"

say "The code under demonstration"
if [ -n "${DEMO_RUN:-}" ]; then
  show cat "$DEMO_RUN/spire-source.txt"
else
  show git -C "$SPIRE_REPO" --no-pager log --oneline -3
  # grep ends with status 1 when go.mod has no replace directive
  show grep -E '^replace' "$SPIRE_REPO/go.mod" || echo "go.mod has no replace directive"
fi

if [ -n "${DEMO_RUN:-}" ]; then
  say "Narrated from the record of a run already made: $DEMO_RUN"
  RUN="$DEMO_RUN"
else
  say "The run: a new confidential VM, SPIRE Agent, the attested Workload"
  RUN_LOG="$DEMO_DIR/run.log"
  set +e
  case "$PLATFORM" in
    sev-snp | tdx) TEE="$PLATFORM" "$HERE/e2e/scripts/spire-gcp-snp-e2e.sh" 2>&1 | tee "$RUN_LOG"; rc=${PIPESTATUS[0]} ;;
    aws) "$HERE/e2e/scripts/spire-aws-snp-e2e.sh" 2>&1 | tee "$RUN_LOG"; rc=${PIPESTATUS[0]} ;;
  esac
  set -e
  RUN="$(grep -E '^== run directory: ' "$RUN_LOG" | tail -1 | sed 's/^== run directory: //' || true)"
  [ -n "$RUN" ] && [ -d "$RUN" ] || bench_die "no run directory in $RUN_LOG"
  [ "$rc" = 0 ] || bench_die "the run failed with exit status $rc; its record is $RUN"
fi
echo "$RUN" > "$DEMO_DIR/run-directory.txt"

say "The configuration of the Server for the Targets: paths and policy, no secret"
show sed -n '/credential_acquisition {/,/^        }$/p' "$RUN/config/server.conf"

say "The X509-SVID that the Workload enrolled: its key, the SPIFFE ID of the registration entry, the CA of the trust domain"
show openssl x509 -in "$RUN/workload/svid.pem" -noout -subject -issuer -dates -ext subjectAltName
echo "the record of the Enrollment, as the Workload wrote it:"
python3 - "$RUN/workload/result.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
for k in ("target", "credential_type", "mode", "freshness_kind", "handle_hex", "binding_value_hex", "evidence_media_type", "evidence_bytes", "report_provider", "report_version", "report_signer", "report_measurement_hex", "spiffe_id", "chain_verified", "key_matches", "initiate_ms", "enroll_ms"):
    print(f"  {k}: {r.get(k)}")
PY

say "What SPIRE Server recorded for the Enrollment, in its audit log: the Verifier, the launch measurement, a waiver when one applied"
{ grep -E 'Enrolled an attested X509-SVID|API accessed.*method=EnrollCredential|admitted under a waiver' "$RUN/server.log" || true; } | sed -E 's/ caller_addr="[^"]*"//' | fold -w 160

VAULT_MODE="$(cat "$RUN/config/vault-mode.txt" 2>/dev/null || true)"
case "$VAULT_MODE" in
  *background-check*) say "The sessions of the Verifier: the Server opens one for the Enrollment; in the Background Check model the Secret Vault opens one for the Retrieval" ;;
  *) say "The sessions of the Verifier, both opened by the Server: in the Passport model the Server forwards the Attestation Results to the Secret Vault" ;;
esac
{ grep -E 'session requested|challenge-response/v1/newSession|challenge-response/v1/session' "$RUN/bench-logs/veraison-verification.log" || true; } | head -6 | cut -c1-200

say "What SPIRE Server recorded for the Retrieval, in its audit log"
{ grep -E 'API accessed.*method=RetrieveCredential|Retrieved an attested credential bundle' "$RUN/server.log" || true; } | sed -E 's/ caller_addr="[^"]*"//' | fold -w 160

say "The credential that the Workload retrieved from the Secret Vault, sealed to the CEK of the Workload"
python3 - "$RUN/workload-retrieve/result.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
for k in ("target", "credential_type", "credential_hint", "mode", "freshness_kind", "suite", "cek_pub_bytes", "report_measurement_hex", "group_id", "item_type", "item_kid", "item_purpose", "item_algorithm", "secret_bytes", "secret_sha256", "origin_verified", "initiate_ms", "retrieve_ms"):
    print(f"  {k}: {r.get(k)}")
PY
echo "the container as the Secret Vault released it (the associated data name the Target, the Handle and the Credential Hint):"
python3 -c "import json,sys; b=json.load(open(sys.argv[1])); print('  container:', b['container'], 'suite:', b['suite']); print('  aad:', b['aad']); print('  origin signature:', (b.get('origin') or {}).get('alg') or 'none')" "$RUN/workload-retrieve/bundle.json"
echo "the release, in the log of the Secret Vault:"
{ grep -E 'released: target=' "$RUN/bench-logs/vault-gateway.log" || true; } | head -2 | cut -c1-220

say "The verdict"
cat "$RUN/verdict.txt"

say "Writing the walkthrough"
python3 - "$RUN" "$DEMO_DIR" "$PLATFORM_NAME" "$VERIFIER_NAME" "$HOME" <<'PY'
import json, os, re, subprocess, sys, textwrap
run, demo, platform, verifier, home = sys.argv[1:6]
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
vault = [l for l in read(f"{run}/bench-logs/vault-gateway.log").splitlines() if "released: target=" in l]
mode = read(f"{run}/config/vault-mode.txt").strip().removeprefix("vault ")
bc = "background-check" in mode
sessions_intro = (
    "The sessions of the Verifier. The Server opens the first, with the binding value of the Enrollment as the nonce. In\n"
    "the Background Check model the Secret Vault opens the second, for the Retrieval:"
    if bc else
    "The sessions of the Verifier, both opened by the Server: the first with the binding value of the Enrollment as the\n"
    "nonce, the second with the binding value of the Retrieval. In the Passport model the Server forwards the Attestation\n"
    "Results of the second session, unchanged, to the Secret Vault:")
retrieval_model = (
    "In the Background Check model the Secret Vault sent the Evidence to the Verifier, recomputed the binding value from\n"
    "the Handle, the Target and CEKpub, and appraised the Attestation Results by its own policy."
    if bc else
    "In the Passport model the Server sent the Evidence to the Verifier and forwarded the Attestation Results, unchanged,\n"
    "to the Secret Vault. The Secret Vault recomputed the binding value from the Handle, the Target and CEKpub, and\n"
    "appraised the Attestation Results by its own policy.")
conf = subprocess.run(["sed", "-n", "/credential_acquisition {/,/^        }$/p", f"{run}/config/server.conf"], capture_output=True, text=True).stdout
cert = subprocess.run(["openssl", "x509", "-in", f"{run}/workload/svid.pem", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"], capture_output=True, text=True).stdout
built_from = re.search(r"commit ([0-9a-f]{40})", read(f"{run}/spire-source.txt"))
built_from = f", built from commit `{built_from.group(1)[:12]}` (`spire-source.txt`)" if built_from else ""
kernel = read(f"{run}/kernel.txt").split()
kernel = kernel[2] if len(kernel) > 2 else " ".join(kernel)
machine = read(f"{run}/machine-type.txt").strip().split("/")[-1]
handle_octets = len(r.get("handle_hex") or "") // 2
signer = r.get("report_signer") or "the platform"
doc = f"""# TACRA through SPIRE: an attested Workload on {platform}

A walkthrough of one run of the SPIRE proof of concept of TACRA, written from the record of the run
`{os.path.basename(run)}`. Every output below comes from that record.

## Roles

- The Workload is the Attester. It generates its keys, and the private keys stay inside the environment that its
  Evidence attests.
- SPIRE Agent is the Client of the Credential Acquisition System, and SPIRE Server its Server.
- In Enrollment the Server is the Relying Party as well: it issues the Freshness Handle, sends the Evidence to the
  Verifier, verifies the Attestation Results and the binding, applies the policy for the Target, and its CA mints the
  X509-SVID.
- In Retrieval the Relying Party is the Secret Vault of the bench, and the Server is the conduit.
- The Verifier is {verifier}.
- The Secret Vault in this run: {mode or 'rats_model=passport'}.

## What runs where

- On the computer that runs the bench: SPIRE Server (the TWI-Unified-Model fork of SPIRE{built_from}), the Verifier
  and the Secret Vault.
- In a new confidential VM ({machine or platform}, kernel {kernel}): SPIRE Agent and the attested Workload, which
  generates its keys and obtains its Evidence through the Linux configfs-tsm interface.
- The VM reaches the Server through an SSH reverse tunnel. The Server reaches the Verifier and the Secret Vault on
  that computer over mutually authenticated TLS.

## 1. InitiateCredentialAcquisition

The Workload asks the Agent for the Target `{r['target']}` and the Credential Type `{r['credential_type']}`. The Agent
attests the Workload (unix selectors), picks its registration entry and forwards the call to the Server. The Server
answers:

- mode: {r.get('mode')}
- Freshness Kind: {r.get('freshness_kind')}; Handle ({handle_octets} octets, consumed once): `{r.get('handle_hex')}`
- CSK algorithms accepted: {r.get('acceptable_csk')}; Evidence formats accepted: {r.get('acceptable_evidence')}

## 2. EnrollCredential

The Workload generates a P-256 Credential Signing Key and a PKCS#10 CSR. The hardware signs Evidence whose freshness
input is the binding value of TACRA: the SHA-512 digest of the binding input, which holds the Handle, the Target and
the CSR.

- binding value: `{r.get('binding_value_hex')}`
- Evidence: {r.get('evidence_bytes')} octets of `{r.get('evidence_media_type')}` ({r.get('report_provider')}, report version {r.get('report_version')}, signed by {signer})
- launch measurement: `{r.get('report_measurement_hex')}`

The Server sends the Evidence to the Verifier with the binding value as the nonce of the session. The Server then
consumes the Handle that it issued, recomputes the binding value from the Handle, the Target and the CSR, checks the
proof of possession of the CSR, and verifies the Attestation Results: the nonce in them, the launch measurement against
the list for the Target, and the platform rule. Its CA mints the X509-SVID. Timing: initiate {r.get('initiate_ms')} ms,
enroll {r.get('enroll_ms')} ms, the Verifier included.

The certificate as the Workload received it. The Workload verified the chain against the bundle of the trust domain,
and checked that the certificate holds the key that the Workload generated:

```
{cert.strip()}
```

The audit records of the Enrollment in the log of SPIRE Server:

```
{chr(10).join(l for l in audit if 'EnrollCredential' in l)}
{chr(10).join(enrolled)}
```
{('The platform rule admitted the host under a named waiver:' + chr(10) + chr(10) + '```' + chr(10) + chr(10).join(waiver) + chr(10) + '```') if waiver else ''}

{sessions_intro}

```
{chr(10).join(veraison[:8])}
```

## 3. RetrieveCredential

For the Target `{rr['target']}` (Credential Type {rr['credential_type']}, Credential Hint `{rr.get('credential_hint')}`)
the Server answers mode {rr.get('mode')} with the Handle that the Secret Vault originated. The Workload generates a
Credential Encryption Key for the suite `{rr.get('suite')}` (CEKpub {rr.get('cek_pub_bytes')} octets) and binds CEKpub
into new Evidence. The Secret Vault, the Relying Party, releases:

- credential group: `{rr.get('group_id')}`
- item: {rr.get('item_type')} `{rr.get('item_kid')}`, purpose {rr.get('item_purpose')}, algorithm {rr.get('item_algorithm')}, {rr.get('secret_bytes')} octets (the record keeps the SHA-256 of the credential, not the credential: `{rr.get('secret_sha256')}`)
- origin signature of the container verified under the key of the Secret Vault: {rr.get('origin_verified')}
- timing: initiate {rr.get('initiate_ms')} ms, retrieve {rr.get('retrieve_ms')} ms

{retrieval_model} The CEK of the Workload alone opens the container: the Agent and the Server forward the container
sealed.

The audit record of the Retrieval in the log of SPIRE Server, and the release in the log of the Secret Vault:

```
{chr(10).join(l for l in audit if 'RetrieveCredential' in l)}
{chr(10).join(retrieved)}
{chr(10).join(vault[:1])}
```

## The configuration of the Server

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
