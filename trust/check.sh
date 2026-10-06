#!/usr/bin/env bash
# Compares each file in trust/ that has an online source with a fresh download, then checks that every SEV-SNP launch
# in approved-launches.json has a reference value in the CoRIM Veraison is provisioned with. Prints every SHA-256.
#
#   trust/check.sh        (make trust-check)
set -euo pipefail
. "$(cd "$(dirname "$0")/.." && pwd)/scripts/lib.sh"
T="$BENCH_REPO/trust"
bad=0
same_as() { # FILE URL
  local got
  got="$(curl -sf -m 30 "$2" | { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; } | cut -d' ' -f1)"
  if [ "$got" = "$(bench_sha256 "$T/$1")" ]; then
    echo "ok   $1 is the same as $2"
  else
    echo "FAIL $1 differs from $2 (or the download failed)" >&2
    bad=1
  fi
}
same_as amd-kds-milan-cert_chain.pem https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
same_as GCE-cc-tcb-root_1.crt https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt
python3 - "$T/approved-launches.json" "$T/veraison-corim-milan.cbor" <<'PY' || bad=1
import json, sys
approved, corim = json.load(open(sys.argv[1])), open(sys.argv[2], "rb").read()
missing = [e["measurement"] for e in approved["sev-snp"] if bytes.fromhex(e["measurement"]) not in corim]
for m in missing:
    print(f"FAIL approved SEV-SNP launch {m[:16]}... has no reference value in veraison-corim-milan.cbor", file=sys.stderr)
if not missing:
    print(f"ok   the CoRIM holds a reference value for each of the {len(approved['sev-snp'])} approved SEV-SNP launches")
sys.exit(1 if missing else 0)
PY
echo
(cd "$T" && for f in *; do [ -f "$f" ] && printf '%s  %s\n' "$(bench_sha256 "$f")" "$f"; done)
exit "$bad"
