#!/usr/bin/env bash
# Makes a new fictional bank: packs/NAME/pack.json, a copy of the Demo Bank's pack with every one of its names under
# NAME.example instead of demobank.example (the Targets, the RRP identifiers, the workload's names, the components'
# client certificates), and its secret under NAME/ in Vault. Edit it as packs/README.md describes, then bring the bank
# up with BANK=NAME make bank-up.
#
#   scripts/bank-new.sh NAME        (make bank-new NAME=...)
set -euo pipefail
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
name="${1:-}"
[[ "$name" =~ ^[a-z][a-z0-9-]{1,30}[a-z0-9]$ ]] ||
  bench_die "name a bank with 3 to 32 lower-case letters, digits and hyphens: make bank-new NAME=acme-bank"
case "$name" in demo-bank | tacra-bench) bench_die "$name is a pack the bench ships" ;; esac
dst="$BENCH_REPO/packs/$name/pack.json"
[ ! -e "$dst" ] || bench_die "packs/$name exists already"
mkdir -p "$(dirname "$dst")"
python3 - "$BENCH_REPO/packs/demo-bank/pack.json" "$dst" "$name" <<'PY'
import json, sys
from pathlib import Path

src, dst, name = sys.argv[1:]
text = Path(src).read_text().replace("demobank.example", f"{name}.example").replace('"demobank/', f'"{name}/')
pack = json.loads(text)
pack["name"] = name
assert "demobank" not in json.dumps(pack)
Path(dst).write_text(text.replace('"name": "demo-bank"', f'"name": "{name}"', 1))
assert json.loads(Path(dst).read_text()) == pack
PY
echo "packs/$name/pack.json: the Demo Bank's Targets and policy, under $name.example"
echo "Edit it if you wish (packs/README.md), then:  BANK=$name make bank-up"
