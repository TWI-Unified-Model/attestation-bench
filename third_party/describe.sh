#!/usr/bin/env bash
# Prints one line per fetched third-party variant: the upstream commit, how many of our patches are applied, the source
# tree hash, and whether that tree is the one recorded in UPSTREAM (the tested one). Run scripts write this into
# their evidence, so a run names the exact sources it was built from.
#
#   third_party/describe.sh            every component
#   third_party/describe.sh NAME...    some of them
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPONENTS=(go-gen-ref globalsign-est veraison-services)
if [ $# -eq 0 ]; then set -- "${COMPONENTS[@]}"; fi
for c in "$@"; do
  NAME="" BASE="" VARIANTS=""
  # shellcheck disable=SC1090
  . "$HERE/$c/UPSTREAM"
  for v in $VARIANTS; do
    variant="${v%%:*}" n="$(echo "$v" | cut -d: -f2)" want="${v##*:}" dir="$HERE/$c/${v%%:*}"
    if [ ! -d "$dir/.git" ]; then
      echo "$NAME/$variant not fetched (third_party/fetch.sh $NAME)"
      continue
    fi
    head="$(git -C "$dir" rev-parse HEAD)" tree="$(git -C "$dir" write-tree)"
    state="tested tree"
    [ "$head" = "$BASE" ] && [ "$tree" = "$want" ] || state="NOT the tested tree (expected $want)"
    echo "$NAME/$variant upstream ${head:0:12} + $n patch(es), tree ${tree:0:12}: $state"
  done
done
