#!/usr/bin/env bash
# Fetches each third-party component at the upstream commit pinned in its UPSTREAM file, applies our patch series and
# checks that the resulting source tree is exactly the one the bench was tested with (the git tree hash recorded in
# UPSTREAM). Sources land in third_party/<name>/<variant>/, which git ignores. Veraison's patched variants then take
# go-gen-ref from third_party/go-gen-ref/src instead of the path in our patch.
#
#   third_party/fetch.sh               every component
#   third_party/fetch.sh NAME...       some of them: go-gen-ref, globalsign-est, veraison-services
#
# Needs git and network access to github.com (and go, for Veraison's go-gen-ref path). A variant whose tree already
# matches is left as it is, so the script can run again at any time.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPONENTS=(go-gen-ref globalsign-est veraison-services)

die() { echo "fetch: $*" >&2; exit 1; }

fetch_variant() { # NAME REPO BASE VARIANT PATCHES TREE
  local name=$1 repo=$2 base=$3 variant=$4 n=$5 want=$6
  local dir="$HERE/$name/$variant"
  case "$variant" in src | src-[a-z0-9]*) ;; *) die "$name: odd variant name '$variant'" ;; esac
  if [ -d "$dir/.git" ] && [ "$(git -C "$dir" rev-parse HEAD)" = "$base" ] && [ "$(git -C "$dir" write-tree)" = "$want" ]; then
    echo "ok    $name/$variant: already at $base + $n patch(es)"
  else
    rm -rf "${dir:?}"
    git clone --quiet --no-checkout --filter=blob:none "$repo" "$dir"
    git -C "$dir" checkout --quiet --detach "$base"
    [ "$(git -C "$dir" rev-parse HEAD)" = "$base" ] || die "$name: $base is not what $repo returned"
    local i=0 p
    for p in "$HERE/$name"/patches/*.patch; do
      [ "$i" -lt "$n" ] || break
      git -C "$dir" apply --index --whitespace=nowarn "$p" || die "$name/$variant: $(basename "$p") does not apply"
      i=$((i + 1))
    done
    [ "$i" -eq "$n" ] || die "$name/$variant: needs $n patches, found $i"
    local got
    got="$(git -C "$dir" write-tree)"
    [ "$got" = "$want" ] || die "$name/$variant: tree $got, expected $want: the sources are not the tested ones"
    echo "ok    $name/$variant: $base + $n patch(es) = tree $want"
  fi
  # Veraison's patch 0002 points go-gen-ref at ../go-gen-ref-v123, our workstation's layout: use the bench's copy.
  if [ "$name" = veraison-services ] && grep -q '^replace github.com/jraman567/go-gen-ref' "$dir/go.mod"; then
    (cd "$dir" && go mod edit -replace github.com/jraman567/go-gen-ref=../../go-gen-ref/src)
    echo "      $name/$variant: go-gen-ref => third_party/go-gen-ref/src"
  fi
}

fetch() { # NAME
  local name=$1 f="$HERE/$1/UPSTREAM"
  [ -f "$f" ] || die "no $f"
  local NAME REPO BASE VARIANTS v
  # shellcheck disable=SC1090
  . "$f"
  [ "$NAME" = "$name" ] || die "$f names $NAME"
  for v in $VARIANTS; do
    fetch_variant "$NAME" "$REPO" "$BASE" "${v%%:*}" "$(echo "$v" | cut -d: -f2)" "${v##*:}"
  done
}

if [ $# -eq 0 ]; then set -- "${COMPONENTS[@]}"; fi
for c in "$@"; do fetch "$c"; done
