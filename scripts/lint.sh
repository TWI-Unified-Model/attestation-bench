#!/usr/bin/env bash
# The repository's linters, each at the version scripts/versions.env and scripts/requirements-dev.txt pin (installed
# into BENCH_HOME/tools/bin and BENCH_HOME/venv when missing). Exits non-zero on any finding.
#
#   scripts/lint.sh        (make lint)
#
#   ShellCheck     the bench's shell scripts
#   gofmt, go vet  every Go module (hwcheck under each of its three module files)
#   golangci-lint  every Go module (.golangci.yml)
#   ruff           the Python scripts: check, and format --check (ruff.toml)
#   actionlint     the CI workflows, and that their Go is GO_VERSION
#
# Not linted, kept as upstream has them: the TACRA proof of concept's deploy/ scripts, and its est module, whose test
# does not build against the current est code (reported to the group).
set -euo pipefail
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
cd "$BENCH_REPO"
T="$BENCH_HOME/tools/bin"
mkdir -p "$T"

bench_say "lint tools"
bench_go_tool golangci-lint "$GOLANGCI_LINT" "$T"
bench_go_tool actionlint "$ACTIONLINT" "$T"
if ! "$T/shellcheck" --version 2>/dev/null | grep -qx "version: ${SHELLCHECK_VERSION#v}"; then
  sc_arch="$([ "$BENCH_ARCH" = arm64 ] && echo aarch64 || echo x86_64)"
  sc_tgz="shellcheck-$SHELLCHECK_VERSION.$BENCH_OS.$sc_arch.tar.gz"
  sc_key="SHELLCHECK_SHA256_${BENCH_OS}_${BENCH_ARCH}"
  [ -n "${!sc_key:-}" ] || bench_die "no pinned ShellCheck $SHELLCHECK_VERSION for $BENCH_OS/$BENCH_ARCH in scripts/versions.env"
  sc_tmp="$(mktemp -d)"
  curl -sfL -o "$sc_tmp/$sc_tgz" "https://github.com/koalaman/shellcheck/releases/download/$SHELLCHECK_VERSION/$sc_tgz" \
    || bench_die "download $sc_tgz"
  [ "$(bench_sha256 "$sc_tmp/$sc_tgz")" = "${!sc_key}" ] || bench_die "$sc_tgz does not match its pinned SHA-256"
  tar -xzf "$sc_tmp/$sc_tgz" -C "$sc_tmp"
  mv "$sc_tmp/shellcheck-$SHELLCHECK_VERSION/shellcheck" "$T/shellcheck"
  rm -rf "${sc_tmp:?}"
  echo "  shellcheck $SHELLCHECK_VERSION: installed (SHA-256 matches the pin)"
else
  echo "  shellcheck $SHELLCHECK_VERSION: present"
fi
[ -x "$BENCH_HOME/venv/bin/python3" ] || python3 -m venv "$BENCH_HOME/venv"
if ! "$BENCH_HOME/venv/bin/ruff" --version 2>/dev/null | grep -qx "ruff $(sed -n 's/^ruff==//p' scripts/requirements-dev.txt)"; then
  "$BENCH_HOME/venv/bin/python3" -m pip install -q --disable-pip-version-check -r scripts/requirements-dev.txt
fi
echo "  $("$BENCH_HOME/venv/bin/ruff" --version): present"

failed=""
check() { # NAME COMMAND...: runs a linter, reports it in one line, remembers a failure
  local name=$1 out
  shift
  if out="$("$@" 2>&1)"; then
    printf '  ok    %s\n' "$name"
  else
    printf '  FAIL  %s\n' "$name"
    printf '%s\n' "$out" | sed 's/^/        /'
    failed="$failed $name"
  fi
}
go_each() { # COMMAND...: in every Go module
  local m
  for m in $BENCH_GO_MODULES; do (cd "$m" && "$@") || return 1; done
}
gofmt_clean() { [ -z "$(gofmt -l "$@")" ] || { gofmt -l "$@"; return 1; }; }
ci_go_pinned() { # every go-version in the workflows is the bench's GO_VERSION
  local v bad=0
  while IFS= read -r v; do
    if [ "$v" != "$GO_VERSION" ]; then echo "a workflow uses Go $v; scripts/versions.env says $GO_VERSION"; bad=1; fi
  done < <(sed -nE 's/.*go-version: *"?([0-9][0-9.]*)"?.*/\1/p' .github/workflows/*.yml)
  return "$bad"
}
hwcheck_vet() {
  local mf
  for mf in go.mod go.patched.mod go.v015.mod; do (cd hwcheck && go vet -modfile="$mf" ./...) || return 1; done
}

bench_say "third-party sources: the Go modules build against them (third_party/fetch.sh)"
"$BENCH_REPO/third_party/fetch.sh"

bench_say "linters"
sh_files=()
while IFS= read -r f; do sh_files+=("$f"); done < <(git ls-files '*.sh' | grep -v -e '^deploy/' -e '^third_party/.*/src')
py_files=()
while IFS= read -r f; do py_files+=("$f"); done < <(git ls-files '*.py' | grep -v -e '^third_party/' -e '/evidence/')
check "shellcheck (${#sh_files[@]} scripts)" "$T/shellcheck" -x "${sh_files[@]}"
# shellcheck disable=SC2086  # BENCH_GO_MODULES is a list of directories
check "gofmt" gofmt_clean $BENCH_GO_MODULES
check "go vet" go_each go vet ./...
check "go vet (hwcheck: go.patched.mod, go.v015.mod)" hwcheck_vet
check "golangci-lint" go_each "$T/golangci-lint" run --show-stats=false ./...
check "ruff check (${#py_files[@]} scripts)" "$BENCH_HOME/venv/bin/ruff" check "${py_files[@]}"
check "ruff format" "$BENCH_HOME/venv/bin/ruff" format --check "${py_files[@]}"
if [ -d .github/workflows ]; then
  check "actionlint" "$T/actionlint"
  check "CI's Go is GO_VERSION" ci_go_pinned
fi

if [ -n "$failed" ]; then bench_die "lint failed:$failed"; fi
echo "lint: every linter clean"
