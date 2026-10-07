# Contributing

Thank you for improving the bench. The rules below keep every result reproducible and every claim checkable.

## Before you send a change

```bash
make check      # every linter at its pinned version, then every unit test; CI runs the same
```

Then run what your change touches, and say in the commit message what you ran and what it gave:

| You changed | Run |
|---|---|
| a script, the trust zone, a gateway, a verifier, the generator, a pack | `make setup`, `make check-mtls`, `make demo`, `make attacks`, `make redirect` |
| a platform plug-in, the CAI, the binding | the above, and the hardware runs of the platforms it touches (`PLATFORM=…`) |
| the Demo Bank | `make bank-up`, `bank-pay` on the platforms and both controls, `bank-audit`, `bank-down` |
| documentation | every command you added or changed, exactly as written |

## Commits

- One logical change per commit, with a message that says what changed and why, in plain words.
- End with a "Checked:" paragraph: the commands you ran and their results ("make demo 10/10; make attacks 82/82 and
  50/50").
- Author commits with your real name and e-mail address.

## Evidence

A number in the documentation names the run it comes from. When a hardware run changes a documented result, keep it
in the repository, in the directory of its kind:

```bash
RUNS_DIR="$PWD/e2e/evidence" make demo PLATFORM=gcp-snp
RUNS_DIR="$PWD/hwcheck/evidence" make attacks PLATFORM=gcp-snp
```

Compare it with the run it replaces (the tools in [docs/results.md](docs/results.md)), add a short `README.md` to its
directory saying what it shows, and commit the directory as the run left it. Never edit a sealed run's files.

## Style

- **Go**: `gofmt`, and golangci-lint with `.golangci.yml`. Errors are returned with context, never ignored without a
  comment saying why.
- **Shell**: bash, `set -euo pipefail`, ShellCheck clean; source `scripts/lib.sh` for the shared settings and
  helpers. A run judges itself with `scripts/verdict.py` (its `verdict.txt`), then seals its directory with
  `bench_seal`, prints `== run directory: <path>` and exits 1 unless the verdict is PASS. A new kind of run gets its
  expectation in `scripts/verdict.py` and a test in `scripts/tests/`.
- **Python**: ruff with `ruff.toml` (format and check); files opened with `with` or `pathlib`; tests with `unittest`
  (`make test` runs them).
- **Comments and documentation**: say what the code is for and why, not what each line does; plain English; no
  claim without its source (a file and line, a run directory, a URL).

## Changing a third-party component

The EST server, Veraison and go-gen-ref are fetched at a pinned upstream commit, with our patch series on top
(`third_party/<name>/UPSTREAM`, `patches/`). `third_party/fetch.sh` refuses sources whose tree differs from the one
recorded. To change a patch:

```bash
cd third_party/veraison-services/src
git reset --hard <BASE from UPSTREAM>           # the pinned upstream commit
git am ../patches/*.patch                       # our series, as commits
# ... make the change and commit it ...
rm ../patches/*.patch && git format-patch -o ../patches <BASE>
git write-tree                                  # record this tree in UPSTREAM, VARIANTS, for the variant
cd - && third_party/fetch.sh veraison-services  # fetches again and checks the recorded tree
```

## The TACRA proof of concept's code

`cai/`, `platform/`, `proto/`, `gen/`, `client/`, `server/`, `deploy/` and `est/` are the TWI SIG's proof of concept.
A change there is a change to the SIG's code: propose it to the SIG as well (github.com/TWI-Unified-Model/tacra), and
keep this repository's copy the same as what the SIG merges.

## Secrets and private material

Never commit keys, tokens, passwords, cloud credentials or anything from `~/.attestation-bench`. Never commit
material under licence or confidentiality terms, or anyone's personal data. A run directory may show the host names
and paths of the machine it ran on: look before you commit it.
