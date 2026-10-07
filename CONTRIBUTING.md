# Contributing

Thank you for improving the bench. The rules below keep every result reproducible and every claim checkable.

## Before you send a change

```bash
make check      # every linter at its pinned version, then every unit test; CI runs the same
```

Then run what your change touches, and say in the commit message what you ran and what it gave:

| You changed | Run |
|---|---|
| a script, the trust zone, a gateway, a verifier, the generator, a pack | `make setup`, `make check-mtls`, `make test-live`, and `make demo`, `make attacks`, `make redirect` with `PLATFORM=gcp-snp` (and the other platforms the change reaches) |
| a platform plug-in, the CAI, the binding | the above, on every platform it touches (`PLATFORM=…`) |
| a third-party patch (`third_party/`) | the above, and the hardware runs of the platforms it touches; `make check` runs the tests the patches add |
| the Demo Bank | `make bank-up`, `bank-pay` on the platforms and both controls, `bank-audit`, `bank-down` |
| documentation | every command you added or changed, exactly as written |

## Commits

- One logical change per commit, with a message that says what changed and why, in plain words.
- End with a "Checked:" paragraph: the commands you ran and their results ("make demo PLATFORM=gcp-snp 10/10; make
  attacks PLATFORM=gcp-snp 212/212").
- Author commits with your real name and e-mail address.

## Tests

Nothing in a test stands in for a part of the system: no fake verifier, Vault, CA, EST server or TSM device, and no
made-up report, EAR, certificate or log. A test runs on real data (the reports, EARs and certificate tables that
hardware runs kept under `*/evidence/`, the draft's test vector, the reference implementation's vectors), on the live
trust zone that `make setup` brings up, or on the live services of AMD and Intel (AMD's key server for its CRLs,
Intel's provisioning certification service for its PCK CRL), so `make test` needs the network and fails without it. A test of a refusal
changes one input of real data, as an attacker would. What only a confidential VM can do, such as making Evidence, is
tested by the hardware runs.

In a third-party component, `make test` runs the tests our patches add (the test files the pinned upstream commit
does not have) and no others. It checks that each of them ran, and refuses a test binary that links a mock. Upstream's
own tests are not run: some of them use mocks, as the EST fork's tests use its mock CA. And no program the bench
builds, its own or a third-party one, may link a package named mock, fake or stub: `make test` checks every one.

`make test-live` runs the tests that need the running bench and no hardware: the EST server's wire format through the
live server, and the Evidence of the committed attack runs appraised again by the live verifiers. It fails when the
bench is not up; it never skips.

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
rm ../patches/*.patch && git format-patch --no-signature -o ../patches <BASE>
git write-tree                                  # record this tree in UPSTREAM, VARIANTS, for the variant
cd - && git status --short third_party/veraison-services/patches
```

`git am` makes new commits, so `git format-patch` writes a new commit id on the first line of every patch file. The
evidence cites the ids the patches have now; put back each patch you did not change, then fetch the sources again,
which checks the recorded tree, and run Veraison's tests on it:

```bash
git checkout -- third_party/veraison-services/patches/<a patch you did not change>
third_party/fetch.sh veraison-services
make test                                       # our tests in every component, Veraison's among them
```

`make setup` then builds the bench's Veraison again from the new tree, keeping its keys, certificates and stores
(the deployment records the trees it was built from, Veraison's and go-gen-ref's); a Demo Bank builds its own from
the trees at each `make bank-up`.

## The TACRA proof of concept's code

`cai/`, `platform/`, `proto/` and `gen/` are the parts of the TWI SIG's proof of concept that the bench runs. A change
there is a change to the SIG's code: propose it to the SIG as well (github.com/TWI-Unified-Model/tacra), and keep
this repository's copy of those parts the same as what the SIG merges.

The bench runs nothing that stands in for the real thing, so the proof of concept's simulated parts are not in this
tree: its Simulated plug-in (`platform/sim.go`) and EAT reader, the CAI sidecar, the HTTP client and the PoC's CAAPI
server with their Docker deployment, the `deploy/` scripts and the `est/` module with their mock CA, the PoC's guides,
and the CAI's and the plug-in interface's tests, which ran on the Simulated plug-in and on stand-ins for the CAAPI and
the CA. `git log` keeps them. The CAI and the SEV-SNP and TDX plug-ins run in every hardware run.

## Secrets and private material

Never commit keys, tokens, passwords, cloud credentials or anything from `~/.attestation-bench`. Never commit
material under licence or confidentiality terms, or anyone's personal data. A run directory may show the host names
and paths of the machine it ran on: look before you commit it. `make lint` scans the git history with gitleaks; add to
`.gitleaks.toml` only what you have shown is not a secret, with the narrowest pattern and the reason.
