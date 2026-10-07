# Verification of the first release

How this release was checked before it was published, on 6 and 7 October 2026, and what each check found. Every
result names its evidence: a run directory in this repository, a command anyone can run again, or a commit.

| # | Gate | Checked | Result |
|---|---|---|---|
| 1 | Build and lint | every Go module; ShellCheck, gofmt, go vet, golangci-lint, ruff, Markdown links, actionlint and gitleaks, each at its pinned version (`make lint`) | clean, on macOS and on a fresh Ubuntu 24.04 |
| 2 | Tests | `go test` in the ten Go modules (fourteen packages have tests) and the 26 Python tests (`make test`) | all pass |
| 3 | Secrets and private material | gitleaks over the whole history; the tracked files searched for keys and for material that must not be here | no secret; what looks like one is explained below |
| 4 | A newcomer's run | [getting-started.md](getting-started.md) alone, on a fresh Ubuntu 24.04 VM and on a Mac with a fresh bench home | every step passed, after three fixes to the guide |
| 5 | Hardware | `make demo`, `attacks` and `redirect` on GCP SEV-SNP, GCP TDX and AWS SEV-SNP | identical to the earlier runs, check by check |
| 6 | The Demo Bank | `bank-up`, the five `bank-pay`, `bank-audit`, `bank-down`, in both RATS models, and a bank of one's own | as expected; both clouds empty afterwards |
| 7 | The documentation | every command in it run as written; every number tied to its evidence | done, but for `git clone` from GitHub (below) |

## 1 and 2. Build, lint and tests

`make check` (lint, then the tests) is clean on the Mac the bench was built on, at the release's commit, and on the
fresh Ubuntu 24.04 VM of section 4. CI runs the same target on every push, then sets the bench up from zero and runs
it, the refusal scenarios included ([../.github/workflows/ci.yml](../.github/workflows/ci.yml)). Before the repository
was published, CI's steps were run on fresh VMs, the last time at `31be704`: every step passed.

## 3. Secrets and private material

- **gitleaks** v8.30.1 over all the commits: no finding with [../.gitleaks.toml](../.gitleaks.toml). Without that
  file it reports 178 matches, none a secret: 175 SHA-256 digests of the demo API key, which an end-to-end run records
  instead of the key; the signing key of the signed container's test vectors, twice; and a signed attestation result
  kept as a test fixture. The file allows each by its narrowest pattern, with the reason; a made-up secret put in other
  fields of the same files is still found. `make lint` runs the scan on every change.
- **Keys:** no private key in the tracked files; the one match for a key header is a test that checks a value starts
  with it.
- **E-mail addresses:** none in the files. The commits carry their authors' own identities, the TWI SIG's and ours.
- **What the runs record about where they ran.** Run directories hold the host name and home path of the machine that
  ran the bench, and the id and number of the Google Cloud project the VMs ran in. They stay: the repository is
  private, for the team, and rewriting them would break the runs' seals and the commit ids they record. A public
  version would be a cleaned copy with a history of its own.
- **Known vulnerabilities in the pinned dependencies:** [limits.md](limits.md), "Third-party versions".

## 4. A newcomer's run

**On a fresh Ubuntu 24.04 VM** (Google Cloud e2-standard-4, 40 GB disk), at `7b36b6a`, with nothing but the guide: Go
as step 1 says, the code from a bundle of `main` (the repository was not on GitHub yet), then each step as written.

| Step | Result | Time | Disk used |
|---|---|---|---|
| the machine as it came | git, curl, python3 3.12.3 present; make, gcc, Go absent | | 2.5 GB |
| 1, Go 1.27.0 from go.dev, checked against its SHA-256; git and make | ok | 3 s + 35 s | 3.1 GB |
| 3, `make doctor` | `MISSING`: python3-venv, gcc, unzip, sqlite3, protobuf-compiler, each with its apt command | 1 s | |
| installing what it asked for | ok (61.5 MB from the Ubuntu mirror at 60 kB/s that hour) | 1062 s | 3.4 GB |
| 3, `make doctor` again | `Ready for make setup`, one warning: no AWS CLI (hardware only) | 0 s | |
| 4, `make setup` | ok, 10/10 | 510 s | 10.7 GB |
| 5, 6: `make status`, `make check-mtls` | 13 services; `VERDICT PASS: 47 of 47` | 2 s | |
| 7, `make demo` | `VERDICT PASS: all 10 Targets` | 44 s | |
| 8, `make attacks` | `VERDICT PASS: 132 checks` | 33 s | |
| 9, `make redirect` | `VERDICT PASS`, the bench back in Passport | 34 s | 11.2 GB |
| 10, the run directory's seal, `make report` | every file `OK`; 4 runs, 4 PASS | 1 s | |
| 11, Background Check, `make demo`, back to Passport | `VERDICT PASS: all 10 Targets`; 13 services | 25 s | |
| 12, `make stop`, `make start`, then the uninstall | ok; the bench's home was 1.4 GB, Go's module cache 2.6 GB, its build cache 1.8 GB | 15 s | 9.7 GB |
| 12, `make setup` again, `make demo` | ok, from zero; `VERDICT PASS: all 10 Targets` | 66 s | 11.2 GB |
| `make check`, as CI runs it | clean; every test passes | 320 s | 12.9 GB |

**On the Mac** (macOS 26.6.2, Apple silicon), at `8b73a49`: a clone in an empty directory and a fresh
`~/.attestation-bench`, steps 3 to 12. The bench's own home was moved aside for the test and put back after it;
`make demo` on it then gave `VERDICT PASS`.

| Step | Result | Time |
|---|---|---|
| 3, `make doctor` | `Ready for make setup` | 1 s |
| 4, `make setup` | ok, 10/10 (Go's caches were already on this machine) | 114 s |
| 5, 6: `make status`, `make check-mtls` | 13 services; `VERDICT PASS: 47 of 47` | 2 s |
| 7, `make demo` | `VERDICT PASS: all 10 Targets` | 6 s |
| 8, `make attacks` | `VERDICT PASS: 132 checks` | 3 s |
| 9, `make redirect` | `VERDICT PASS`, the bench back in Passport | 36 s |
| 10, the run directory's seal, `make report` | every file `OK`; 4 runs, 4 PASS | 1 s |
| 11, Background Check, `make demo`, back to Passport | `VERDICT PASS: all 10 Targets`; 13 services | 26 s |
| 12, `make stop`, `make start`, then the uninstall | ok; the bench's home was 1.4 GB | 15 s |

**What the two runs changed in the guide:** step 1 now names git and make, which a fresh Ubuntu lacks and which
`make doctor` itself needs (`7b36b6a`); step 3 quotes `MISSING`, the word `make doctor` prints, not `need`
(`41c379c`); and the disk asked for is 8 GB, not 5, in the guide and in `make doctor` (`8b73a49`).

## 5 and 6. Hardware and the Demo Bank

From a bench set up from zero, every hardware run of the earlier stages was made again with the `make` commands
(6 October), and once more as the documentation writes each command, on the release's code (7 October). Each run that
had an earlier counterpart was compared with it, check by check, with the tools of [results.md](results.md): no
difference. The runs first made on 7 October (the Targets of another platform, the Demo Bank in Background Check,
`acme-bank`) stand on their own verdicts.

```bash
make report RUNS="e2e/evidence/20261006T2[23]* hwcheck/evidence/20261006T2[23]*"   # 6 October: 19 runs, 19 PASS
make report RUNS="e2e/evidence/20261007T0* hwcheck/evidence/20261007T0*"           # 7 October: 20 runs, 20 PASS
```

The runs of 6 October are judged again from their files (they were made before runs kept a verdict); those of
7 October kept theirs, the Demo Bank in Background Check and `acme-bank` among them. Every run deleted its VM and
recorded when (`vm-deleted.txt`); `make cloud-check` found both clouds empty after each bank and at the end, when the
Google Cloud project held no instance and no disk of any kind.

## 7. The documentation

Every command in the documentation was run as written, on the release's code, the hardware ones included; the runs
are those of 7 October. Every number in it names the run, the command or the source it comes from. One command was
not run here: `git clone` from GitHub, as the repository did not exist yet; it is run after publishing. The uninstall,
`rm -rf ~/.attestation-bench`, ran in both tests of section 4 on the test's own home.

The proof of concept's own guides ([tacra-poc/](tacra-poc/README.md), `est/readme.md`, `deploy/`) are the TWI SIG's
and describe its own deployment; they were not part of this check.

## What the checks found, and the fixes

Each was found by one of the checks above and fixed before the release:

| Found | Fixed in |
|---|---|
| A run exited 0 whatever happened: `make demo` could report 0 of 10 and succeed, so CI could not catch a regression | `1e819b8`, `52ba142` |
| Evidence for one platform at a Target of another (tacra-est N24) had no `make` command | `e6539c2` |
| `make redirect` left the bench in Background Check, and an interrupted run left it binding no RRP identifier | `545fbfc` |
| A bank made with `make bank-new` got a report naming the Demo Bank and its pack | `022c1bb` |
| The docs gave a hardware run's duration that no run directory could show | `7e4162e` |
| Two steps of the guide: switching back without a restart; an uninstall that ignored `BENCH_HOME` | `f790820` |
| A link out of the repository passed the link check on one machine only | `31be704` |
| `make help` described `redirect`, `test` and `demo` as they were before | `297cf66` |
| The patch procedure of CONTRIBUTING rewrote every patch file even when nothing changed | `fd70fed` |
| `make report` called runs that stopped early "an earlier format" | `046f662` |
| No scan for secrets | `e5f8fc3` |
| The guide, on a fresh machine: git and make; `MISSING`; the disk | `7b36b6a`, `41c379c`, `8b73a49` |
| The known vulnerabilities of the pinned dependencies were not written down | `403913c` |
