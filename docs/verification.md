# Verification of the first release

How this release was checked before it was published, on 6 and 7 October 2026, what each check found, and what
followed publishing (below). Every result names its evidence: a run directory in this repository, a command anyone
can run again, or a commit.

The bench changed after it: nothing in it is simulated any more, and the review's points are closed or written down.
The last section, [v0.1.0: the release for the group](#v010-the-release-for-the-group-7-october-2026), records how
that release was checked. The sections before it are the first release's record; the local mode of section 4 has
gone since.

| # | Gate | Checked | Result |
|---|---|---|---|
| 1 | Build and lint | every Go module; ShellCheck, gofmt, go vet, golangci-lint, ruff, Markdown links, actionlint and gitleaks, each at its pinned version (`make lint`) | clean, on macOS and on a fresh Ubuntu 24.04 |
| 2 | Tests | `go test` in the ten Go modules (fourteen packages have tests) and the 26 Python tests (`make test`) | all pass |
| 3 | Secrets and private material | gitleaks over the whole history; the tracked files searched for keys and for material that must not be here | no secret; what looks like one is explained below |
| 4 | A newcomer's run | [getting-started.md](getting-started.md) alone, on a fresh Ubuntu 24.04 VM and on a Mac with a fresh bench home | every step passed, after three fixes to the guide |
| 5 | Hardware | `make demo`, `attacks` and `redirect` on GCP SEV-SNP, GCP TDX and AWS SEV-SNP | identical to the earlier runs, check by check |
| 6 | The Demo Bank | `bank-up`, the five `bank-pay`, `bank-audit`, `bank-down`, in both RATS models, and a bank of one's own | as expected; both clouds empty afterwards |
| 7 | The documentation | every command in it run as written; every number tied to its evidence | done; `git clone` from GitHub after publishing, and one command that failed as written (below) |

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
`rm -rf ~/.attestation-bench`, ran in both tests of section 4 on the test's own home. One command, in
`trust/README.md`, did not run as written in a plain shell; it was found after publishing (below).

The proof of concept's own guides (then in `docs/tacra-poc/`, `est/readme.md` and `deploy/`) were the TWI SIG's and
described its own deployment; they were not part of this check. They have left the tree since, with the proof of
concept's simulated parts ([../CONTRIBUTING.md](../CONTRIBUTING.md)).

## After publishing

The repository went up on GitHub, private, on 7 October 2026 at `3aaeede`. Then:

| Check | Result |
|---|---|
| CI on GitHub, on every push | both jobs pass. At `3aaeede`: lint and unit tests in 378 s, the bench from zero with its local runs in 522 s; at `43b4505`: 265 s and 520 s |
| Dependabot | its 44 alerts, all on the bench's own pins, closed with `d2c9712`; none open |
| `gh repo clone`, then the hardware runs as the docs write them, at `3aaeede` | every run passed, one at its second try: a copy from a VM had failed once, its error unrecorded (fixed in `7cee226`). These runs were made in a working directory outside the repository and are not kept |
| A review of the published repository | four points to close before any of its numbers go into a draft, and three more; what changed is below |
| `gh repo clone` again, `make setup` from that clone, then every hardware run and the Demo Bank as the docs write them, at `43b4505` | 17 runs, 17 PASS (`make report`): six `make demo`, three `make attacks`, three `make redirect`, and the Demo Bank's three payments and two refusals ([e2e/evidence/20261007T061608Z-demo-bank](../e2e/evidence/20261007T061608Z-demo-bank)). Each run that has a counterpart before is identical to it, check by check; both clouds empty after |

### The review

| Point | What changed |
|---|---|
| Veraison affirmed a debuggable SEV-SNP guest and never checked AMD's intermediate for revocation | patch 0005 (`6e9e98f`): our earlier `6bbeaf9`, ported onto the chain check up to AMD's roots; its tests run in `make test`. The hardware runs on that commit, added in `43b4505`, are identical to gate 7's, check by check |
| The RRPs had no platform policy: no minimum TCB, no rule on the product line | `trust/platform-policy.json` (`4e5e699`), with the source of each value; each `make demo` run keeps the rule it ran under |
| `absent-timestamp` rests on the guest's clock | said in [concepts.md](concepts.md) and [limits.md](limits.md) (`e074285`) |
| The AWS launch is trusted on first use | the approved value is the measurement of AWS's published firmware, which `make trust-check` and the Demo Bank compute again (`trust/firmware-check.sh`); a rebuild from AWS's source does not give that binary (`trust/aws-uefi-rebuild.sh`), so the launch is not called reproduced ([../trust/README.md](../trust/README.md)) |
| The trust zone's keys are files on its disk | said in [limits.md](limits.md), "Keys and secrets"; unchanged on a bench |
| Known vulnerabilities in the pinned dependencies | the bench's own modules on fixed releases (`d2c9712`); Veraison's own pins listed in [limits.md](limits.md), to change with a release that repeats the hardware runs |
| Test coverage | `make test` runs the tests of the packages our third-party patches change (`6e9e98f`); the platform rule is tested on the committed policy file and real results (`4e5e699`) |

Comparing the TCB floors with the hosts' reports found what a floor does not cover: no SEV-SNP host the bench has met
sets the mitigation bit AMD-SB-3034 names for Milan ([limits.md](limits.md), "A TCB floor is not every
mitigation"). `hwcheck/cmd/snpreport` reads the bits from the reports, as go-sev-guest parses them
([results.md](results.md)).

### Found after publishing, and the fixes

| Found | Fixed in |
|---|---|
| `make setup` kept a Veraison built from older sources after a patch changed them | `6e9e98f` |
| CI did not run the tests of our third-party patches | `6e9e98f` |
| `2acbcb7` says a run's `veraison-vts.log` shows each revocation check. It does not: Veraison's trust service records its plugins' lines at debug level, below the bench's log level. At debug the line is there, once per appraisal: replaying the evidence of `20261007T055700Z-gcp-sev-snp` through the deployed service gave ten | the CHANGELOG, corrected with this section |
| A command of `trust/README.md` runs Go in `rrp`, which the repository's `go.work` does not list, and failed as written | `GOWORK=off` in the command, with this section |
| A hardware run that loses its SSH session to the guest stops without a verdict ([e2e/evidence/20261007T045819Z-gcp-sev-snp-e2e-background-check](../e2e/evidence/20261007T045819Z-gcp-sev-snp-e2e-background-check/README.md)) | not fixed: [troubleshooting.md](troubleshooting.md) says how to tell and what to do |

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

## v0.1.0: the release for the group (7 October 2026)

After the review, two plans changed the bench before anyone else is invited to it: nothing in it is simulated any
more, and each point of the review is closed or written down. The release check, R6, then made everything again from
a fresh clone of the GitHub repository.

### What changed

| Step | What | Commits |
|---|---|---|
| N1 | the proof of concept's simulated stack out of the tree | `15a58e0` |
| N2 | no stand-in TEE: the protocol runs on real hardware only; the local mode of section 4 is gone | `355156d`, `de93417`; runs `bc894a6` |
| N3 | the Go tests on real data and live services only; the EAR forger out of the gateways | `475cdf4` |
| N4 | the tests of our third-party patches on real data and live services; the EST server without a mock CA | `220e75c`; runs `936729a` |
| N6 | the verdict tests judge real runs only | `7755d18` |
| N7 | the EST library without the proof of concept's mock TEE; no program the bench builds links a mock; `make test-live` | `43189d1`, `e1bcdcf`; runs `11795fc` |
| R1 | AMD's mitigation vectors reach the RRP, and the platform rule requires the bits AMD's bulletins name; the bench admits Milan hosts without bit 4 under a named waiver, a bank's rule does not; every attack run checks the rule on the Attestation Results it got | `c516408`, `98a0ed3`, `be0a45f` |
| R2 | the AWS launch rests on AWS's published firmware, measured again; a rebuild from AWS's source does not give that binary | `692dbd7` |
| R3 | the guest's clock in every hardware run; absent-timestamp Evidence made with the clock ahead, accepted older than `max_age` | `794ea61`, `124eb90`, `8da994c`; runs `dee791f` |
| R4 | no known vulnerability reached in the pinned dependencies | `076a595` |
| R5 | hardware runs survive a broken SSH session, tested on a VM that breaks them on purpose | `3e073d6`, `033c88f`, `c973f3a`, `e5d2d88`; runs `03d3f51` |

Not in this release: a debuggable SEV-SNP guest refused live (no cloud the bench uses launches one; it needs a
bare-metal AMD server), and the trust zone's keys in a KMS or HSM ([limits.md](limits.md)).

### R6: everything again, from a fresh clone

`git clone` of the repository at `dee791f` into an empty directory, with a bench home of its own (`BENCH_HOME`); the
machine's own bench was stopped, as the ports are fixed.

| Step | Result |
|---|---|
| `make doctor` | `Ready for make setup`; its line "not needed locally", left from the local mode, was reworded (`ebcc810`) |
| `make setup` | ok, 10/10, in about 3 minutes (Go's caches were on this machine) |
| `make check` | clean: every linter; the tests of every Go module and of our third-party patches; the Python tests; 38 programs built, none links a mock |
| `make check-mtls` and `make test-live`, in Passport and in Background Check | 40 of 40 checks in each model ([Passport](../e2e/evidence/20261007T172815Z-bench-mtls-passport), [Background Check](../e2e/evidence/20261007T172900Z-bench-mtls-background-check)); the EST wire format as expected, and the 26 committed attack runs appraised again by the live verifiers, 1300 checks, in each |

Then the hardware, every run into the clone. Before the attacks, the platform rule's checks of attack runs were
added (`be0a45f`, the reviewer's "limits that became refusals"); the clone took that commit (`git pull`, then
`make setup`, which restarted what changed). Phases A and B ran at `dee791f`: the commits after it change nothing a
demo runs, as the gateways' platform package only gains two functions they do not call (`git diff dee791f be0a45f`).

| Phase | Commit | Runs | Result |
|---|---|---|---|
| A, Background Check | `dee791f` | `make demo` on the three platforms; `OTHER_PLATFORM=1` on GCP TDX | 4 PASS; the SEV-SNP verdicts name the waiver of Milan's bit 4 |
| B, Passport | `dee791f` | `make demo` on the three platforms; `UNAPPROVED=1` on GCP and AWS SEV-SNP; `OTHER_PLATFORM=1` on the three | 8 PASS |
| C, attacks | `be0a45f` | `make attacks` on the three platforms | 3 PASS: 262, 262 and 162 checks, the platform rule's 50, 50 and 30 among them; absent-timestamp Evidence accepted 296, 293 and 291 s old with `max_age` 120 s, reported as an exposure |
| D, redirect | `be0a45f` | `make redirect` on the three platforms | 3 PASS: with the RRP identifier `ca2` refused all five Freshness Kinds; without it, all but present-nonce |
| E, the Demo Bank | `be0a45f` | `bank-up`; `bank-pay` gcp-tdx, gcp-snp, aws-snp, ordinary, unapproved; `bank-audit`; `bank-down` | 5 PASS: the TDX payment went through; the bank refused GCP and AWS SEV-SNP for bit 4 (LAUNCH_MIT_VECTOR 0xb and 0xfef); the ordinary VM and the unapproved launch got no credential ([the bank's run](../e2e/evidence/20261007T183914Z-demo-bank)) |

```bash
make report RUNS="e2e/evidence/20261007T17* e2e/evidence/20261007T18* hwcheck/evidence/20261007T18*"   # 25 runs, 25 PASS
```

Each run was compared, check by check, with the run of its kind before it, and keeps the comparison
(`compare-with-<run>.txt`): 20 runs, no difference. The demos and the redirect runs were compared with runs made
before the platform rule required AMD's mitigation bits (`98a0ed3`): the outcomes are the same, but the SEV-SNP hosts
were admitted then without the waiver, which the rule did not need yet; in the release's runs they are admitted
under it, and each verdict names it. The platform rule's checks of attack runs are new, with nothing
before them to compare; [platform-check's test](../rrp/cmd/platform-check/main_test.go) gives them again from each
run's own files, field by field. The Demo Bank's SEV-SNP payments, which went through before R1 (on 6 October and on the morning of
7 October), are refused now, as R1 intends. Every run deleted its VMs and recorded when; `make cloud-check` found both clouds empty at the end.

Found by the check and fixed before the release: a Demo Bank payment refused by the platform rule had an empty line
after its `VERDICT` line, from the gateway's error (`scripts/verdict.py`; its runs keep the verdict as written, and
the tests judge them again). Once, CI's job that sets the trust zone up from zero waited 40 minutes on Ubuntu's
packages, before any of the bench's steps; run again, the step took 23 s.

The tag `v0.1.0` is set on the release's commit once CI has passed on it.

### v0.1.1: the first page from the release's runs

A review of v0.1.0 found its first page older than its mechanism: README's Status table showed the runs before the
platform rule required AMD's mitigation bits, with SEV-SNP demos "under the platform rule" and no waiver, the Demo
Bank's three payments and acme-bank's SEV-SNP payment going through; the Quick start, the guide's outputs, the
example verdict of [attacks.md](attacks.md) and the platform pages were as old. They now quote the release check's
runs. Two rows had no run under the rule, and were run again at v0.1.0 (`6e77624`):

| Run | Result |
|---|---|
| the Demo Bank in Background Check, `RATS_MODEL=background-check make bank-up`, the five `bank-pay`, `bank-audit`, `bank-down` | the same five verdicts as in Passport: the TDX payment went through; GCP and AWS SEV-SNP refused for bit 4 (LAUNCH_MIT_VECTOR 0xb and 0xfef); the ordinary VM and the unapproved launch got no credential ([run](../e2e/evidence/20261007T193224Z-demo-bank)) |
| a bank of one's own, `make bank-new NAME=acme-bank`, then `bank-up`, `bank-pay` gcp-tdx and gcp-snp, `bank-audit`, `bank-down` | the ledger admitted `payments.workload.acme-bank.example` from TDX; GCP SEV-SNP refused for bit 4; `make bank-new` made the same pack, byte for byte, as before the rule ([run](../e2e/evidence/20261007T195519Z-acme-bank)) |

```bash
make report RUNS="e2e/evidence/20261007T17* e2e/evidence/20261007T18* e2e/evidence/20261007T19* hwcheck/evidence/20261007T18*"   # 32 runs, 32 PASS
```

The verdict tests judge these payments too. `make test-live` at v0.1.0: the EST wire format as expected, and the 29
committed attack runs appraised again by the live verifiers, 1450 checks. Both clouds were empty after each bank. The
tag `v0.1.1` is set once CI has passed on its commit.

## The redirection's variants (8 October 2026)

The redirection experiment answers TACRA #20 with two things fixed: its two Credential Authorities share one epoch
marker, and the conduit offers Evidence made for `ca1`. Two variants change each (`c0f02ac`), and a third runs the
experiment on the Secret Vaults, which it left out (`1a751f6`: a second Vault in the bench's pack,
`rrp-issue retrieve`); [attacks.md](attacks.md), section 2. The verdict checks each refusal's reason in them. One run
of each came first, on GCP SEV-SNP in Background Check; the others followed, one at a time, each checked for VMs left
behind.

| Runs | Commit | Result |
|---|---|---|
| `REDIRECT_VARIANT=own-epochs make redirect` on the three platforms, Background Check and Passport | `c0f02ac` | 6 PASS, 20 of 20 each: without the RRP identifier `ca2` issued for absent-timestamp and absent-none alone, refusing present-nonce for the Handle and the two epoch kinds for its epoch marker; with it, all five refused |
| `REDIRECT_VARIANT=start-ca2 make redirect`, the same | `c0f02ac` | 6 PASS, 20 of 20 each: without the identifier `ca2` issued for every kind but absent-epoch, present-nonce included; with it, all five refused, its own Handles for the binding |
| `REDIRECT_VARIANT=vault make redirect`, the same | `1a751f6` | 6 PASS, 20 of 20 each: without the identifier `vault2` released the workload's group's key for every kind but present-nonce, each container sealed to the Attester's CEKpub and naming `vault2`; with it, all five refused |

```bash
make report RUNS="hwcheck/evidence/20261008T03* hwcheck/evidence/20261008T04*"   # 18 runs, 18 PASS
```

`make check` at `c0f02ac`: every linter clean, 52 Python tests; with the runs committed, 59, the verdict and report
tests judging the twelve runs and copies of them changed in one place; with the Vault's runs, 60. The 27 earlier
redirect runs are judged as before. Before its runs, the bench with the second Vault passed `make check-mtls`, 40 of
40, locally. `make cloud-check` found both clouds empty at the end of each batch.

## The attest-* wire as proposed for the EST draft (8 October 2026; merged on 10 October)

Merged into the draft's master on 10 October 2026 (`4fa3883`), after Mark Novak's review of that day: three remarks, on the
media-type table and the processing steps, all answered in the text. The wire format proposed for draft-novak-lamps-tacra-est (`f3cc899`): a media type for each message type, no `rrp_id`
in the attest-initiate response, no `endorsements` in the requests, and the messages in CDDL
([../e2e/est-attest.cddl](../e2e/est-attest.cddl)). The EST server (patch 0014) refuses, saying why, any request that
is not what the CDDL defines. Before any code, the CDDL took the 360 messages of the 18 hardware runs of 7 and 8
October that kept a wire log, once `rrp_id` and `required_bindings` were taken out, and refused each of 50 alterations
that break a rule of it. Two faults of the bench came out on the way, each fixed in a commit of its own: a demo run
whose SSH reverse tunnel did not come up still ran and blamed the Targets (`6bf2b37`), and the pre-play stopped at a
Vault Target with two credential groups (`dae1fb0`; [the run that found it](../hwcheck/evidence/20261008T135750Z-gcp-sev-snp)).

| Check | Commit | Result |
|---|---|---|
| `make check` | `dae1fb0` | every linter clean; the EST patches' tests 12 (9 before), in 7 files, each of eight checks of patch 0014 failing one when turned off; 60 Python tests, and with these runs and their tests 63 |
| `make check-mtls`, `make test-live` | `6bf2b37` | 40 of 40; the EST wire format: 21 checks as expected (the attest-initiate response's type and members; 415 with Accept for `application/json`, `text/plain` and the other resource's type; 400 for `endorsements`, a request twice, a member twice, standard base64; the Handle unused by any of them); 33 committed runs appraised again, 1650 checks |
| `make demo` on the three platforms, Passport and Background Check | `6bf2b37` | 6 PASS, 10 of 10 Targets each |
| `e2e/scripts/est-wire-cddl.py` on the six demos' wire logs | `6bf2b37` | 120 messages valid, 180 of 180 with the media type of their place (the Vault's containers as `application/est-attest-bundle+json`), 84 altered messages refused |
| `make attacks` on the three platforms | `dae1fb0` | 3 PASS: 262, 262 and 162 checks; the pre-play's 72 messages, taken from the EST server's wire log (an attack run keeps none of its own), valid against the CDDL with their media types |
| `make test-live` with the new runs | `dae1fb0` | the EST wire format as expected; 37 committed runs appraised again, 1850 checks |

`make cloud-check` found both clouds empty at the end of each batch.

### After the check against what was asked (`bee2ae9`)

The wire was then checked against what the group asked in the review of the EST draft's pull request #1 and in TACRA
#17, #19 and #20. `credential_type` is now optional in both requests, as in the draft's Retrieval request and the
group's fork: whether it travels at all is #19. The check also found two faults of the server, both fixed in
`bee2ae9`. It correlated a request's Handle before its Evidence format, so a request refused for the format (415) used
up a present-nonce Handle, against the draft's order: syntax, media type and size limits first, then the Handle
(`TestFormatRefusalLeavesTheHandle` fails under the old order). And nothing tested its 502 and 503: `TestUnreachable`
gets each from a local port nothing listens on.

| Check | Commit | Result |
|---|---|---|
| `make check` | `bee2ae9`, with these runs | every linter clean, gitleaks over 274 commits and the changes not yet committed; the EST patches' tests 14 (12 before), in 8 files; 63 Python tests |
| `make demo` on the three platforms, Passport and Background Check | `bee2ae9` | 6 PASS, 10 of 10 Targets each |
| `e2e/scripts/est-wire-cddl.py` on the six demos' wire logs | `bee2ae9` | 120 messages valid, 180 of 180 with the media type of their place, 84 altered messages refused |
| `make attacks` on the three platforms | `bee2ae9` | 3 PASS: 262, 262 and 162 checks; the pre-play's 72 messages valid against the CDDL, 132 of 132 media types as their place's, 60 altered messages refused |
| `make test-live` with the new runs | `bee2ae9` | the EST wire format: 25 checks as expected, the 415 for Evidence of a format not accepted among them, after which the same Handle reaches the RRP; 40 runs appraised again, 2000 checks |

`make cloud-check` found both clouds empty at the end of each batch.

## No RRP identifier, the default (11 October 2026)

The group decided on 6 October to leave the RRP identifier out of the binding until the threat model is agreed
(TheBankster/rats-tacra#20; Mark Novak in TWI-Unified-Model/globalsign-est#4, 11 October). The code follows: the EST server
of the group's code computes the binding with an empty identifier field and carries no server_id (the transfer branch's
`7e4224c`; EST patch 0017 here), and this bench binds none by default ([rrp-identifier.md](rrp-identifier.md), section 8).
Run the same day, each with its EST source recorded (`code-revs.txt`, `veraison-revs.txt` or `est-source.txt`). These runs
bound the layout of that morning, four fields with an empty identifier (`7e4224c`); the three-field layout Mark asked for at
14:31Z (`b531556`, patch 0018) is the next section's.

**The group's tree, `7e4224c`, in the trust zone.**

| run | kind | outcome | |
|---|---|---|---|
| `20261011T132003Z-gcp-sev-snp-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T132003Z-gcp-sev-snp-e2e-passport) |
| `20261011T132258Z-aws-sev-snp-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T132258Z-aws-sev-snp-e2e-passport) |
| `20261011T132505Z-gcp-tdx-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T132505Z-gcp-tdx-e2e-passport) |
| `20261011T132808Z-gcp-sev-snp-e2e-background-check` | demo, Background Check | 10 of 10 Targets | [run](../e2e/evidence/20261011T132808Z-gcp-sev-snp-e2e-background-check) |
| `20261011T133105Z-aws-sev-snp-e2e-background-check` | demo, Background Check | 10 of 10 Targets | [run](../e2e/evidence/20261011T133105Z-aws-sev-snp-e2e-background-check) |
| `20261011T133326Z-gcp-tdx-e2e-background-check` | demo, Background Check | 10 of 10 Targets | [run](../e2e/evidence/20261011T133326Z-gcp-tdx-e2e-background-check) |
| `20261011T133625Z-gcp-sev-snp` | attacks | 232 checks | [run](../hwcheck/evidence/20261011T133625Z-gcp-sev-snp) |
| `20261011T134703Z-aws-sev-snp` | attacks | 232 checks | [run](../hwcheck/evidence/20261011T134703Z-aws-sev-snp) |
| `20261011T135526Z-gcp-tdx` | attacks | 142 checks | [run](../hwcheck/evidence/20261011T135526Z-gcp-tdx) |

The attack suites count 232 and 142 checks, not 262 and 162: the "other RRP identifier" substitution is left out when no
identifier is bound, as it would be the honest case again (docs/attacks.md, section 8).

**The bench's own tree, patch 0017 (tree `3b2cb1f71b2a`, the tested tree).**

| run | kind | outcome | |
|---|---|---|---|
| `20261011T140418Z-gcp-sev-snp-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T140418Z-gcp-sev-snp-e2e-passport) |
| `20261011T140722Z-aws-sev-snp-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T140722Z-aws-sev-snp-e2e-passport) |
| `20261011T140930Z-gcp-tdx-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T140930Z-gcp-tdx-e2e-passport) |

`make cloud-check` found both clouds empty at the end. Log: the bench's working notes, `tm-logs/drop-ids-verify-20261011.txt`.

## The identifiers ripped out (11 October 2026, evening)

At 14:31Z Mark Novak asked, in TWI-Unified-Model/globalsign-est#4, to rip the RRP identifier and the EST Server's identifier out
altogether: the binding is three length-prefixed fields, the freshness element, the Target and the subject, in the group's EST
server (the transfer branch's `b531556`; EST patch 0018 here) and in every component of this bench
([rrp-identifier.md](rrp-identifier.md), section 8). Run the same evening, each with its EST source recorded; every attack run's
cases record the layout (`binding_layout`), and the present-nonce Enrollment of the first attack run is the hardware vector of
the three-field binding (`platform/testvector_test.go`; the transfer branch's test). `make check` holds every run.

**The group's tree, `b531556`, in the trust zone binding the same three fields.**

| run | kind | outcome | |
|---|---|---|---|
| `20261011T150339Z-gcp-sev-snp-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T150339Z-gcp-sev-snp-e2e-passport) |
| `20261011T150637Z-aws-sev-snp-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T150637Z-aws-sev-snp-e2e-passport) |
| `20261011T150841Z-gcp-tdx-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T150841Z-gcp-tdx-e2e-passport) |
| `20261011T151137Z-gcp-sev-snp-e2e-background-check` | demo, Background Check | 10 of 10 Targets | [run](../e2e/evidence/20261011T151137Z-gcp-sev-snp-e2e-background-check) |
| `20261011T161559Z-aws-sev-snp-e2e-background-check` | demo, Background Check | 10 of 10 Targets | [run](../e2e/evidence/20261011T161559Z-aws-sev-snp-e2e-background-check) |
| `20261011T151633Z-gcp-tdx-e2e-background-check` | demo, Background Check | 10 of 10 Targets | [run](../e2e/evidence/20261011T151633Z-gcp-tdx-e2e-background-check) |
| `20261011T151929Z-gcp-sev-snp` | attacks | 232 checks, every attack refused for its own reason | [run](../hwcheck/evidence/20261011T151929Z-gcp-sev-snp) |
| `20261011T153014Z-aws-sev-snp` | attacks | 232 checks, every attack refused for its own reason | [run](../hwcheck/evidence/20261011T153014Z-aws-sev-snp) |
| `20261011T153829Z-gcp-tdx` | attacks | 142 checks, every attack refused for its own reason | [run](../hwcheck/evidence/20261011T153829Z-gcp-tdx) |

The AWS Background Check run of 15:14Z, `20261011T151431Z-aws-sev-snp-e2e-background-check`, is kept with its README: a host's
fault, the guest could not read the report's certificate table (`auxblob: invalid argument`) on that instance, every Target
failed before the protocol began; the run of 16:15Z above, on a fresh instance, is the one of the matrix.

**The bench's own tree, patch 0018 (tree `09762d19ebc6`, the tested tree).**

| run | kind | outcome | |
|---|---|---|---|
| `20261011T154708Z-gcp-sev-snp-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T154708Z-gcp-sev-snp-e2e-passport) |
| `20261011T155003Z-aws-sev-snp-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T155003Z-aws-sev-snp-e2e-passport) |
| `20261011T155209Z-gcp-tdx-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T155209Z-gcp-tdx-e2e-passport) |

**The conduit's redirect drill** (`CONDUIT_ATTACK=redirect`; [attacks.md](attacks.md), section 6): the EST server routed every
request to the second Credential Authority and the second Secret Vault, the RRPs the Attester did not ask for.

| run | regime | outcome | |
|---|---|---|---|
| `20261011T155450Z-gcp-sev-snp-e2e-passport-conduit-redirect` | Passport; the copies sharing the first RRPs’ PKI and keys | 5 Enrollments admitted (issued under the shared PKI); 5 Retrievals admitted (sealed under the first Vault’s keys) | [run](../e2e/evidence/20261011T155450Z-gcp-sev-snp-e2e-passport-conduit-redirect) |
| `20261011T155756Z-aws-sev-snp-e2e-passport-conduit-redirect` | Passport; the copies sharing the first RRPs’ PKI and keys | 5 Enrollments admitted (issued under the shared PKI); 5 Retrievals admitted (sealed under the first Vault’s keys) | [run](../e2e/evidence/20261011T155756Z-aws-sev-snp-e2e-passport-conduit-redirect) |
| `20261011T160001Z-gcp-tdx-e2e-passport-conduit-redirect` | Passport; the copies sharing the first RRPs’ PKI and keys | 5 Enrollments admitted (issued under the shared PKI); 5 Retrievals admitted (sealed under the first Vault’s keys) | [run](../e2e/evidence/20261011T160001Z-gcp-tdx-e2e-passport-conduit-redirect) |
| `20261011T160255Z-gcp-sev-snp-e2e-background-check-conduit-redirect` | Background Check; the copies sharing the first RRPs’ PKI and keys | 5 Enrollments admitted (issued under the shared PKI); 5 Retrievals admitted (sealed under the first Vault’s keys) | [run](../e2e/evidence/20261011T160255Z-gcp-sev-snp-e2e-background-check-conduit-redirect) |
| `20261011T160608Z-gcp-sev-snp-e2e-passport-conduit-redirect-own-keys` | Passport; the second Vault with keys of its own | 5 Enrollments admitted (issued under the shared PKI); 5 Retrievals refused by the CAI for their origin | [run](../e2e/evidence/20261011T160608Z-gcp-sev-snp-e2e-passport-conduit-redirect-own-keys) |
| `20261011T160900Z-aws-sev-snp-e2e-passport-conduit-redirect-own-keys` | Passport; the second Vault with keys of its own | 5 Enrollments admitted (issued under the shared PKI); 5 Retrievals refused by the CAI for their origin | [run](../e2e/evidence/20261011T160900Z-aws-sev-snp-e2e-passport-conduit-redirect-own-keys) |
| `20261011T161104Z-gcp-tdx-e2e-passport-conduit-redirect-own-keys` | Passport; the second Vault with keys of its own | 5 Enrollments admitted (issued under the shared PKI); 5 Retrievals refused by the CAI for their origin | [run](../e2e/evidence/20261011T161104Z-gcp-tdx-e2e-passport-conduit-redirect-own-keys) |

What the drill measures: without an identifier in the binding, a credential from an RRP the Attester did not ask for is
admitted when that RRP issues under the PKI, or seals under the keys, the Attester already trusts; a certificate names its
issuer, not the RRP that asked for it. The Attester's pin is its trust anchors and the Target's name, which is what the threat
model's 3.3 and the text proposed for 4.5 and the Security Considerations on 8 October say.

`make cloud-check` found both clouds empty at the end. Logs: the bench's working notes, `tm-logs/ripout-verify-20261011.txt`
and `ripout-verify-20261011-rerun-aws-bc.txt`.

## The prototype, run again on three platforms (25 October 2026)

Before answering a question from the group on the end-to-end prototype, the bench ran the whole path again from this tree
(`750d5abf`; the group's EST server at `623c197`), the trust zone already set up: `make check-mtls`, 40 of 40;
`make test-live`, the EST wire format as expected.

| run | kind | outcome | |
|---|---|---|---|
| `20261025T225030Z-gcp-tdx-e2e-passport` | demo, Passport, Google Cloud TDX | 10 of 10 Targets | [run](../e2e/evidence/20261025T225030Z-gcp-tdx-e2e-passport) |
| `20261025T225259Z-aws-sev-snp-e2e-passport` | demo, Passport, AWS SEV-SNP | 10 of 10 Targets | [run](../e2e/evidence/20261025T225259Z-aws-sev-snp-e2e-passport) |
| `20261025T223843Z-gcp-sev-snp-e2e-passport` | demo, Passport, Google Cloud SEV-SNP | 0 of 10: every Target refused, `SEVSNP is "contraindicated"` | [run](../e2e/evidence/20261025T223843Z-gcp-sev-snp-e2e-passport) |
| `20261025T224154Z-gcp-sev-snp-e2e-background-check` | demo, Background Check, Google Cloud SEV-SNP | 0 of 10, the same refusal | [run](../e2e/evidence/20261025T224154Z-gcp-sev-snp-e2e-background-check) |
| `20261025T224459Z-gcp-sev-snp` | attacks, Google Cloud SEV-SNP | the offline verifiers as on 22 October (142, 142; the fork's 50 reported, not judged); the service verifier refused all 40 | [run](../hwcheck/evidence/20261025T224459Z-gcp-sev-snp) |

**Why Google Cloud SEV-SNP refused.** The guest's launch measurement had changed: `ccdc5cf0…26fa` on 22 October,
`e79ebb5b…984d` on 25 October, on the same chip (`1d1f823a…`), with the same guest policy (`0x30000`) and platform info
(`0x25`): Google had moved the host to another UEFI build. The Verifier knew the approved launches only and refused the one
it did not know, as it must (`docs/attacks.md`, "Unapproved launch"). Google's signed endorsement of the new measurement
verifies to the pinned root (`GCE-uefi-signer`, SVN 2, built 2026-08-28;
[`refvals/`](../hwcheck/evidence/20261025T224459Z-gcp-sev-snp/refvals/)), so the launch was approved as
[`trust/README.md`](../trust/README.md) says: an entry in `approved-launches.json`, a new `veraison-corim-milan.cbor` with
three launches, `make trust-check` passing. The earlier Google launch stays approved: Google runs both builds.

**A second refusal, the bench's own.** The new CoRIM was first submitted to Veraison's existing store, which then held two
trust anchors for the same ARK. The scheme requires exactly one (`expected exactly 1 trust anchor; found 2`) and answered
every session with HTTP 500: `20261025T230344Z-gcp-sev-snp-e2e-passport`, `20261025T230657Z-gcp-sev-snp-e2e-background-check`
(0 of 10 each) and `20261025T231000Z-gcp-sev-snp` (the service verifier's 40 not as expected). The store was recreated and the
CoRIM submitted once: one trust anchor, three reference values. `trust/README.md`, "Approving a new launch", now carries that
step.

| run | kind | outcome | |
|---|---|---|---|
| `20261025T232331Z-gcp-sev-snp-e2e-passport` | demo, Passport, Google Cloud SEV-SNP | 10 of 10 Targets | [run](../e2e/evidence/20261025T232331Z-gcp-sev-snp-e2e-passport) |
| `20261025T232650Z-gcp-sev-snp-e2e-background-check` | demo, Background Check, Google Cloud SEV-SNP | 10 of 10 Targets | [run](../e2e/evidence/20261025T232650Z-gcp-sev-snp-e2e-background-check) |
| `20261025T232947Z-gcp-sev-snp` | attacks, Google Cloud SEV-SNP | 232 checks: the honest Evidence passed, every attack refused for its own reason; the service verifier's 40 as expected | [run](../hwcheck/evidence/20261025T232947Z-gcp-sev-snp) |

`make test-live` afterwards: the EST wire format as expected, and the 57 committed runs appraised again, 2,690 checks as
expected, the run of the new launch among them. `make cloud-check` found both clouds empty after each stage.

## The text of the draft matches the code (22 October 2026)

On 22 October Mark Novak merged pull requests #23 (Trust Model) and #24 (Freshness) into TheBankster/rats-tacra (master `c2c378e`).
With #24, Section 4.5 binds three values, the freshness element, the Target and the subject, each with a 32-bit big-endian length
prefix, under SHA-512: the binding the group's EST server has computed since 11 October (`internal/tacra/binding.go` at `623c197`,
the bench's `third_party/globalsign-est`, tested tree `86de667a4abf`). To record that the text and the code now agree, the bench ran
on Google Cloud SEV-SNP from this tree (`c4b34ddb`), the trust zone set up from zero (`make setup`, `make check-mtls`: 40 of 40):

| run | kind | outcome | |
|---|---|---|---|
| `20261022T222734Z-gcp-sev-snp-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261022T222734Z-gcp-sev-snp-e2e-passport) |
| `20261022T223108Z-gcp-sev-snp` | attacks, GCP SEV-SNP | 232 checks, the honest Evidence passed, every attack refused for its own reason; the service verifier's 40: 10 honest passed, three substitutions refused 10 each (no identifier left to substitute) | [run](../hwcheck/evidence/20261022T223108Z-gcp-sev-snp) |
| `20261022T224242Z-gcp-sev-snp-e2e-background-check` | demo, Background Check | 10 of 10 Targets | [run](../e2e/evidence/20261022T224242Z-gcp-sev-snp-e2e-background-check) |

Each run's record names the code (`code-revs.txt`, `code-rev.txt`) and the VM's deletion (`vm-deleted.txt`); `make cloud-check` found
both clouds empty before and after. The outcomes are those of 11 October on the same code: what changed on 22 October is the text.
Logs: `tm-logs/text-equals-code-*.log` (not committed).

## The bench on the group's master of 13 October (`623c197`)

Mark Novak merged our pull request #6 at 06:43Z on 13 October (`623c197`; #5 on 12 October). `third_party/globalsign-est` pins
that master with one patch, 0001 (regenerated: #6 re-indented one line of the sample configuration the patch replaces); patch 0002
is retired, since the group's mock now carries #5 and #6 and `make check` holds the bench's rule without it ("no program the
bench builds links a mock": the EST tree's 2 programs). Tested tree `86de667a`. `make check`: every linter clean; our 18 tests in
9 files of the EST tree; 79 Python tests. The wire, the binding and the backend are those of `6f80871`, so the runs of 11 October
below are the runs of this tree too.

## The bench on the group's master (11 October 2026, late evening)

Mark Novak merged pull request #4 at 18:49Z (`6f80871`, a merge commit of its 22 commits). Since `8a000861` the bench's
`third_party/globalsign-est` pins that master, with two patches, the bench's rules the group's server does not need (no mock CA,
the TACRA backend alone and a strict configuration; the mock TEE and mock attested CA out of the tree): tree `bfd8d3aa3ec6`, the
tested tree. The series of 18 patches the sections above name is retired; the bench at `9d3e74b3` reproduces it.

`make check` at `8a000861`: every linter clean; our tests in the EST tree 18, in 9 files (the test files the patches add and
those of `cmd/estserver`, `internal/refvectors` and `internal/tacra`, ours, merged upstream); 78 Python tests. `make test-live`
in Passport and in Background Check: the wire format as expected; the 52 committed runs appraised again by the live verifiers,
2490 checks as expected (the bench's working notes, `tm-logs/g3-test-live-passport-20261011.txt` and `g3-test-live-bc-20261011.txt`).
Then, from `8a000861`, with the EST server built from that tree:

| run | kind | outcome | |
|---|---|---|---|
| `20261011T191449Z-gcp-sev-snp-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T191449Z-gcp-sev-snp-e2e-passport) |
| `20261011T191754Z-aws-sev-snp-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T191754Z-aws-sev-snp-e2e-passport) |
| `20261011T191952Z-gcp-tdx-e2e-passport` | demo, Passport | 10 of 10 Targets | [run](../e2e/evidence/20261011T191952Z-gcp-tdx-e2e-passport) |
| `20261011T192237Z-gcp-sev-snp-e2e-background-check` | demo, Background Check | 10 of 10 Targets | [run](../e2e/evidence/20261011T192237Z-gcp-sev-snp-e2e-background-check) |
| `20261011T192535Z-aws-sev-snp-e2e-background-check` | demo, Background Check | 10 of 10 Targets | [run](../e2e/evidence/20261011T192535Z-aws-sev-snp-e2e-background-check) |
| `20261011T192727Z-gcp-tdx-e2e-background-check` | demo, Background Check | 10 of 10 Targets | [run](../e2e/evidence/20261011T192727Z-gcp-tdx-e2e-background-check) |
| `20261011T193017Z-gcp-sev-snp` | attacks, GCP SEV-SNP | 232 checks, every attack refused for its own reason | [run](../hwcheck/evidence/20261011T193017Z-gcp-sev-snp) |
| `20261011T194051Z-aws-sev-snp` | attacks, AWS SEV-SNP | 232 checks, every attack refused for its own reason | [run](../hwcheck/evidence/20261011T194051Z-aws-sev-snp) |
| `20261011T194919Z-gcp-tdx` | attacks, GCP TDX | 142 checks, every attack refused for its own reason | [run](../hwcheck/evidence/20261011T194919Z-gcp-tdx) |

Each run's record names what it ran: `estserver built from …/third_party/globalsign-est/src`, commit `6f80871`; the demos'
`code-revs.txt` adds `globalsign-est/src upstream 6f8087199539 + 2 patch(es), tree bfd8d3aa3ec6: tested tree`. The outcomes are
those of the runs of the afternoon on the same backend (above): the group's master and the bench's tree of the afternoon differ
only in the mock the bench leaves out and in two tests. `make cloud-check` found both clouds empty at the end. Log:
`tm-logs/g3-verify-20261011.txt`.
