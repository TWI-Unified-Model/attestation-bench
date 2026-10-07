# Changelog

What changed, newest first. Dates are UTC.

## Unreleased: the first private release

The bench as a repository of its own, with the TACRA proof of concept's history. Everything below was added on
6 and 7 October 2026 and checked on real hardware: gate 5 (every earlier hardware run repeated from a bench set up
from zero, all identical), gate 6 (the Demo Bank) and gate 7 (every command in the docs run as written, on the
release's code; the hardware runs identical to gate 5's, check by check).

### Added

- **One command per job**: `make doctor`, `setup`, `start`, `stop`, `status`, `config`; `make demo`, `attacks` and
  `redirect` on real hardware, `PLATFORM=gcp-snp|gcp-tdx|aws-snp`;
  `make bank-new`, `bank-up`, `bank-pay`, `bank-audit`, `bank-down`; `make check-mtls`, `trust-check`, `cloud-check`;
  `make report`; `make lint`, `test`, `check`. `make help` lists them.
- **Every run judges itself** (`scripts/verdict.py`): its verdict, `VERDICT PASS` or `VERDICT FAIL`, is kept in the
  sealed run directory, and on FAIL the run, `make` and CI fail. Its tests judge every reference run of 6 October.
  `make report` lists runs, one row each with its verdict, the reference runs included.
- **Refusal scenarios of `make demo`** on hardware, each refused for its own reason: `UNAPPROVED=1` (an SEV-SNP
  launch the bench does not approve: four vCPUs) and `OTHER_PLATFORM=1` (the Targets of another platform's verifier,
  tacra-est N24).
- **Banks of your own**: `make bank-new NAME=…` makes a bank's pack from the Demo Bank's under its own names;
  `BANK=… make bank-up` brings it up.
- **Your own cloud**: hardware runs use the project or account your `gcloud` or `aws` CLI is signed in to
  (`GCP_PROJECT`, `GCP_ZONE`, `AWS_REGION`, `AWS_AZ`), and check it before creating anything.
- **A platform rule** (`trust/platform-policy.json`) that every RRP applies besides the verifier's verdict: on
  SEV-SNP the product line, the minimum TCB from AMD's bulletins (on REPORTED_TCB and COMMITTED_TCB) and SMT only
  with the microcode floor met; on TDX a TD under debug, profiled or migratable is refused. Each `make demo` run keeps
  the rule it ran under (`platform-rule.json`).
- **`hwcheck/cmd/snpreport`**: the launch measurement and the platform fields of the SEV-SNP reports a hardware run
  kept, as go-sev-guest reads them: the MEASUREMENT, the TCBs, the CPUID, the CHIP_ID and the mitigation vectors
  ([docs/results.md](docs/results.md)).
- **The mitigation vectors reach the RRP.** go-gen-ref patch 0002 annotates LAUNCH_MIT_VECTOR and CURRENT_MIT_VECTOR
  of a version 5 report (measurement keys 4032 and 4096, by AMD's CoRIM profile's bit-position rule; the profile names
  none for them), Veraison patch 0006 leaves them out of its reference-value matching, and the platform rule can
  require bits of them (`required_mitigation_bits`, in both vectors) and of PLATFORM_INFO
  (`required_platform_info_bits`). The bench's rule requires PLATFORM_INFO bit 5 (BadRAM, AMD-SB-3015) for Milan and
  Genoa, and none of the mitigation bits yet ([docs/limits.md](docs/limits.md)). `rrpverify service -save-ears DIR`
  keeps the EAR of each honest check.
- **`trust/`**: the approved launches, each with its endorsement and the record of the check, and the vendor roots
  and CoRIM the verifiers trust, each with its source; `make trust-check` compares them with their origins.
- **`packs/` and `scripts/trustzone.py`**: a bank's Targets and policy as data, and one program that writes every
  trust zone's configuration, the bench's and the Demo Bank's alike.
- **Third-party components as pinned upstream commits plus our patches** (`third_party/`), each checked against the
  tree it was tested with.
- **CI** on every push and pull request: `make check`, then the trust zone from zero on Ubuntu 24.04, live, and its
  mutual TLS in Passport and in Background Check. CI runs no protocol: it has no hardware.
- **A secrets scan in `make lint`**: gitleaks over the git history, with `.gitleaks.toml` allowing, by narrow
  patterns and with the reason for each, the things that look like secrets and are not.
- **Documentation**: [README.md](README.md) and [docs/](docs/getting-started.md), with how the release was checked:
  [docs/verification.md](docs/verification.md).

### Changed

- The Demo Bank runs on the bench's configuration: mutual TLS between its components, the verifiers' keys given to
  the gateways as files, the API key in the signed container, pinned and checked tool versions.
- P-256 keys are read and written strictly with the standard library (`rrp/internal/jwk`): full-length coordinates,
  the point on the curve, a private key matching its public key.
- Every run directory is sealed the same way (`sha256sums.txt`) and ends with `== run directory: <path>`.
- The TACRA proof of concept's own guides moved from the repository root to `docs/tacra-poc/`, and later left the
  tree (Removed, below).
- `make redirect` puts the bench back as it was (its RATS model, the RRP identifier in the binding) when it ends,
  fails or is interrupted; it used to leave the bench in Background Check.
- `make test` (and so `make check` and CI) also runs, in each third-party component, the tests our patches add, and
  no others. It checks that each of them ran and that none of their test binaries links a mock; upstream's tests,
  some of them on mocks, are not run ([CONTRIBUTING.md](CONTRIBUTING.md), "Tests").
- **The approved AWS launch rests on AWS's published firmware**, no longer on trust on first use:
  `approved-launches.json` pins the binary of AWS's EC2 SEV-SNP UEFI, release 20260814 (its SHA-256), and how
  `sev-snp-measure` 0.0.13 measures it for a c6a.large; `make trust-check` and the Demo Bank at start download it and
  compute the measurement again (`trust/firmware-check.sh`). `trust/aws-uefi-rebuild.sh` rebuilds that firmware from
  AWS's source as AWS's README says (Nix) and compares: the rebuild is not the published binary, for release 20240809
  either, so the launch is not called reproduced ([trust/README.md](trust/README.md)).

### Fixed

- The approved TDX launches include both of Google's TDX firmware builds; with one, every VM that got the other build
  was refused.
- AWS VLEK reports are checked by the bench's Veraison build, which gives go-sev-guest AMD's roots.
- A run exited 0 whatever happened: `make demo` could print "0 of 10 Targets" and succeed.
- The bench's own modules and scripts used releases with known vulnerabilities, as Dependabot and govulncheck
  reported: `golang.org/x/crypto` v0.17.0 in `platform` and `hwcheck/vlekcheck` (now v0.56.0, as in the other
  modules), grpc v1.79.3 and x/text v0.37.0 in `hwcheck` (now v1.83.2 and v0.41.0), and `cryptography` 42.0.8 for
  the scripts (now 50.0.2).
- A copy to or from a VM that failed once, for a reason of the cloud's, ended the whole run, and its error went
  nowhere. Copies are now tried up to three times, and each failure is written to the run directory.
- Veraison affirmed a debuggable SEV-SNP guest and never checked AMD's intermediate for revocation. Patch 0005 (our
  earlier Veraison commit `6bbeaf9`, ported onto the chain check up to AMD's roots) refuses a guest whose policy
  allows debugging or a migration agent, and checks the intermediate that signed the report's certificate against
  AMD's CRL, fetched once per validity period; the check fails closed. Each check that passes is logged by the
  plugin at INFO; Veraison's trust service records its plugins' INFO lines at debug level, so at the bench's log
  level (info) they are not in `vts.log`, and a run shows the check by the plugin's build in `code-revs.txt`.
- Veraison and the EST server ran releases with known vulnerabilities that their code reaches: grpc, otel and x/text
  in Veraison, chi v4 in the EST server, which no chi v4 release fixes. Patches 0007 move them to fixed releases (chi
  to v5); `govulncheck` now finds no vulnerability reached anywhere in the bench ([docs/limits.md](docs/limits.md)).
- `make setup` left services running the programs and configuration they started with after it rebuilt them.
  `make start` now records what it starts the services with, and `make setup` restarts them when that changed.
- `make setup` kept a Veraison built from older sources after a patch changed them. The deployment now records the
  source trees it was built from, Veraison's and go-gen-ref's, and `make setup` builds it again when either
  changes, keeping its keys, certificates and stores.
- The secrets scan saw only what was committed: a dependency patch of 7 October carried `go.sum` lines that gitleaks
  takes for API keys (a module named `oauth2`), found only after the commit, before it was pushed. `make lint` now
  also scans the changes not yet committed, staged or not, and `.gitleaks.toml` allows `go.sum` lines in our patches
  by their form (a module, its version and a hash), and nothing else in them.
- The bench's RRPs accepted the software stand-in's results whenever the bench ran, hardware runs included:
  `bench.sh` wrote their configuration with `allow_simulated_tee`, and the stand-in's verifier ran beside the real
  ones. No hardware run used that path; the path is gone with the stand-in (the Demo Bank's trust zone never had it).
- A hardware run whose SSH session to the VM broke ended without a verdict
  (`e2e/evidence/20261007T045819Z-gcp-sev-snp-e2e-background-check`). The workload now runs in the VM detached from
  any session (`bench_guest_run`, `scripts/lib.sh`): the bench reads its output and its end with short calls, each
  made again when it fails, and starts it once, even when the call that started it broke after the VM ran it. It is
  tested live: with `BENCH_CHAOS_SSH=1` a real VM breaks the bench's SSH sessions on purpose
  ([docs/troubleshooting.md](docs/troubleshooting.md)). The SEV-SNP hardware checks also keep what the checker
  logged (`rrpverify-*.stderr.log`) and the EAR of each honest check (`ears/`).

### Removed

- **The proof of concept's simulated parts**, as the bench runs nothing that stands in for the real thing: the
  Simulated plug-in (`platform/sim.go`) and its EAT reader, the CAI sidecar, the HTTP client and the PoC's CAAPI
  server with their Docker deployment, the `deploy/` scripts and the `est/` module with their mock CA, the PoC's
  guides, and the CAI's and the plug-in interface's tests, which ran on the Simulated plug-in and on stand-ins for
  the CAAPI and the CA ([CONTRIBUTING.md](CONTRIBUTING.md)). The CAI and the SEV-SNP and TDX plug-ins run in every
  hardware run. `git log` keeps what was removed.
- **The software stand-in TEE** (`platform.SimTEE`) and its verifier (`sim-verifier`), and with them the local mode
  (`PLATFORM=local`, the default until then), the stand-in's refusal scenarios (`SIM_DEBUG`, `SIM_LABEL`) and every
  test built on it: the bench runs nothing that stands in for the hardware. `UNAPPROVED=1 make demo` shows on
  hardware what `SIM_LABEL` showed on the stand-in; no cloud launches a debuggable guest, so no run shows that refusal
  ([docs/limits.md](docs/limits.md)).
- **Tests on stand-ins**, and `gateway.SignTestEAR`, which forged EARs and was compiled into the gateways: the
  gateways' tests on a fake Veraison or a fake Vault, the mutual TLS test on a CA of its own, the plug-ins' tests on a
  fake TSM device and made-up AMD certificates, the TDX verifier's on a fake Intel service. In their place, tests on
  real data and live services: the plug-in reads the reports and certificate tables of real Google Cloud and AWS runs,
  and checks their signatures; the certificate chain is completed on AWS's real table; the identity and group rules
  run on the approved launches; the TDX verifier fetches Intel's real revocation list; `make check-mtls` checks the
  live trust zone. The rule is in [CONTRIBUTING.md](CONTRIBUTING.md), "Tests".
- **The EST server's mock CA** (EST patch 0009). The fork's server made a mock CA at every start, issued its own TLS
  certificate from it when its configuration had no `tls` section, and used it as its CA unless a `tacra` or `attest`
  section replaced it. The bench's server runs only with the TACRA backend: it needs its `tls` and `tacra` sections,
  and refuses `mock_ca`, `attest` and any field it does not know.
- **The tests of our third-party patches on stand-ins.** The EST backend's tests ran on a verifier, RRPs and a CA of
  their own (EST patch 0008). Veraison's revocation tests ran on a snapshot of AMD's CRLs at a stopped clock, its DER
  certificate table was made by re-encoding a PEM one, and its mitigation vectors were made up (Veraison patch 0008).
  go-gen-ref's parser tests built their reports from scratch (go-gen-ref patch 0003). They run now on AMD's CRLs
  fetched from its key server at the time of the test, on real Google Cloud and AWS reports and on the bench's CoRIM.
  The tests on the reference implementation's EST messages moved to a package of their own (EST patch 0010): their
  test binary had held the fork's tests, whose start creates a mock CA. The checks of the EST server's media types
  and Handle encoding through the server went with the removed tests ([docs/limits.md](docs/limits.md)).

## Before: the TACRA proof of concept and the bench's first stages

The TWI SIG's proof of concept (from 12 August 2026), then the bench built on it from 28 September 2026 and rebuilt
and run again on 6 October (stages S1 to S5): the RRP gateways, the TDX verifier, the end-to-end and attack runs on
three platforms, the Demo Bank, mutual TLS between the components, Background Check, the redirection experiment. The
git history has each step; the runs are under `e2e/evidence/` and `hwcheck/evidence/`.
