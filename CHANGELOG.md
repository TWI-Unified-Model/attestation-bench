# Changelog

What changed, newest first. Dates are UTC.

## Unreleased: the first private release

The bench as a repository of its own, with the TACRA proof of concept's history. Everything below was added on
6 and 7 October 2026 and checked on real hardware: gate 5 (every earlier hardware run repeated from a bench set up
from zero, all identical), gate 6 (the Demo Bank) and gate 7 (every command in the docs run as written, on the
release's code; the hardware runs identical to gate 5's, check by check).

### Added

- **One command per job**: `make doctor`, `setup`, `start`, `stop`, `status`, `config`; `make demo`, `attacks` and
  `redirect`, on the software stand-in TEE or with `PLATFORM=gcp-snp|gcp-tdx|aws-snp` on real hardware;
  `make bank-new`, `bank-up`, `bank-pay`, `bank-audit`, `bank-down`; `make check-mtls`, `trust-check`, `cloud-check`;
  `make report`; `make lint`, `test`, `check`. `make help` lists them.
- **Every run judges itself** (`scripts/verdict.py`): its verdict, `VERDICT PASS` or `VERDICT FAIL`, is kept in the
  sealed run directory, and on FAIL the run, `make` and CI fail. Its tests judge every reference run of 6 October.
  `make report` lists runs, one row each with its verdict, the reference runs included.
- **Refusal scenarios of `make demo`**, each refused for its own reason: `SIM_DEBUG=1` (a debuggable instance),
  `SIM_LABEL=…` (an unapproved workload) and `OTHER_PLATFORM=1` (the Targets of another platform's verifier,
  tacra-est N24; also on hardware).
- **Banks of your own**: `make bank-new NAME=…` makes a bank's pack from the Demo Bank's under its own names;
  `BANK=… make bank-up` brings it up.
- **Local mode**: the software stand-in TEE (`platform.SimTEE`) and its verifier (`sim-verifier`), so every flow
  runs on a laptop; RRPs refuse its results unless their configuration allows them.
- **Your own cloud**: hardware runs use the project or account your `gcloud` or `aws` CLI is signed in to
  (`GCP_PROJECT`, `GCP_ZONE`, `AWS_REGION`, `AWS_AZ`), and check it before creating anything.
- **`trust/`**: the approved launches, each with its endorsement and the record of the check, and the vendor roots
  and CoRIM the verifiers trust, each with its source; `make trust-check` compares them with their origins.
- **`packs/` and `scripts/trustzone.py`**: a bank's Targets and policy as data, and one program that writes every
  trust zone's configuration, the bench's and the Demo Bank's alike.
- **Third-party components as pinned upstream commits plus our patches** (`third_party/`), each checked against the
  tree it was tested with.
- **CI** on every push and pull request: `make check`, then the bench from zero on Ubuntu 24.04 and its local runs,
  the refusal scenarios included, in Passport and in Background Check.
- **A secrets scan in `make lint`**: gitleaks over the git history, with `.gitleaks.toml` allowing, by narrow
  patterns and with the reason for each, the three things that look like secrets and are not.
- **Documentation**: [README.md](README.md) and [docs/](docs/getting-started.md), with how the release was checked:
  [docs/verification.md](docs/verification.md).

### Changed

- The Demo Bank runs on the bench's configuration: mutual TLS between its components, the verifiers' keys given to
  the gateways as files, the API key in the signed container, pinned and checked tool versions.
- P-256 keys are read and written strictly with the standard library (`rrp/internal/jwk`): full-length coordinates,
  the point on the curve, a private key matching its public key.
- Every run directory is sealed the same way (`sha256sums.txt`) and ends with `== run directory: <path>`.
- The TACRA proof of concept's own guides moved from the repository root to [docs/tacra-poc/](docs/tacra-poc/README.md).
- `make redirect` puts the bench back as it was (its RATS model, the RRP identifier in the binding) when it ends,
  fails or is interrupted; it used to leave the bench in Background Check.

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

## Before: the TACRA proof of concept and the bench's first stages

The TWI SIG's proof of concept (from 12 August 2026), then the bench built on it from 28 September 2026 and rebuilt
and run again on 6 October (stages S1 to S5): the RRP gateways, the TDX verifier, the end-to-end and attack runs on
three platforms, the Demo Bank, mutual TLS between the components, Background Check, the redirection experiment. The
git history has each step; the runs are under `e2e/evidence/` and `hwcheck/evidence/`.
