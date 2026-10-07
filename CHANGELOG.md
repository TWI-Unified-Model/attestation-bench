# Changelog

What changed, newest first. Dates are UTC.

## Unreleased: the first private release

The bench as a repository of its own, with the TACRA proof of concept's history. Everything below was added on
6 and 7 October 2026 and checked on real hardware: gate 5 (every earlier hardware run repeated from a bench set up
from zero, all identical) and gate 6 (the Demo Bank).

### Added

- **One command per job**: `make doctor`, `setup`, `start`, `stop`, `status`, `config`; `make demo`, `attacks` and
  `redirect`, on the software stand-in TEE or with `PLATFORM=gcp-snp|gcp-tdx|aws-snp` on real hardware;
  `make bank-up`, `bank-pay`, `bank-audit`, `bank-down`; `make check-mtls`, `trust-check`, `cloud-check`; `make lint`,
  `test`, `check`. `make help` lists them.
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
- **CI** on every push and pull request: `make check`, then the bench from zero on Ubuntu 24.04 and its local runs.
- **Documentation**: [README.md](README.md) and [docs/](docs/getting-started.md).

### Changed

- The Demo Bank runs on the bench's configuration: mutual TLS between its components, the verifiers' keys given to
  the gateways as files, the API key in the signed container, pinned and checked tool versions.
- P-256 keys are read and written strictly with the standard library (`rrp/internal/jwk`): full-length coordinates,
  the point on the curve, a private key matching its public key.
- Every run directory is sealed the same way (`sha256sums.txt`) and ends with `== run directory: <path>`.
- The TACRA proof of concept's own guides moved from the repository root to [docs/tacra-poc/](docs/tacra-poc/README.md).

### Fixed

- The approved TDX launches include both of Google's TDX firmware builds; with one, every VM that got the other build
  was refused.
- AWS VLEK reports are checked by the bench's Veraison build, which gives go-sev-guest AMD's roots.

## Before: the TACRA proof of concept and the bench's first stages

The TWI SIG's proof of concept (from 12 August 2026), then the bench built on it from 28 September 2026 and rebuilt
and run again on 6 October (stages S1 to S5): the RRP gateways, the TDX verifier, the end-to-end and attack runs on
three platforms, the Demo Bank, mutual TLS between the components, Background Check, the redirection experiment. The
git history has each step; the runs are under `e2e/evidence/` and `hwcheck/evidence/`.
