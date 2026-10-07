# FAQ

**Do I need a cloud account?**
No, not for the local bench: `make setup`, `demo`, `attacks`, `redirect` and `check-mtls` run on your machine with the
software stand-in TEE. You need Google Cloud for hardware runs on `gcp-snp` and `gcp-tdx` and for the Demo Bank, and
AWS for `aws-snp`.

**Is the local mode secure?**
No. The stand-in TEE signs its reports with a key in a file and isolates nothing. It exists so that every flow and
every check can run anywhere, and the gateways accept it only because the local bench's configuration allows it
([concepts.md](concepts.md), the software stand-in TEE).

**What does a hardware run cost?**
One small VM for a few minutes: between 118 and 395 seconds in the reference runs of 6 October 2026, at the cloud's
price for that machine ([hardware/](hardware/README.md)). The Demo Bank keeps two VMs for as long as it is up.

**Can a run leave something running in my cloud?**
Every run deletes what it created and checks; if a run is interrupted, `make cloud-check` lists what is left.

**Where are the keys and secrets?**
In `~/.attestation-bench` (`BENCH_HOME`), made on your machine by `make setup`. Nothing secret is in the repository,
and nothing is sent anywhere.

**What does the bench download?**
Pinned versions, each from its origin: Go modules (through Go's module proxy and checksum database), the third-party
sources from GitHub, HashiCorp Vault, ShellCheck and Go (for the Demo Bank's VM) with their SHA-256 checked, Python
packages from PyPI. Hardware runs also fetch AMD's certificate chain from AMD and Intel's collateral from Intel.

**Which operating systems?**
macOS and Linux. CI runs every change on Ubuntu 24.04; the bench was built on macOS (Apple silicon). Windows is not
tested.

**Why EST?**
The TACRA proof of concept the bench builds on uses EST as its Credential Acquisition System, through GlobalSign's EST
server with TACRA's `attest-*` resources; the architecture draft names EST among the mechanisms TACRA can extend.

**How do I add a Target, or make my own bank?**
Edit a pack: [../packs/README.md](../packs/README.md). The local bench uses `packs/tacra-bench`, the Demo Bank
`packs/demo-bank`.

**How do I approve a new firmware build?**
Only on its vendor's signed endorsement: [../trust/README.md](../trust/README.md).

**Who wrote what?**
The TACRA proof of concept (the CAI, the CAAPI, the platform plug-in interface, the EST server's TACRA resources) is
the TWI SIG's; the bench (the RRPs, the verifiers for TDX and the stand-in, the runs, the attack suite, the Demo Bank)
was built on it. The repository layout in [../README.md](../README.md) says which directory is which.
