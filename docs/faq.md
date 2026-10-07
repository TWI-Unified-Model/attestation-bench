# FAQ

**Do I need a cloud account?**
Yes, for any run of the protocol: nothing stands in for the hardware. `make setup` and `make check-mtls` set up and
check the trust zone on your machine; `make demo`, `attacks` and `redirect` need a Google Cloud project (`gcp-snp`,
`gcp-tdx`) or an AWS account (`aws-snp`) with confidential VMs, and the Demo Bank needs Google Cloud.

**Why is there no laptop mode?**
The bench had one, a software stand-in for the hardware. It showed that the protocol's checks work, but nothing about
isolation, and a run on it could be taken for an attested one. The bench now runs nothing that stands in for the real
thing ([concepts.md](concepts.md), only real hardware).

**What does a hardware run cost?**
One small VM for a few minutes: between 108 and 272 seconds in the fourteen hardware runs of 7 October 2026, at the
cloud's price for that machine ([hardware/](hardware/README.md)). The Demo Bank keeps two VMs for as long as it is
up.

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
Edit a pack: [../packs/README.md](../packs/README.md). The bench's own trust zone uses `packs/tacra-bench`, the Demo
Bank `packs/demo-bank`.

**How do I approve a new firmware build?**
From where its value comes: Google's signed endorsement for Google Cloud, AWS's published firmware measured again for
AWS ([../trust/README.md](../trust/README.md)). Never from a value a VM reported.

**Who wrote what?**
The TACRA proof of concept (the CAI, the CAAPI, the platform plug-in interface, the EST server's TACRA resources) is
the TWI SIG's; the bench (the RRPs, the TDX verifier, the runs, the attack suite, the Demo Bank)
was built on it. The repository layout in [../README.md](../README.md) says which directory is which.
