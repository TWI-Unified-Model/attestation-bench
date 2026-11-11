# TACRA through SPIRE

The bench runs the SPIRE proof of concept of TACRA end to end on real hardware. An attested Workload in a confidential
VM enrolls an X509-SVID for a key that it generates, and retrieves a credential from the Secret Vault. The Workload
calls the Workload API of SPIRE Agent, and the Agent forwards the calls to SPIRE Server.

The code is the fork [TWI-Unified-Model/spiffe-spire](https://github.com/TWI-Unified-Model/spiffe-spire). The page
[doc/attested_credential_acquisition.md](https://github.com/TWI-Unified-Model/spiffe-spire/blob/main/doc/attested_credential_acquisition.md)
of the fork describes the roles, the three calls, the configuration and the refusals. This page says how to run the
proof of concept on the bench and how to read a run.

Nothing in a run is mocked. The Evidence comes from the hardware of the VM. The Verifier is Veraison for SEV-SNP and the
TDX Verifier of the bench for TDX. The CA is the CA of SPIRE Server. The Secret Vault is the gateway of the bench in
front of HashiCorp Vault.

## What a run needs

1. The bench set up and running: steps 1 to 5 of [getting-started.md](getting-started.md). `make status` shows the
   services.
2. A cloud account that can create the confidential VM, as every hardware run needs
   ([hardware/README.md](hardware/README.md)).
3. A checkout of the fork, outside this repository. `SPIRE_REPO` names the checkout:

```bash
git clone https://github.com/TWI-Unified-Model/spiffe-spire "$HOME/spiffe-spire"
export SPIRE_REPO="$HOME/spiffe-spire"
```

A run builds SPIRE Server for the computer that runs the bench, and SPIRE Agent and the attested Workload for
linux/amd64, from HEAD of the checkout. `SPIRE_REPO` has no default: a run builds only from a directory that the user
named.

## The commands

From the root of this repository:

```bash
e2e/scripts/spire-gcp-snp-e2e.sh            # Google Cloud, AMD SEV-SNP, n2d-standard-2
TEE=tdx e2e/scripts/spire-gcp-snp-e2e.sh    # Google Cloud, Intel TDX, c3-standard-4
e2e/scripts/spire-aws-snp-e2e.sh            # AWS, AMD SEV-SNP, c6a.large
```

A run lasts three to four minutes. The first run also compiles SPIRE, which adds about ten minutes on a computer with
four vCPUs. A run creates one VM in the project or the account that the cloud CLI is signed in to, deletes the VM at
the end and checks that the VM is gone. The exit status is 0 when the verdict admits every check.

## What a run does

1. The run builds the three programs and records the sources (`spire-source.txt`, `binaries.sha256`).
2. The run writes the configuration of SPIRE Server from the configuration of the bench: the Verifier, the approved
   launch measurements, the platform rule and the Secret Vault (`config/server.conf`). The Server listens on
   `127.0.0.1:8081` with the audit log on. The run creates a join token for the Agent and a registration entry for the
   Workload.
3. The run creates the VM, copies the Agent, the Workload and the public configuration to the VM, and opens an SSH
   reverse tunnel from the VM to the Server.
4. In the VM the Agent joins. The Workload then enrolls an X509-SVID for the Target `spiffe://example.org` with the
   Freshness Kind present-nonce, and retrieves the API key of the Target `https://ledger-nonce.tacra.example` from the
   Secret Vault. The Secret Vault seals the API key to a Credential Encryption Key that the Workload generates for the
   request.
5. The run copies the record from the VM, deletes the VM, writes the verdict and seals the run directory.

## The verdict

`verdict.txt` has one line for each check, `ADMITTED` or `REFUSED`, and then the figures of the run.

| Check | Admitted when |
|---|---|
| `Enrollment: the Workload completed without an error` | the Workload reports the Enrollment as done |
| `Enrollment: the chain of the X509-SVID verifies against the bundle` | the Workload verified the chain against the bundle of the trust domain |
| `Enrollment: the X509-SVID certifies the key that the Workload generated` | the public key of the certificate is the key that the Workload generated |
| `Enrollment: the X509-SVID names the SPIFFE ID of the registration entry` | the certificate names `spiffe://example.org/workload` |
| `Enrollment: the launch measurement is approved` | the launch measurement in the Evidence is in `approved-measurements.json` |
| `Enrollment: SPIRE Server enrolled with the launch measurement of the Evidence` | the log of SPIRE Server records the Enrollment with that launch measurement |
| `Enrollment: SPIRE Server audited the call as a success with that launch measurement` | the audit log of SPIRE Server has the line |
| `Retrieval: the Workload completed without an error` | the Workload reports the Retrieval as done |
| `Retrieval: the Workload opened the credential with its Credential Encryption Key` | the Workload opened the container; the record keeps the SHA-256 of the credential, not the credential |
| `Retrieval: the Evidence has the launch measurement of the Enrollment` | the two launch measurements are equal |
| `Retrieval: SPIRE Server audited the call as a success` | the audit log of SPIRE Server has the line |
| `Retrieval: the Secret Vault released the credential for the Target` | the log of the Secret Vault records the release for `https://ledger-nonce.tacra.example` |
| `Retrieval: the Workload verified the origin signature of the container under the key of the Secret Vault` | the Secret Vault signed the container and the Workload verified the signature; the verdict has this check when the Secret Vault signs for the Target, which is the default of the bench |

## The files of a run

The run directory is `~/.attestation-bench/runs/<time>-spire-<cloud>-<tee>-e2e`; `RUNS_DIR` names another place.

| File | Content |
|---|---|
| `verdict.txt` | the checks and the figures of the run |
| `spire-source.txt`, `binaries.sha256` | the commit of the checkout, its uncommitted changes, the Go version, the `replace` directives of `go.mod`, the commit of a module that the build uses from a directory; the SHA-256 of the three programs |
| `config/` | the configuration of SPIRE Server and of SPIRE Agent, the platform rule, the RATS model of the Secret Vault and its origin key; no secret |
| `workload/` | the Enrollment: `result.json`, the X509-SVID, the bundle, the Evidence as sent, the output of the Workload |
| `workload-retrieve/` | the Retrieval: `result.json`, the container as released, the Evidence as sent, the output of the Workload |
| `server.log`, `agent.log`, `agent.stdout` | the log of SPIRE Server with the audit records, the log of SPIRE Agent |
| `bench-logs/` | the logs of the Verifier and of the Secret Vault during the run |
| `approved-measurements.json`, `entry.txt` | the launch measurements that the bench approves, the registration entry |
| `provision.txt`, `kernel.txt`, `machine-type.txt`, `clock.txt`, `clock-offset.txt`, `run-window.txt` | the VM: the TSM interface, the kernel, the machine type, the clock |
| `guest-stdout.txt`, `guest-rc.txt`, `ssh.stderr` | the output of the script in the VM, its exit status, the messages of SSH |
| `vm-deleted.txt` | the time at which the VM was gone |
| `sha256sums.txt` | the seal: `shasum -a 256 -c sha256sums.txt` in the run directory shows that no file changed ([results.md](results.md)) |

The join token reaches the Agent on its command line and is in no file of the record. The private keys of the Workload
stay in the VM.

## Passport and Background Check

A run reads the RATS model of the Secret Vault from the configuration of the bench. Section 11 of
[getting-started.md](getting-started.md) switches the model:

```bash
RATS_MODEL=background-check make config
make stop start
e2e/scripts/spire-gcp-snp-e2e.sh
```

In Passport, SPIRE Server sends the Evidence of the Retrieval to the Verifier and forwards the Attestation Results,
unchanged, to the Secret Vault. In Background Check, the Secret Vault sends the Evidence to the Verifier. In both
models the Secret Vault recomputes the binding value and appraises the Attestation Results by its own policy.
`config/vault-mode.txt` records the model of a run.

## The demo

`e2e/scripts/spire-demo.sh` makes one run in a recorded terminal session, narrates the run and writes a walkthrough
from the record of the run:

```bash
e2e/scripts/spire-demo.sh                             # Google Cloud SEV-SNP; the argument tdx or aws names another platform
DEMO_RUN=<run directory> e2e/scripts/spire-demo.sh    # narrates a run already made, without SPIRE_REPO and without a cloud account
```

The demo writes `demo.typescript`, `demo.txt`, `run.log`, `run-directory.txt` and `walkthrough.md` to
`~/.attestation-bench/demo/<time>-spire-<platform>`.

## Reference runs

One run on each platform, made with the commands above:

- [Google Cloud SEV-SNP](../e2e/evidence/20261111T145013Z-spire-gcp-sev-snp-e2e)
- [Google Cloud TDX](../e2e/evidence/20261111T145412Z-spire-gcp-tdx-e2e)
- [AWS SEV-SNP](../e2e/evidence/20261111T145723Z-spire-aws-sev-snp-e2e)

## Limits

- The Agent joins with a join token. The run does not attest the node; it attests the Workload.
- SPIRE Server runs on the computer that runs the bench, and the VM reaches it through an SSH reverse tunnel. The keys of
  the Server are in memory, and the `credential_acquisition` block is under `experimental`. This arrangement is for
  testing, not for deployment.
- On Google Cloud and AWS SEV-SNP the Server admits the host under the waiver of the bench for the mitigation bit that
  AMD-SB-3034 names ([limits.md](limits.md)). `server.log` records the waiver; `verdict.txt` does not.
- The run script judges the run. `scripts/verdict.py` does not know this kind of run: `make report` lists it as "not a
  run of the make commands", and `make test-live` does not appraise its Evidence again.
