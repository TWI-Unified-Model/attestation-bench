# Getting started

From a fresh clone to a passing run on real hardware, one step at a time. Each step says what it does and what you
should see. Steps 1 to 6 set up and check the trust zone on your machine, at no cost. Steps 7 to 9 run TACRA with a
confidential VM in your own cloud account: one small VM for a few minutes each, deleted at the end. Nothing stands in
for the hardware.

## 1. What you need

- **macOS** (Apple silicon or Intel) or **Linux** (CI runs every change on Ubuntu 24.04).
- **git and make**, to get the code and run its commands. On macOS they come with the Xcode Command Line Tools
  (`xcode-select --install`); on Debian or Ubuntu, `sudo apt-get install -y git make` (a fresh Ubuntu 24.04 has git,
  not make).
- **Go 1.26.5 or later**: <https://go.dev/dl/>.
- **Python 3.10 or later**, with its `venv` module.
- **About 8 GB of free disk.** On a fresh Ubuntu 24.04, `make setup` took 7.3 GB: the bench's home 1.4 GB, Go's
  module cache 2.6 GB and build cache 1.8 GB, and the third-party sources in the clone; `make check` takes 1.7 GB
  more ([verification.md](verification.md)).
- **For steps 7 to 9, a cloud account that can create confidential VMs:** a Google Cloud project (AMD SEV-SNP and
  Intel TDX) or an AWS account (AMD SEV-SNP), with its CLI signed in. How to set it up, the quotas and the cost:
  [hardware/](hardware/README.md).
- Access to the repository. It is private: ask its owner to invite your GitHub account.

`make doctor` (step 3) checks everything else and prints the command that installs what is missing.

## 2. Get the code

```bash
git clone git@github.com:nikolaichuk7/attestation-bench.git    # or: gh repo clone nikolaichuk7/attestation-bench
cd attestation-bench
```

Every command below runs from this directory.

## 3. Check your machine

```bash
make doctor
```

It lists each tool the bench needs with `ok`, or with `MISSING` and the command to install it, then the cloud tools
the hardware runs use (from step 7), the ports and the disk. When everything is there it ends with:

```
  ok       disk         13 GB free

Ready for make setup.
```

Install what it asks for and run it again until it says `Ready for make setup.`

## 4. Set the trust zone up

```bash
make setup
```

It builds and starts a complete trust zone on your machine, under `~/.attestation-bench` (set `BENCH_HOME` to use
another directory): what a bank runs to give credentials to attested workloads. Nothing is installed system-wide. Ten
steps, each announced with `== n/10`:

1. a Python environment with the packages the scripts use (`scripts/requirements.txt`);
2. pinned tools, built from source or downloaded and checked against their SHA-256: `step`, `step-ca`, HashiCorp Vault,
   the protoc plug-ins;
3. the third-party sources: the EST server, Veraison and go-gen-ref, each at a pinned upstream commit plus our patches;
4. a TLS root for the bench and a certificate for each service;
5. step-ca, the workload CA;
6. Veraison, built and deployed;
7. the configuration of every service, from the bench's pack (`packs/tacra-bench/pack.json`), and the bench's
   programs;
8. HashiCorp Vault, with the secret the demo releases;
9. Veraison started and given the AMD trust anchor and the approved launches;
10. the trust zone started.

The first time, it builds the tools and Veraison from source and takes noticeably longer; later runs reuse what is
there and only check it. It ends with:

```
The bench is up in /Users/you/.attestation-bench. Next: make status, make check-mtls.
```

`make setup` is safe to run again at any time, and it is how you update the bench after `git pull`: it builds again
what the new code changed, Veraison included, and restarts the services when their programs or configuration
changed. If a step fails, it says which, and the details are in `~/.attestation-bench/logs/setup.log`.

## 5. See what runs

```bash
make status
```

```
vts running (10698)
provisioning running (10724)
verification running (10726)
management running (10728)
step-ca running (10730)
vault running (10731)
tdx-verifier running (10755)
ca-gateway running (10760)
ca-gateway-2 running (10761)
vault-gateway running (10762)
est-server running (10775)
rup running (10776)
```

Twelve services, all listening on `127.0.0.1` only: Veraison's four, step-ca, Vault, the TDX verifier, the two
Credential Authority gateways (the second exists for the redirection experiment), the Secret Vault gateway, the EST
server and the Relying Party (`rup`). What each one does: [architecture.md](architecture.md).

## 6. Check that every component authenticates the others

```bash
make check-mtls
```

For every channel between components it tries every kind of caller: the components allowed there, the other
components (the wrong role), a certificate with the EST server's name from a CA the bench does not know, no
certificate at all, and an allowed component limited to TLS 1.2. Only the allowed components, over TLS 1.3, may get
through.

```
VERDICT PASS: 40 of 40 checks as expected: only the allowed components, over TLS 1.3
== run directory: /Users/you/.attestation-bench/runs/20261007T140853Z-bench-mtls-passport
```

## 7. Run TACRA end to end, on real hardware

```bash
make demo PLATFORM=gcp-snp    # or gcp-tdx, aws-snp
```

It creates one confidential VM in your account, AMD SEV-SNP here, and runs the workload in it. The workload asks for
a credential for each of ten Targets: an X.509 certificate from the Credential Authority and an API key from the
Secret Vault, each under the five Freshness Kinds. For each one it proves itself with the hardware's report, gets the
credential through the EST server on your machine, and presents it to the Relying Party. Then the VM is deleted, and
the deletion checked.

```
10 of 10 Targets: credential acquired and admitted by the relying party
ok  https://db-nonce.tacra.example         x509        755.8 ms 200
ok  https://db-epoch.tacra.example         x509        645.9 ms 200
...
ok  https://ledger-none.tacra.example      api-key     491.9 ms 200
VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party
== run directory: /Users/you/.attestation-bench/runs/20261007T135611Z-gcp-sev-snp-e2e-passport
```

Every run ends this way: its verdict, then the directory that holds everything it recorded. A run whose verdict is
`FAIL` makes `make` fail too. The same command can play an attacker: `UNAPPROVED=1` (a launch the bench does not
approve) and `OTHER_PLATFORM=1` (the Targets of another platform's verifier), in which every Target must be refused
([attacks.md](attacks.md), sections 4 and 5).

## 8. Attack it

```bash
make attacks PLATFORM=gcp-snp
```

For each of the ten requests it first checks the honest Evidence, then changes one input at a time, as an
intermediary could: another Target, another RRP, another key, a replayed or stale freshness value, a key that is not
the platform's, an unapproved launch, a timestamp an hour off. Each must be refused for its own reason. It runs the
checks twice: inside one program, with the bench's build of Veraison, and through the deployed Veraison as an RRP
would ask it; two other builds of Veraison are run beside them, for comparison only.

```
rrpverify-service: 50 checks, 0 not as expected
rrpverify-veraison-fixed: 162 checks, 0 not as expected (a build the bench compares with: reported, not judged)
rrpverify-veraison-fork: 142 checks, 60 not as expected (a build the bench compares with: reported, not judged)
rrpverify-veraison-v015: 162 checks, 0 not as expected
VERDICT PASS: 212 checks: the honest Evidence passed, every attack refused for its own reason
== run directory: /Users/you/.attestation-bench/runs/20261007T134801Z-gcp-sev-snp
```

The catalogue of attacks and what stops each: [attacks.md](attacks.md).

## 9. The redirection experiment

```bash
make redirect PLATFORM=gcp-snp
```

The workload produces Evidence for a Target of one Credential Authority, `ca1`. A hostile intermediary then offers
the same Evidence to a second one, `ca2`. The bench does it twice: with the RRP identifier in the binding, and
without it. It ends with:

```
pass         kind               ca1      ca2
with-rrp-id  present-nonce      ISSUED   refused
with-rrp-id  present-epoch      ISSUED   refused
with-rrp-id  absent-epoch       ISSUED   refused
with-rrp-id  absent-timestamp   ISSUED   refused
with-rrp-id  absent-none        ISSUED   refused
no-rrp-id    present-nonce      ISSUED   refused
no-rrp-id    present-epoch      ISSUED   ISSUED
no-rrp-id    absent-epoch       ISSUED   ISSUED
no-rrp-id    absent-timestamp   ISSUED   ISSUED
no-rrp-id    absent-none        ISSUED   ISSUED
VERDICT PASS: with the RRP identifier, ca2 refused all 5 Freshness Kinds; without it, all but present-nonce
== run directory: /Users/you/.attestation-bench/runs/20261007T060630Z-gcp-snp-redirect
```

With the RRP identifier in the binding, `ca2` refuses every Freshness Kind. Without it, only a nonce `ca2` never
issued stops the redirection. This is the question of
[TACRA issue #20](https://github.com/TheBankster/rats-tacra/issues/20). The experiment runs in Background Check and
puts the bench back as it was when it ends, also when it fails or is interrupted.

## 10. Read what a run left

Every run writes a directory under `~/.attestation-bench/runs/` (set `RUNS_DIR` for another place):

```bash
ls ~/.attestation-bench/runs/
cd "$(ls -d ~/.attestation-bench/runs/*-e2e-* | tail -1)"
shasum -a 256 -c sha256sums.txt
```

The last command checks that nothing in the directory has changed since the run sealed it: every line ends in `OK`.
What each file holds: [results.md](results.md). All your runs, one row each with its verdict:

```bash
make report
```

## 11. Passport and Background Check

The bench runs in one RATS model at a time: **Passport** (the EST server asks the verifier and passes the result to
the RRP) or **Background Check** (the RRP asks the verifier itself). To switch:

```bash
RATS_MODEL=background-check make config
make stop start
make demo PLATFORM=gcp-snp
```

`make demo` names its run directory after the model it ran in. To switch back: `RATS_MODEL=passport make config`,
then `make stop start`.

## 12. Stop, start, start over

```bash
make stop     # stops every service; nothing is lost
make start    # starts them again
```

To remove the bench entirely, its keys, stores and your run directories with it, stop it and delete its directory
(`$BENCH_HOME` instead, if you set it):

```bash
make stop
rm -rf ~/.attestation-bench
```

The next `make setup` builds it again from zero.

## Next

- The other platforms, their quotas and their cost: [hardware/](hardware/README.md).
- Bring up the Demo Bank in the cloud: [demo-bank.md](demo-bank.md).
- Change what a bank issues: [../packs/README.md](../packs/README.md).
- Every `make` target: `make help`.
- Stuck: [troubleshooting.md](troubleshooting.md).
