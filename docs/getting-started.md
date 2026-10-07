# Getting started

From a fresh clone to a passing local run, one step at a time. Each step says what it does and what you should see.
Nothing here uses a cloud account or costs money.

## 1. What you need

- **macOS** (Apple silicon or Intel) or **Linux** (CI runs every change on Ubuntu 24.04).
- **Go 1.26.5 or later**: <https://go.dev/dl/>.
- **Python 3.10 or later**, with its `venv` module.
- **About 5 GB of free disk** for the tools, Veraison and the Go module cache.
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

It lists each tool the bench needs with `ok`, or with `need` and the command to install it, then the cloud tools the
hardware runs use (not needed for anything on this page), the ports and the disk. When everything is there it ends
with:

```
  ok       disk         13 GB free

Ready for make setup.
```

Install what it asks for and run it again until it says `Ready for make setup.`

## 4. Set the bench up

```bash
make setup
```

It builds and starts a complete trust zone on your machine, under `~/.attestation-bench` (set `BENCH_HOME` to use
another directory). Nothing is installed system-wide. Ten steps, each announced with `== n/10`:

1. a Python environment with the two packages the scripts use;
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

`make setup` is safe to run again at any time. If a step fails, it says which, and the details are in
`~/.attestation-bench/logs/setup.log`.

## 5. See what runs

```bash
make status
```

```
vts running (58326)
provisioning running (58352)
verification running (58354)
management running (58356)
step-ca running (58358)
vault running (58359)
tdx-verifier running (58383)
sim-verifier running (58384)
ca-gateway running (58391)
ca-gateway-2 running (58392)
vault-gateway running (58393)
est-server running (58406)
rup running (58407)
```

Thirteen services, all listening on `127.0.0.1` only: Veraison's four, step-ca, Vault, the TDX verifier, the stand-in
TEE's verifier, the two Credential Authority gateways (the second exists for the redirection experiment), the Secret
Vault gateway, the EST server and the Relying Party (`rup`). What each one does: [architecture.md](architecture.md).

## 6. Check that every component authenticates the others

```bash
make check-mtls
```

For every channel between components it tries every kind of caller: the components allowed there, the other
components (the wrong role), a certificate with the EST server's name from a CA the bench does not know, no
certificate at all, and an allowed component limited to TLS 1.2. Only the allowed components, over TLS 1.3, may get
through.

```
47 of 47 checks as expected
== run directory: /Users/you/.attestation-bench/runs/20261006T235843Z-bench-mtls-passport
```

## 7. Run TACRA end to end

```bash
make demo
```

The workload asks for a credential for each of ten Targets: an X.509 certificate from the Credential Authority and an
API key from the Secret Vault, each under the five Freshness Kinds. For each one it proves itself with a report from
the stand-in TEE, gets the credential through the EST server, and presents it to the Relying Party.

```
10 of 10 Targets: credential acquired and admitted by the relying party
ok  https://db-nonce.tacra.example         x509         33.1 ms 200
ok  https://db-epoch.tacra.example         x509          8.5 ms 200
...
ok  https://ledger-none.tacra.example      api-key       6.4 ms 200
== run directory: /Users/you/.attestation-bench/runs/20261006T215154Z-local-sim-e2e-passport
```

## 8. Attack it

```bash
make attacks
```

For each of the ten requests it first checks the honest Evidence, then changes one input at a time, as an
intermediary could: another Target, another RRP, another key, a replayed or stale freshness value, a key that is not
the platform's, an unapproved launch, a timestamp an hour off. Each must be refused for its own reason. It runs the
checks twice: inside one program, and through the bench's verifier as an RRP would ask it.

```
82 checks, 0 not as expected
50 checks, 0 not as expected
every attack refused for its own reason, every honest check passed
```

The catalogue of attacks and what stops each: [attacks.md](attacks.md).

## 9. The redirection experiment

```bash
make redirect
```

The workload produces Evidence for a Target of one Credential Authority, `ca1`. A hostile intermediary then offers
the same Evidence to a second one, `ca2`. The bench does it twice: with the RRP identifier in the binding, and
without it. It ends with:

```
pass         kind               ca1      ca2
no-rrp-id    present-nonce      ISSUED   refused
no-rrp-id    present-epoch      ISSUED   ISSUED
no-rrp-id    absent-epoch       ISSUED   ISSUED
no-rrp-id    absent-timestamp   ISSUED   ISSUED
no-rrp-id    absent-none        ISSUED   ISSUED
with-rrp-id  present-nonce      ISSUED   refused
with-rrp-id  present-epoch      ISSUED   refused
with-rrp-id  absent-epoch       ISSUED   refused
with-rrp-id  absent-timestamp   ISSUED   refused
with-rrp-id  absent-none        ISSUED   refused
```

With the RRP identifier in the binding, `ca2` refuses every Freshness Kind. Without it, only a nonce `ca2` never
issued stops the redirection. This is the question of
[TACRA issue #20](https://github.com/TheBankster/rats-tacra/issues/20). `make redirect` leaves the bench in Background
Check (step 11).

## 10. Read what a run left

Every run writes a directory under `~/.attestation-bench/runs/` (set `RUNS_DIR` for another place):

```bash
ls ~/.attestation-bench/runs/
cd "$(ls -d ~/.attestation-bench/runs/*-local-sim-e2e-* | tail -1)"
shasum -a 256 -c sha256sums.txt
```

The last command checks that nothing in the directory has changed since the run sealed it: every line ends in `OK`.
What each file holds: [results.md](results.md).

## 11. Passport and Background Check

The bench runs in one RATS model at a time: **Passport** (the EST server asks the verifier and passes the result to
the RRP) or **Background Check** (the RRP asks the verifier itself). To switch:

```bash
RATS_MODEL=background-check make config
make stop start
make demo
```

`make demo` names its run directory after the model it ran in. `RATS_MODEL=passport make config` switches back.

## 12. Stop, start, start over

```bash
make stop     # stops every service; nothing is lost
make start    # starts them again
```

To remove the bench entirely, its keys, stores and your run directories with it, stop it and delete its directory:

```bash
make stop
rm -rf ~/.attestation-bench
```

The next `make setup` builds it again from zero.

## Next

- Run the same three experiments on real hardware: [hardware/](hardware/README.md).
- Bring up the Demo Bank in the cloud: [demo-bank.md](demo-bank.md).
- Change what a bank issues: [../packs/README.md](../packs/README.md).
- Every `make` target: `make help`.
- Stuck: [troubleshooting.md](troubleshooting.md).
