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
vts running (94687)
provisioning running (94713)
verification running (94715)
management running (94717)
step-ca running (94719)
vault running (94720)
tdx-verifier running (94744)
ca-gateway running (94751)
ca-gateway-2 running (94752)
vault-gateway running (94753)
vault-gateway-2 running (94762)
est-server running (94767)
rup running (94768)
```

Thirteen services, all listening on `127.0.0.1` only: Veraison's four, step-ca, Vault, the TDX verifier, the two
Credential Authority gateways and the two Secret Vault gateways (the second of each exists for the redirection
experiment), the EST server and the Relying Party (`rup`). What each one does: [architecture.md](architecture.md).

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
== run directory: /Users/you/.attestation-bench/runs/20261007T172815Z-bench-mtls-passport
```

Then the tests that need the running bench, still without hardware:

```bash
make test-live
```

It checks the EST server's wire format through the running server: the media types each attest-* resource takes, the
415 it answers to any other, the Handle as unpadded base64url, a Handle that serves one request only. Each request
carries the real Evidence of a committed hardware run, which the RRP refuses because it is bound to another Handle.
Then the live verifiers appraise again the Evidence of every committed attack run from 6 October 2026 on, with each
run's own records as the RRP's: the honest Evidence must pass and each changed binding must fail, as when the run was
made. Veraison fetches AMD's revocation list and the TDX verifier Intel's collateral, so it needs the network.

```
  ok  attest-initiate https://db-nonce.tacra.example: 200, mode enroll, Handle 43 characters of unpadded base64url, 32 octets
  ok  /attest-enroll as text/plain: 415 Content-Type must be application/json
  ...
  ok    20261007T182023Z-gcp-tdx       50 checks, 0 not as expected
test-live: the EST wire format as expected; 29 committed runs appraised again, 1450 checks as expected
```

That is at v0.1.0; every attack run committed after it adds one run and 50 checks.

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
ok  https://db-nonce.tacra.example         x509        933.2 ms 200
ok  https://db-epoch.tacra.example         x509        515.1 ms 200
...
ok  https://ledger-none.tacra.example      api-key     440.2 ms 200
the platform rule's waiver: Milan bit 4: admitted without bit 4, AMD-SB-3034
guest minus RRP: +1.127 s, within 1.308 s
VERDICT PASS: all 10 Targets: credential acquired and admitted by the relying party; admitted under the bench's waiver: Milan bit 4: admitted without bit 4, AMD-SB-3034
== run directory: /Users/you/.attestation-bench/runs/20261007T174229Z-gcp-sev-snp-e2e-passport
```

On SEV-SNP the verdict names the bench's waiver: the platform rule requires the mitigation bit AMD-SB-3034 names for
Milan, no Google Cloud or AWS host sets it, and the bench admits them under that named waiver so that the protocol
can be shown; a bank's rule, with no waiver, refuses them ([limits.md](limits.md)). On TDX the verdict ends at "by
the relying party". `guest minus RRP` is the guest's clock against the RRP's.

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
would ask it; two other builds of Veraison are run beside them, for comparison only. Then it applies the RRPs'
platform rule to the honest results (`rrpverify-platform`). And it pre-plays Evidence made with the guest's clock moved:
300 s ahead, of every Freshness Kind, with Handles the live RRPs minted for it, and 300 s behind, absent-timestamp. The
other kinds are taken at once; absent-timestamp made ahead is refused at once, taken inside its window, older than
`max_age`, and refused after it; made behind, it is refused. That is reported as an exposure, not a pass
([limits.md](limits.md), "Time").

```
rrpverify-platform: 50 checks, 0 not as expected
rrpverify-service: 50 checks, 0 not as expected
rrpverify-veraison-fixed: 162 checks, 0 not as expected (a build the bench compares with: reported, not judged)
rrpverify-veraison-fork: 142 checks, 60 not as expected (a build the bench compares with: reported, not judged)
rrpverify-veraison-v015: 162 checks, 0 not as expected
pre-play ahead enroll-absent-epoch: at once 200
...
pre-play ahead enroll-absent-timestamp: at once 409; 286 s or more after it was made 200, 407 s 200, 411 s 409 (max_age 120 s, clock_skew 5 s)
...
pre-play behind enroll-absent-timestamp: at once 409; 411 s or more after it was made 409
...
the platform rule's waiver: Milan bit 4: admitted without bit 4, AMD-SB-3034
guest minus RRP: +1.283 s, within 1.416 s
VERDICT PASS: 262 checks: the honest Evidence passed, every attack refused for its own reason; the honest Evidence admitted under the bench's waiver: Milan bit 4: admitted without bit 4, AMD-SB-3034; exposure, the guest's clock: https://db-time.tacra.example accepted Evidence 286 s old or more, and again 407 s old or more (max_age 120 s); https://ledger-time.tacra.example accepted Evidence 286 s old or more, and again 407 s old or more (max_age 120 s); absent-timestamp Evidence made with the clock behind refused; the other four kinds' Evidence made with it ahead taken at once
== run directory: /Users/you/.attestation-bench/runs/20261007T212531Z-gcp-sev-snp
```

The catalogue of attacks and what stops each: [attacks.md](attacks.md).

## 9. The redirection experiment

```bash
make redirect PLATFORM=gcp-snp
```

The workload produces Evidence for a Target of one Credential Authority, `ca1`. A hostile intermediary then offers
the same Evidence to a second one, `ca2`. The bench does it twice: with the RRP identifier in the binding, and
without it. Then the intermediary rewrites, one at a time, what it relays to `ca1`: a made-up Handle, the Freshness
Kind, the credential type, another workload's Credential Hint. It ends with:

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
rewrite at ca1                         kind               outcome
made-up Handle                         present-nonce      refused freshness fresh: freshness element is not valid now: unknown or alread
Freshness Kind absent-none             present-nonce      refused freshness-kind-mismatch not allowed by this RRP's policy for the Targe
credential type not offered            present-nonce      refused unsupported-credential-type not allowed by this RRP's policy for the T
Credential Hint of another workload    present-nonce      refused credential-hint the Credential Hint is not the identity the CA assigns
...
the other credential type offered      present-nonce      refused freshness fresh: freshness element is not valid now: Handle was issued
the other credential type offered      present-epoch      ISSUED CN=payments.workload.tacra.example
the other credential type offered      absent-epoch       ISSUED CN=payments.workload.tacra.example
the other credential type offered      absent-timestamp   ISSUED CN=payments.workload.tacra.example
the other credential type offered      absent-none        ISSUED CN=payments.workload.tacra.example
guest minus RRP: +1.111 s, within 1.306 s
VERDICT PASS: with the RRP identifier, ca2 refused all 5 Freshness Kinds; without it, all but present-nonce; of the conduit's 20 rewrites at ca1, the other credential type the Target offers was issued for every kind but present-nonce, and every other was refused for its own reason
== run directory: /Users/you/.attestation-bench/runs/20261007T204444Z-gcp-snp-redirect
```

With the RRP identifier in the binding, `ca2` refuses every Freshness Kind. Without it, only a nonce `ca2` never
issued stops the redirection: here, where the two share one epoch marker and the Evidence is made for `ca1`. With
`REDIRECT_VARIANT=own-epochs` `ca2` keeps an epoch marker of its own; with `REDIRECT_VARIANT=start-ca2` the conduit
also starts the exchange at `ca2`, and without the identifier `ca2` issues on its own nonce; `REDIRECT_VARIANT=vault`
runs the same on the two Secret Vaults ([attacks.md](attacks.md), section 2). This is the question of
[TACRA issue #20](https://github.com/TheBankster/rats-tacra/issues/20). Each rewrite is refused for its own reason,
except the other credential type the Target offers: nothing binds the type, and only the present-nonce Handle, minted
for one type, catches it ([attacks.md](attacks.md), section 2; [TACRA issue #19](https://github.com/TheBankster/rats-tacra/issues/19)).
The experiment runs in Background Check, and with `PASSPORT=1` in Passport, where the intermediary offers the
Attestation Results the verifier issued for `ca1`; the outcomes are the same. It puts the bench back as it was when it
ends, also when it fails or is interrupted.

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
