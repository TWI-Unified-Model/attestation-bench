# Troubleshooting

Each entry: what you see, why, what to do. Most of them were met while the bench was built.

## Setting up

**`make doctor` lists `need …`.** A tool is missing or too old; the line ends with the command that installs it
(Homebrew on macOS, apt on Linux). Install it and run `make doctor` again.

**`make doctor` says a port is in use.** Another program listens on one of the trust zone's ports. If it is an earlier
bench, stop it (`make stop`, or that bench's own stop command); otherwise stop the program, or run the bench on a
machine where the ports are free.

**`make setup` stops with `error: …; the details are in ~/.attestation-bench/logs/setup.log`.** The message names the
step; the log has the full output. Fix the cause and run `make setup` again: every step that is already done is kept.

**Step 6, Veraison, fails on macOS.** Veraison's deployment script needs GNU `sort` (`gsort`), a C compiler and
`protoc`; `make doctor` checks all three.

**Step 9: `Veraison did not accept the CoRIM`.** Veraison's provisioning service could not reach its trust service
yet. `make setup` retries for a while; if it still fails, run `make setup` again.

## Running

**`!! start the bench first: make start`.** A run needs the trust zone: `make start` (after `make setup`), then
`make status`.

**`!! port 50061 (the CAS Client) is taken on this machine`.** A previous `make demo` was interrupted and left its CAS
Client running, or another program uses the port. Find it with `lsof -i :50061` and stop it.

**The run directory is named `…-background-check` and you expected Passport.** `make redirect` leaves the bench in
Background Check. Switch back: `RATS_MODEL=passport make config`, then `make stop start`.

**A run's `sha256sums.txt` check shows `FAILED`.** A file changed after the run sealed it. If you did not change it,
treat the directory as not trustworthy and run again.

## Hardware runs

**`error: no Google Cloud project`, `gcloud is not signed in`, `the AWS CLI is not signed in`, or a project that does
not exist.** The command stopped before creating anything. Sign in (`gcloud auth login`, `aws configure` or
`aws sso login`), set the project (`gcloud config set project <id>` or `GCP_PROJECT=<id>`) and run it again.

**The VM is not created: quota, or the machine type is not offered in the zone.** Ask for quota for the machine's
family in that region, or choose another zone or region (`GCP_ZONE`, `AWS_REGION`, `AWS_AZ`) where the machine type
exists ([hardware/](hardware/README.md)).

**`ssh never came up`.** The VM did not answer SSH in time. On GCP, check that your account can log in through OS
Login with administrator rights; on AWS, that your public address did not change during the run. The VM is deleted
anyway; run again.

**GCP TDX: every Target refused, `contraindicated`, and the TDX verifier logs an MRTD that matches no reference
value.** The VM started on a TDX firmware build the bench has not approved. Check Google's endorsement of that MRTD and
approve it ([../trust/README.md](../trust/README.md)); never approve a build whose endorsement does not check out.

**A run was interrupted (closed terminal, lost network).** It may have left its VM. Run `make cloud-check` and delete
anything it lists.

## Checks

**`make lint` or `make test` cannot fetch the third-party sources.** They need network access to github.com, to
fetch the pinned EST server, Veraison and go-gen-ref the Go modules build against.

**`make lint` reports a finding in code you did not touch.** The linters run at pinned versions; a different
version installed elsewhere on your machine is not used. Read the finding: it is real, or the configuration needs a
documented exception (`.golangci.yml`, `ruff.toml`).

## The Demo Bank

**`make bank-up` stopped during install or setup.** Fix the cause, then `e2e/bank/demo-bank.sh provision` continues on
the same VMs. If you give up, `make bank-down` deletes everything.

**`error: no Demo Bank is up`.** `bank-pay`, `bank-audit` and `approve` need a bank: `make bank-up` first.
