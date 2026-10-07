# attestation-bench: the bench's make targets, included at the end of the Makefile. `make help` lists them with the
# TACRA proof of concept's own targets. Every target runs a script that also works on its own.
#
# BENCH_HOME (default ~/.attestation-bench) holds the running bench; RUNS_DIR (default BENCH_HOME/runs) the run
# directories. See scripts/lib.sh.

.PHONY: doctor setup start stop status config check-mtls trust-check third-party demo attacks redirect report \
	bank-new bank-up bank-pay bank-audit bank-down lint test check cloud-check

## doctor: checks this machine for what the bench needs: tools and versions, ports, disk
doctor:
	@scripts/doctor.sh

## setup: sets the bench up from zero in BENCH_HOME and starts it (safe to run again)
setup:
	@scripts/setup.sh

## start: starts the local trust zone (after setup)
start:
	@e2e/scripts/bench.sh start

## stop: stops the local trust zone
stop:
	@e2e/scripts/bench.sh stop

## status: shows which of the trust zone's services run
status:
	@e2e/scripts/bench.sh status

## config: writes the trust zone's configuration again (after a change in packs/ or trust/); then: make stop start
config:
	@e2e/scripts/bench.sh config

## check-mtls: mutual TLS between the components (N23), locally, no hardware
check-mtls:
	@scripts/check-mtls.sh

## trust-check: compares trust/ with its online sources; checks the approved launches against Veraison's CoRIM
trust-check:
	@trust/check.sh

## lint: every linter at its pinned version: ShellCheck, gofmt, go vet, golangci-lint, ruff, actionlint, gitleaks
lint:
	@scripts/lint.sh

## test: the unit tests: every Go module, our third-party patches', the Python scripts' (scripts/tests)
test:
	@scripts/test.sh

## check: lint, then test (what CI runs first)
check: lint test

## third-party: fetches the EST server, Veraison and go-gen-ref (pinned upstream + our patches)
third-party:
	@third_party/fetch.sh

# PLATFORM picks where the TEE runs for demo, attacks and redirect: local (default: this machine, the software
# stand-in TEE, no hardware, no cost, no security), or gcp-snp, gcp-tdx, aws-snp (real hardware: one VM in your own
# cloud account, deleted at the end; scripts/lib.sh). See scripts/run.sh.
PLATFORM ?= local

## demo: end to end, 10 Targets acquire their credentials and use them   [PLATFORM=local|gcp-snp|gcp-tdx|aws-snp]
##       refusal scenarios, every Target refused: SIM_DEBUG=1, SIM_LABEL=..., OTHER_PLATFORM=1 (docs/attacks.md)
demo:
	@scripts/run.sh demo $(PLATFORM)

## attacks: the substitution suite, every attack refused for its own reason   [PLATFORM=local|gcp-snp|gcp-tdx|aws-snp]
attacks:
	@scripts/run.sh attacks $(PLATFORM)

## redirect: the #20 redirection experiment, in Background Check; puts the bench back as it was   [PLATFORM=...]
redirect:
	@scripts/run.sh redirect $(PLATFORM)

## report: a table of your runs, each with what it tested and its verdict   [RUNS="dir ..."; default: RUNS_DIR]
report:
	@python3 scripts/report.py $(RUNS)

## cloud-check: checks that no VM, disk, firewall rule, key pair or security group of the bench is left in your clouds
cloud-check:
	@scripts/cloud-check.sh

# The Demo Bank: a fictional bank in your Google Cloud project, its payment service on real hardware (e2e/bank).
# Every bank command writes into the bank's run directory under RUNS_DIR; bank-down deletes everything it created.

## bank-new: a new fictional bank, packs/NAME/pack.json, from the Demo Bank's   [NAME=acme-bank]
bank-new:
	@scripts/bank-new.sh $(NAME)

## bank-up: the bank's trust zone and core VMs in your Google Cloud project   [BANK=demo-bank]
bank-up:
	@e2e/bank/demo-bank.sh up

## bank-pay: one payment by the bank's payment service   [PLATFORM=gcp-snp|gcp-tdx|aws-snp, controls: ordinary|unapproved]
bank-pay:
	@e2e/bank/demo-bank.sh pay $(PLATFORM)

## bank-audit: the ledger's record of who moved money, and the state of every service
bank-audit:
	@e2e/bank/demo-bank.sh audit

## bank-down: deletes the bank's VMs and firewall rules, checks that nothing is left, writes the bank's report
bank-down:
	@e2e/bank/demo-bank.sh down
