# attestation-bench: the bench's make targets, included at the end of the Makefile. `make help` lists them with the
# TACRA proof of concept's own targets. Every target runs a script that also works on its own.
#
# BENCH_HOME (default ~/.attestation-bench) holds the running bench; RUNS_DIR (default BENCH_HOME/runs) the run
# directories. See scripts/lib.sh.

.PHONY: doctor setup start stop status config check-mtls trust-check third-party demo attacks redirect

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

## third-party: fetches the EST server, Veraison and go-gen-ref (pinned upstream + our patches)
third-party:
	@third_party/fetch.sh

# PLATFORM picks where the TEE runs for demo, attacks and redirect: local (default: this machine, the software
# stand-in TEE, no hardware, no cost, no security), or gcp-snp, gcp-tdx, aws-snp (real hardware: one VM in your own
# cloud account, deleted at the end; scripts/lib.sh). See scripts/run.sh.
PLATFORM ?= local

## demo: end to end, 10 Targets acquire their credentials and use them   [PLATFORM=local|gcp-snp|gcp-tdx|aws-snp]
demo:
	@scripts/run.sh demo $(PLATFORM)

## attacks: the substitution suite, every attack refused for its own reason   [PLATFORM=local|gcp-snp|gcp-tdx|aws-snp]
attacks:
	@scripts/run.sh attacks $(PLATFORM)

## redirect: the #20 redirection experiment; leaves the bench in Background Check   [PLATFORM=local|gcp-snp|...]
redirect:
	@scripts/run.sh redirect $(PLATFORM)
