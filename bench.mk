# attestation-bench: the bench's make targets, included at the end of the Makefile. `make help` lists them with the
# TACRA proof of concept's own targets. Every target runs a script that also works on its own.
#
# BENCH_HOME (default ~/.attestation-bench) holds the running bench; RUNS_DIR (default BENCH_HOME/runs) the run
# directories. See scripts/lib.sh.

.PHONY: doctor setup start stop status check-mtls third-party demo attacks redirect

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

## check-mtls: mutual TLS between the components (N23), locally, no hardware
check-mtls:
	@scripts/check-mtls.sh

## third-party: fetches the EST server, Veraison and go-gen-ref (pinned upstream + our patches)
third-party:
	@third_party/fetch.sh

## demo: the end-to-end run locally, software stand-in TEE (no hardware, no cost, no security): 10 Targets
demo:
	@scripts/local-e2e.sh

## attacks: the substitution suite locally (software stand-in TEE), in process and through the sim-verifier
attacks:
	@scripts/local-attacks.sh

## redirect: the #20 redirection experiment locally (software stand-in TEE); leaves the bench in Background Check
redirect:
	@hwcheck/scripts/redirect.sh local
