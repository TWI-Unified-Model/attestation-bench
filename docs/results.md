# Reading a run

Every run writes one directory: under `~/.attestation-bench/runs/` by default, or under `RUNS_DIR`. Its name says when
it started (UTC) and what it was, for example `20261006T222601Z-gcp-sev-snp-e2e-passport`. The reference runs behind
the numbers in these docs are kept in the repository, under `e2e/evidence/` and `hwcheck/evidence/`.

## Is it intact?

The run's last step writes `sha256sums.txt`: the SHA-256 of every other file in the directory. Check it from inside
the directory:

```bash
shasum -a 256 -c sha256sums.txt        # or: sha256sum -c sha256sums.txt
```

Every line must end in `OK`. A file changed or removed since the run shows `FAILED`. (A `README.md` or a
`compare-with-*.txt` added after the run, as the reference runs have, is not in the list. The runs of
`make check-mtls` among the reference runs, all made before 7 October 2026, have no seal: the check did not write one
yet.)

## Did it come out as expected?

Before it seals its directory, a run judges itself: `verdict.txt` holds what the run did and a last line,
`VERDICT PASS: …` or `VERDICT FAIL: …`. On FAIL the run exits with an error, so `make` and CI fail too.
`scripts/verdict.py` judges any run again from its directory alone, the reference runs included:

```bash
python3 scripts/verdict.py demo e2e/evidence/20261006T222601Z-gcp-sev-snp-e2e-passport
python3 scripts/verdict.py attacks hwcheck/evidence/20261006T225040Z-gcp-tdx
python3 scripts/verdict.py redirect hwcheck/evidence/20261006T225552Z-gcp-snp-redirect
```

What each kind of run must show is at the top of `scripts/verdict.py`; its tests judge every reference run of
6 October 2026 and runs changed in one place (`scripts/tests/`). The reference runs made before the verdict existed
have no `verdict.txt`; the program judges them all the same.

## All your runs at a glance

```bash
make report                                              # every run in ~/.attestation-bench/runs (or RUNS_DIR)
make report RUNS="e2e/evidence/* hwcheck/evidence/*"     # or any run directories, the reference runs too
```

One row per run (per payment, for a bank): what it tested, the platform, the RATS model and the verdict, then how
many passed and failed. A run made before runs kept their verdict is judged again from its files and marked `*`. A
run that stopped before its results, finished without any, or whose files are of an earlier format is listed as not
judged, with the reason; a reference run's `README.md` says what it showed. Among the
reference runs, six fail: each found a fault in its day, which its README or the results file that cites it
(`e2e/RESULTS-*.md`) describes, and a later run shows fixed.

## Files every run has

| File | Holds |
|---|---|
| `code-rev.txt` or `code-revs.txt` | the bench's commit (`-dirty` if the code had uncommitted changes), and for end-to-end runs each third-party component's upstream commit and patches, and the deployed Veraison's build |
| `binaries.sha256` | the SHA-256 of the programs the run built and ran |
| `rats-model.txt` | `passport` or `background-check` |
| `platform.txt` | on the stand-in TEE only: a reminder that it gives no security |
| `verdict.txt` | the run's verdict (above) |
| `sha256sums.txt` | the seal (above) |

## `make demo`: `…-e2e-<model>`

| File | Holds |
|---|---|
| `results.json` | one entry per Target: `target`, credential `type`, `ok`, `attempts`, `acquire_ms`, the Relying Party's answer (`rup_status`, `rup_response`) and, for certificates, `cert_names`, `cert_issuer`, `cert_serial`, `not_after` |
| `e2e-attester.json` | the workload's configuration: Targets, RRP identifiers and public keys only |
| `e2e-attester-stdout.txt`, `caapi-est.log` | what the workload and the CAS Client printed |
| `bench-logs/` | each trust zone service's log lines for this run only |
| `run-window.txt` | the run's start and end, in seconds since 1970 |
| `platform-rule.json` | the platform rule the RRPs applied: product lines, minimum TCB, required PLATFORM_INFO and mitigation bits and SMT on SEV-SNP, refused TD attributes on TDX ([../trust/README.md](../trust/README.md)); runs before 7 October 2026 have none |
| hardware only: `kernel.txt`, `machine-type.txt` (GCP) or `instance.txt` (AWS), `vm-deleted.txt` | the guest's kernel, the machine, and the record of its deletion, with the time it was found gone |

## `make attacks`: `…-local-sim-attacks`, `…-gcp-sev-snp`, `…-gcp-tdx`, `…-aws-sev-snp`

| File | Holds |
|---|---|
| `handles.json` | the Freshness Handles the RRP minted for the run |
| `enroll-<kind>/`, `retrieve-<kind>/` | per request: the Evidence (`evidence.tsm.cbor`), the CSR or CEKpub (`subject.der`), the claims, and `meta.json` (the Target, the RRP identifier, the freshness element, the binding value, and which key signed the report) |
| `rrpverify-*.json`, `rrpverify-*.txt` | every check: the request (`case`), what was changed (`check`), what was expected (`want`), what happened (`got`), and whether that is as expected (`ok`); the `.txt` ends with the summary line |
| `rrpverify-*.stderr.log` | what the checker and the verifier it builds in logged; on SEV-SNP, Veraison's revocation check of each appraisal (`… is not on AMD's CRL …`) |
| `ears/` (SEV-SNP) | the Attestation Results the deployed Veraison issued for the honest Evidence (`<request>.ear.jws`) and the binding value each answers (`<request>.bv.hex`): what an RRP's platform rule reads, kept to check it again later |
| `rrp-clock-window.txt` | the RRP's clock before and after the guest made its reports, in seconds since 1970: the window timestamps are checked against |
| hardware: `amd-kds-*.pem` (SEV-SNP), `kernel.txt`, `dmesg-*.txt`, `vm-deleted.txt` | the vendor chain used, the guest's kernel and messages, the deletion record with its time |

The variant names in `rrpverify-*`: `sim` and `service` locally; on SEV-SNP `veraison-v015` (the bench's Veraison
build), `veraison-fixed`, `veraison-fork` and `service` (the deployed Veraison); `tdx` on TDX.

## `make redirect`: `…-<platform>-redirect`

| File | Holds |
|---|---|
| `results.jsonl` | one line per case: the pass (`with-rrp-id`, `no-rrp-id`), the Freshness Kind, the RRP offered the Evidence (`ca1`, `ca2`), and the `result` (issued or not, the HTTP status, the RRP's reason) |
| `with-rrp-id/`, `no-rrp-id/` | per pass: the Handles, the Targets, and each case's Evidence and request |

To check the binding of every Enrollment yourself, character by character, with no Go code involved:

```bash
python3 hwcheck/scripts/recompute-binding.py <run directory> sev-snp     # or tdx, sim
```

## `make check-mtls`: `…-bench-mtls-<model>`

`mtls.json` has one entry per check: the channel, the caller, the TLS version, what was expected and what happened.
`run.log` is the printed table.

## `make bank-…`: `…-demo-bank`

`README.md` is the bank's report, written by `make bank-down` from everything below it: the machines, the code, each
payment's steps and verdict, the server log lines for it, the endorsements, the ledger audit and the teardown.
`runs/<stamp>-<kind>/` holds each payment: `report.json` (the payment service's steps), `verdict.txt`,
`trust-logs/` and `core-logs/` (the servers' lines for that payment) and `vm-deleted.txt`.

## Comparing two runs

| Tool | Compares |
|---|---|
| `e2e/scripts/compare-e2e.py A/results.json B/results.json` | two end-to-end runs, Target by Target |
| `hwcheck/scripts/compare-rrpverify.py A.json B.json` | two attack runs, check by check |
| `hwcheck/scripts/compare-redirect.py [--ignore-platform] A/results.jsonl B/results.jsonl` | two redirect runs, case by case (`--ignore-platform` compares the stand-in with hardware) |
| `e2e/scripts/compare-mtls.py A/mtls.json B/mtls.json` | two mTLS checks |

Each prints what differs and exits 0 only when nothing does. Serial numbers, timings, nonces and other values that
change by nature are not compared.

## Reading the SEV-SNP reports of a run

The Attestation Results carry only some of the report's fields. For the rest, the reports an SEV-SNP hardware run
kept (`<step>/evidence.tsm.cbor`) can be read as go-sev-guest parses them: the report's version, POLICY, the launch
MEASUREMENT, PLATFORM_INFO, the reported, committed and launch TCBs, the CPUID, whether a CHIP_ID is present, and the
mitigation vectors with the bits each sets. Identical reports are printed once, with their count. (`GOWORK=off`: the
repository's `go.work` lists the proof of concept's modules, not `hwcheck`.)

```bash
cd hwcheck && GOWORK=off go run ./cmd/snpreport evidence/20261007T050654Z-gcp-sev-snp evidence/20261007T051142Z-aws-sev-snp
```
