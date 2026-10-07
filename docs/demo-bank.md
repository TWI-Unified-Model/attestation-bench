# The Demo Bank

A fictional bank built in your cloud to run TACRA the way a bank would. Its payment service runs in a confidential VM
and holds no credential of its own: it gets its database certificate and its partner's API key only by attestation,
then moves money. Two controls show what happens without that. Every name, account and amount is made up.

```bash
make bank-up                          # the trust zone and the core, in your Google Cloud project
make bank-pay PLATFORM=gcp-snp        # a payment from a confidential VM; also gcp-tdx, aws-snp
make bank-pay PLATFORM=ordinary       # the same service on an ordinary VM: refused
make bank-pay PLATFORM=unapproved     # a genuine SEV-SNP VM of a launch the bank has not approved: refused
make bank-audit                       # the ledger's own record of who moved money
make bank-down                        # deletes everything, checks both clouds, writes the bank's report
```

## The bank

| Part | Where | What |
|---|---|---|
| Trust zone | a Google Cloud SEV-SNP VM, `n2d-standard-4` | the bench's trust zone: Veraison, step-ca, Vault, the Credential Authority and Secret Vault gateways, the TDX verifier, and the EST server, the one port the payment service reaches |
| Core | an ordinary Google Cloud VM, `e2-standard-2` | the ledger (PostgreSQL; the payment service's role logs in only with a client certificate from the bank's workload CA) and a fraud-scoring service (a partner API that admits a pre-shared API key) |
| Payment service | one VM per payment, deleted after it | `payments`: the CAI with the platform's plug-in |

The trust zone is configured by the bench's own program from the bank's pack, `packs/demo-bank/pack.json`, so it
works as the local bench does: mutual TLS between its components, the verifiers' keys given to the gateways as files,
the API key released in the signed container. Its approved launches start as `trust/approved-launches.json`.

A payment: the service acquires the ledger certificate (Enrollment) and the fraud service's API key (Retrieval),
asks the fraud service to score the transfer with the key, and moves 125.50 from one account to the other in one
database transaction, logged in with the certificate.

## What you need

- Everything [hardware/gcp-snp.md](hardware/gcp-snp.md) needs, with quota for the trust zone (4 N2D vCPUs), the core
  (2 E2 vCPUs) and one payment VM at a time.
- For `PLATFORM=aws-snp` only: what [hardware/aws-snp.md](hardware/aws-snp.md) needs. The bank opens the trust zone's
  EST port to that one AWS instance with a firewall rule, deleted with it.
- Nothing has to run on your machine: it only builds the programs, creates the VMs and collects the evidence.

## What to expect

`make bank-up` builds the programs, checks Google's endorsement of each approved launch, creates the two VMs, builds
Veraison on the trust zone and starts everything. In the reference run of 28 September 2026 the first payment began
14 minutes after `bank-up` started (`e2e/evidence/20260928T212732Z-demo-bank`).

Each `make bank-pay` creates its VM, runs the payment service, deletes the VM and prints a verdict:

| `PLATFORM` | Verdict when everything works |
|---|---|
| `gcp-snp`, `gcp-tdx`, `aws-snp` | `PASS: the payment went through, with credentials acquired by attestation` |
| `ordinary` | `PASS: no attestation, no credential; the ledger and the fraud service refused it` |
| `unapproved` | `PASS: genuine hardware evidence, unapproved launch: no credential issued` |

The reference run of 6 October 2026 had all five ([e2e/evidence/20261006T230714Z-demo-bank](../e2e/evidence/20261006T230714Z-demo-bank/README.md)):
three transfers, each logged in with its own certificate, and both controls refused.

`make bank-down` deletes every VM labelled `purpose=demo-bank` and every `demobank-*` firewall rule, counts what is left
in both clouds, and writes the bank's report, `README.md` in its run directory.

## Approving a new TDX firmware build

Google runs more than one TDX firmware build. A payment VM that starts on a build the bank has not approved is
refused. To approve one, only after Google's signed endorsement checks out:

```bash
e2e/bank/demo-bank.sh approve tdx <MRTD, 96 hex digits>
```

The command checks the endorsement against Google's pinned root, adds the build to the bank's approved launches, and
has the trust zone apply them. A new SEV-SNP launch needs a reference value for Veraison as well, so it is approved in
`trust/` instead ([../trust/README.md](../trust/README.md)).

## Making it your own bank

The bank's Targets, names, RRP identifiers and policy are data: edit `packs/demo-bank/pack.json`
([../packs/README.md](../packs/README.md)), then `make bank-up`. The payment service uses the pack's Credential
Authority Target for the ledger and its Secret Vault Target for the fraud service's key.

To run the bank in Background Check: `RATS_MODEL=background-check make bank-up`.

## If something fails

- `make bank-up` stopped: fix the cause, then `e2e/bank/demo-bank.sh provision` continues on the same VMs (every step
  is safe to repeat).
- Interrupted, or not sure everything is gone: `make bank-down`, then `make cloud-check`.
