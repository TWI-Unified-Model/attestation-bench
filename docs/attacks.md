# Attacks

What the bench tries against TACRA, what stops each attempt, and how to run it yourself. The terms are in
[concepts.md](concepts.md).

## Who the attacker is

The attacker controls everything between the workload and the RRP: the CAS Client, the EST server and the network.
They can change, replay or redirect any request, and they can run VMs of their own, on genuine confidential hardware
or not. They do not control the workload's TEE, the trust zone (the RRPs, the verifiers, step-ca, Vault), or the
hardware vendors' and Google's roots. What lies outside this model is in [limits.md](limits.md).

## 1. Changing one input of a request

```bash
make attacks                    # the software stand-in TEE
make attacks PLATFORM=gcp-snp   # also gcp-tdx, aws-snp
```

The RRP mints the Freshness Handles, the workload produces Evidence for each of the ten requests (the five Freshness
Kinds, for Enrollment and for Retrieval), and the RRP's checks run first on the honest request, then on the same
request with one input changed, as the attacker could change it:

| Attack | What the attacker does | What stops it | Expected result |
|---|---|---|---|
| Target substitution | asks for another Target with the same Evidence | the Target is in the binding | refused: the binding does not match |
| Redirection | sends the Evidence to another RRP (another RRP identifier) | the RRP identifier is in the binding | refused: the binding does not match |
| Key substitution | swaps the CSR (Enrollment) or CEKpub (Retrieval) for their own | the CSR or CEKpub is in the binding | refused: the binding does not match |
| Replay, stale freshness | uses another freshness element: an old or foreign Handle, another epoch | the freshness element is in the binding; the RRP knows its Handles and its epoch | refused |
| Old timestamp | for `absent-timestamp`, a timestamp an hour outside the window | the RRP's window around its own clock | refused |
| Forged report | a report that does not chain to the vendor's root: AMD's ASK as the anchor instead of the ARK; a root that is not Intel's; for the stand-in, another key | the vendor's root, pinned | refused |
| Unapproved launch | a launch whose measurement (SEV-SNP `MEASUREMENT`, TDX `MRTD`) differs by one byte | the approved launches (`trust/`) | refused |

Each attack must be refused **for its own reason**. A refusal that also refuses the honest request proves nothing and
is counted as "inconclusive", never as a pass. The run ends with `every attack refused for its own reason, every
honest check passed`, and keeps every check in `rrpverify-*.json` ([results.md](results.md)).

| Platform | Checks in process | Checks through the verifier service |
|---|---|---|
| stand-in | 82 | 50 (the stand-in's verifier) |
| GCP SEV-SNP | 162 with the bench's Veraison build (each report as delivered and with its certificate table normalised) | 50 (the deployed Veraison) |
| GCP TDX | 82 (the TDX verifier's checks) | |
| AWS SEV-SNP | 162 with the bench's Veraison build | 50 |

On SEV-SNP the run also appraises the reports with two older builds of Veraison's scheme, to record what each fix
changes; their results are findings, not failures ([hardware/gcp-snp.md](hardware/gcp-snp.md),
[hardware/aws-snp.md](hardware/aws-snp.md)).

## 2. Redirecting Evidence to another bank

```bash
make redirect                   # also PLATFORM=gcp-snp, gcp-tdx, aws-snp
```

The workload produces Evidence for a Target of the Credential Authority `ca1`; the attacker offers the same Evidence
to a second one, `ca2`, "another bank". With the RRP identifier in the binding, `ca2` refuses every Freshness Kind.
Without it, only a nonce `ca2` never issued stops it: the other four kinds are issued twice. The table and how to read
it: [getting-started.md](getting-started.md), step 9. The open question it informs:
[TACRA issue #20](https://github.com/TheBankster/rats-tacra/issues/20).

## 3. A component without the right identity

```bash
make check-mtls
```

Every channel inside the trust zone authenticates its caller (tacra-est requirement N23). The check calls each one as
every kind of caller: the right component, another component of the same root (the wrong role), a certificate with
the EST server's name from a CA the bench does not know, no certificate, and the right component limited to TLS 1.2.
Only the right component over TLS 1.3 gets through: 47 of 47 checks as expected
([architecture.md](architecture.md), who may call whom).

## 4. A machine that is not what it claims

| Attempt | How to run it | Expected result |
|---|---|---|
| a debuggable instance (its memory can be read from outside) | `SIM_DEBUG=1 make demo` | 0 of 10: refused, "the instance is debuggable" |
| a workload that is not the approved one | `SIM_LABEL="other workload" make demo` | 0 of 10: refused, its measurement matches no reference value |
| an ordinary VM, no TEE | `make bank-pay PLATFORM=ordinary` | no attestation, no credential; the ledger and the fraud service refuse it |
| genuine SEV-SNP hardware, a launch the bank has not approved | `make bank-pay PLATFORM=unapproved` | Veraison `contraindicated`: no credential |

## 5. Evidence for one platform at a Target of another

A Target may take only one platform's verifier: `db-snp-only` takes Veraison alone, `db-tdx-only` the TDX verifier
alone (tacra-est requirement N24). Evidence of the other platform is refused there, before or after appraisal. This
was run on 1 October 2026 with the reference implementation's client against the bench
([e2e/RESULTS-mutual-tls-verifier-choice.md](../e2e/RESULTS-mutual-tls-verifier-choice.md)); no `make` target runs it
yet.

## 6. The software stand-in in production

The stand-in TEE gives no security, so an RRP must never take its results. The gateways refuse an EAR whose
submodule is `SIM` unless their configuration says `allow_simulated_tee`, which only the local bench's does
(`rrp/internal/gateway`, with a test), and they refuse a submodule they have no rule for.
