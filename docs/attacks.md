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
| Clock moved (pre-play) | sets the guest's clock 300 s ahead and makes Evidence of every Freshness Kind, then 300 s behind and makes absent-timestamp Evidence; offers each at once, absent-timestamp's also at its window's edges | for `absent-timestamp`, nothing: the window bounds the age by the guest's clock | the four other kinds taken at once; `absent-timestamp` ahead refused at once, taken from 295 s to 420 s after it was made (300 s − `clock_skew` to 300 s + `max_age`) and refused after; behind, refused: an **exposure**, reported, not a pass ([limits.md](limits.md), "Time") |
| Forged report | a report that does not chain to the vendor's root: AMD's ASK as the anchor instead of the ARK; a root that is not Intel's | the vendor's root, pinned | refused |
| Unapproved launch | a launch whose measurement (SEV-SNP `MEASUREMENT`, TDX `MRTD`) differs by one byte | the approved launches (`trust/`) | refused |

Each attack must be refused **for its own reason**. A refusal that also refuses the honest request proves nothing and
is counted as "inconclusive", never as a pass. The run ends with its verdict, on SEV-SNP
`VERDICT PASS: 262 checks: the honest Evidence passed, every attack refused for its own reason; the honest Evidence
admitted under the bench's waiver: Milan bit 4: admitted without bit 4, AMD-SB-3034; exposure, the guest's clock: …`
([GCP SEV-SNP](../hwcheck/evidence/20261007T180531Z-gcp-sev-snp), the release check), and keeps every check in
`rrpverify-*.json` and the pre-play in `preplay.json` ([results.md](results.md)).

| Platform | Checks in process | Checks through the verifier service | The platform rule (below) |
|---|---|---|---|
| GCP SEV-SNP | 162 with the bench's Veraison build (each report as delivered and with its certificate table normalised) | 50 (the deployed Veraison) | 50 |
| GCP TDX | 82 (go-tdx-guest, Intel's collateral) | 50 (the deployed TDX verifier) | 30 |
| AWS SEV-SNP | 162 with the bench's Veraison build | 50 | 50 |

The run then applies the RRPs' platform rule to the honest Attestation Results it kept (`rrpverify-platform.json`,
`rrp/cmd/platform-check`): the bench's own rule admits them, on SEV-SNP Milan under its named waiver of AMD-SB-3034's
bit 4; a bank's rule, the same without waivers, refuses them for that bit; and the rule one step stricter than the
host, a TCB floor one above its value on SEV-SNP and the TD's own ATTRIBUTES refused on TDX, refuses them for that
reason. Each is a check of the run, judged with the others; the run keeps the rule (`platform-rule.json`), and a
SEV-SNP run's verdict names the waiver, as a demo's does.

On SEV-SNP the run also appraises the reports with two older builds of Veraison's scheme, to record what each fix
changes; their results are findings, not failures ([hardware/gcp-snp.md](hardware/gcp-snp.md),
[hardware/aws-snp.md](hardware/aws-snp.md)).

## 2. The conduit: Evidence redirected to another bank, and what it relays rewritten

```bash
make redirect                   # also PLATFORM=gcp-snp, gcp-tdx, aws-snp; PASSPORT=1 in Passport
```

The workload produces Evidence for a Target of the Credential Authority `ca1`; the attacker offers the same Evidence
to a second one, `ca2`, "another bank". With the RRP identifier in the binding, `ca2` refuses every Freshness Kind.
Without it, only a nonce `ca2` never issued stops it: the other four kinds are issued twice. In Passport
(`PASSPORT=1`) the conduit gets the Attestation Results for each Evidence from the verifier, as an honest CAS does for
`ca1`, and offers those. The table and how to read it: [getting-started.md](getting-started.md), step 9. The open
question it informs: [TACRA issue #20](https://github.com/TheBankster/rats-tacra/issues/20).

Then the conduit rewrites, one at a time, what it relays to `ca1` on Evidence made for `ca1`
([TACRA issue #19](https://github.com/TheBankster/rats-tacra/issues/19): which fields of attest-initiate travel, and
through whom):

| The conduit sends | What stops it | Outcome |
|---|---|---|
| a made-up Handle (present-nonce) | the RRP knows the Handles it minted | refused, `freshness` |
| the Freshness Kind `absent-none`, for a Target of another kind | the kind is the Target's, by the RRP's policy | refused, `freshness-kind-mismatch` |
| a credential type the Target does not offer | the Target's credential types | refused, `unsupported-credential-type` |
| another workload's Credential Hint | the Credential Authority names the attested workload itself | refused, `credential-hint` |
| the other credential type the Target offers | the present-nonce Handle, which the RRP minted for one Target and credential type; nothing else | present-nonce: refused, `freshness`; every other kind: issued, the CA's X.509, as without the rewrite |

The credential type is neither in the binding nor used by the Credential Authority, which issues its X.509 whatever
the field says; only a Handle the RRP minted for one credential type catches a rewritten one. Each rewrite's outcome
is a check of the run, which `scripts/verdict.py` judges against this table.

## 3. A component without the right identity

```bash
make check-mtls
```

Every channel inside the trust zone authenticates its caller (tacra-est requirement N23). The check calls each one as
every kind of caller: the right component, another component of the same root (the wrong role), a certificate with
the EST server's name from a CA the bench does not know, no certificate, and the right component limited to TLS 1.2.
Only the right component over TLS 1.3 gets through: 40 of 40 checks as expected
([architecture.md](architecture.md), who may call whom).

## 4. A machine that is not what it claims

| Attempt | How to run it | Expected result |
|---|---|---|
| genuine SEV-SNP hardware, a launch the bench has not approved (four vCPUs: GCP `n2d-standard-4`, AWS `c6a.xlarge`) | `UNAPPROVED=1 make demo PLATFORM=gcp-snp` (also `aws-snp`) | 0 of 10: each refused, `ear: not affirming: SEVSNP is "contraindicated"` ([GCP SEV-SNP](../e2e/evidence/20261007T140959Z-gcp-sev-snp-e2e-passport-unapproved), [AWS SEV-SNP](../e2e/evidence/20261007T141302Z-aws-sev-snp-e2e-passport-unapproved)) |
| the same in the Demo Bank | `make bank-pay PLATFORM=unapproved` | Veraison `contraindicated`: no credential |
| an ordinary VM, no TEE | `make bank-pay PLATFORM=ordinary` | no attestation, no credential; the ledger and the fraud service refuse it |
| a debuggable instance (its memory can be read from outside) | no cloud launches one | Veraison refuses it (our patch 0005; [limits.md](limits.md)) |

## 5. Evidence for one platform at a Target of another

A Target may take only one platform's verifier: `db-snp-only` takes Veraison alone, `db-tdx-only` the TDX verifier
alone. The Target's configuration chooses the verifier, never the Evidence: one half of tacra-est requirement N24
(the other half, the verifier's key held by the RRP as a file, is in [concepts.md](concepts.md)).

```bash
OTHER_PLATFORM=1 make demo PLATFORM=gcp-snp   # genuine SEV-SNP Evidence at db-tdx-only (also aws-snp)
OTHER_PLATFORM=1 make demo PLATFORM=gcp-tdx   # genuine TDX Evidence at db-snp-only
```

| RATS model | Expected result, at each Target |
|---|---|
| Passport | refused after appraisal: the platform's verifier affirms the Evidence, and the RRP finds `none of the verifiers this RRP takes for the Target (tdx) signed it` for SEV-SNP Evidence at `db-tdx-only` (`veraison` for TDX Evidence at `db-snp-only`) |
| Background Check | refused before appraisal: `none of the verifiers this RRP takes for the Target (veraison) appraises Evidence of provider "tdx_guest"` for TDX Evidence at `db-snp-only` |

Runs: [GCP SEV-SNP](../e2e/evidence/20261007T012220Z-gcp-sev-snp-e2e-passport-other-platform), [AWS SEV-SNP](../e2e/evidence/20261007T012516Z-aws-sev-snp-e2e-passport-other-platform), [GCP TDX](../e2e/evidence/20261007T012715Z-gcp-tdx-e2e-passport-other-platform), [GCP TDX, Background Check](../e2e/evidence/20261007T015243Z-gcp-tdx-e2e-background-check-other-platform). Before the
`make` command existed, it was run on 1 October 2026 with the reference implementation's client: genuine SEV-SNP
Evidence refused at `db-tdx-only` in Passport, genuine TDX Evidence at `db-snp-only` in Background Check
([e2e/RESULTS-mutual-tls-verifier-choice.md](../e2e/RESULTS-mutual-tls-verifier-choice.md)).

## 6. The conduit and the Retrieval container

In Retrieval the Vault seals the secret to the CEKpub the workload's Evidence binds, and the conduit carries the
container back. CEKpub is public, so anyone who saw it can seal a container to it; the CAI opens only a container the
Vault sealed for this request. The conduit of these drills is the workload's own CAS Client (`caapi-est -attack`):

```bash
CONDUIT_ATTACK=seal make demo PLATFORM=gcp-snp   # also swap, hint, hint-group; also aws-snp, gcp-tdx
```

| Drill | What the conduit does to each Retrieval | What stops it | Expected result |
|---|---|---|---|
| `seal` | returns a container it sealed itself to the workload's CEKpub, with its own keys: the Vault's container type and associated data, another secret. TACRA leaves the CAS Server the option of encrypting to CEKpub itself; this is that container | the container's origin: the CAI opens only what the Vault key it holds for the RRP sealed or signed | each Retrieval refused, `bundle: not signed by the trusted Vault key over this request's bundle` |
| `swap` | returns to each Retrieval after the first the Vault's container of the Retrieval before it | the container is the Vault's, but for another request: its associated data names another Target and freshness element, and its signature covers another CEKpub | the first admitted; each later one refused, `bundle: associated data does not name what the Evidence bound` |
| `hint` | asks the Vault with the Credential Hint of a workload the Target serves no group to | the Vault's policy: no credential group for that hint at the Target | each Retrieval refused by the Vault, `credential-hint` |
| `hint-group` | asks the Vault with the Credential Hint of another group the Target serves to the same launches (`audit.workload.tacra.example`, the bench pack's `other_groups`) | the Vault releases that group's secret, sealed to the workload's CEKpub with that hint in its associated data; nothing in the binding covers the hint, so only the CAI's check of the hint it asked for refuses it | each Retrieval refused by the CAI, `bundle: associated data does not name what the Evidence bound` |

Every Enrollment of these runs is admitted: the conduit acts on Retrievals only. Each run is judged by
`scripts/verdict.py conduit` from the workload's results and the conduit's own log line for each Retrieval it acted on.

What the drills leave to the unit tests of the container (`bundle/keptcek_test.go`, real keys, real sealing): which
check refuses a container meant for another request. With a new CEK for each Retrieval, as the CAI makes, it does
not open whatever its associated data says. With one CEK kept across Retrievals, the hpke-auth container's HPKE info
carries the RRP identifier and the freshness element but not the Target, so only the associated data's Target check
refuses another Target's container under a freshness element the Targets share; the hpke-base-signed container's
signature covers the Target and CEKpub, and refuses it without that check.
