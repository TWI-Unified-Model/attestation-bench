# The RRP identifier in the binding: both ways, measured on the same events

8 October 2026, for [TACRA issue #20](https://github.com/TheBankster/rats-tacra/issues/20). Every number below is a
run kept in this repository, named where it is stated; `make check` holds each of them (`scripts/tests/test_verdict.py`).

**11 October 2026.** The group's decision of 6 October, to leave the identifier out until the threat model is agreed,
is now the code, and on 11 October Mark Novak asked for it all to go: the EST server of the group's repository binds the
freshness element, the Target and the subject and carries no RRP or server identifier anywhere (TWI-Unified-Model/globalsign-est#4,
commit `b531556`; EST patch 0018 here), and this bench does the same, with no switch left (section 8).

## 1. The question

Section 4.5 of TACRA binds the Evidence to the freshness element, the Target, the RRP identifier the CAI holds, and the
subject (the CSR or CEKpub). Issue #20 asks whether the identifier belongs there. This report measures the protocol with the identifier in the binding and without it, on the same events: the same
demos, substitutions, second offers, container drills and redirections, on GCP SEV-SNP, AWS SEV-SNP and GCP TDX, in
Background Check and in Passport.

## 2. How "without it" was run (8 October 2026)

On the code of 8 October, `OMIT_RRP_ID=1 make config && make start` configured the whole trust zone to bind no identifier,
end to end (the switch exists no more: since 12 October the code binds none, section 8):

- the workload's CAI leaves the identifier out of the binding (`cai.WithoutRelyingPartyBinding`); the identifiers it
  holds still name the Credential Authority's and the Vault's trust anchors;
- the EST server, the CAS Server of the bench, computes its Passport session nonce for the Verifier without it
  (`third_party/globalsign-est`, patch 0015);
- the RRPs, the Credential Authority and the Secret Vault gateways, recompute the binding without it
  (`omit_rrp_id_in_binding`).

The runs end in `-no-rrp-id`. The runs with the identifier are the bench's reference runs: the demos and the attacks of
8 October, the container drills of 8 October, the redirection runs of 6–8 October; each run names the commit it ran
from (`code-rev.txt`). The verifiers are the same on both sides: Veraison v0.15.0 with AMD's roots, in-process
and as the deployed service, and the TDX verifier; two further Veraison builds the bench compares with are reported,
not judged ([docs/verification.md](verification.md)).

## 3. Results

| What was measured | With the identifier | Without it |
|---|---|---|
| 1. The full exchange: 10 Targets, both RATS models, three platforms | 12 runs, 10 of 10 Targets each | 6 runs, 10 of 10 each |
| 2. Substitution by the conduit of one input of a request (another Target; another CSR or CEKpub; another freshness element), 10 requests per run (5 Freshness Kinds × Enrollment, Retrieval) | 3 runs (262, 262, 162 checks): every substitution refused; a substituted identifier refused too, 10 of 10 per run | 3 runs (232, 232, 142): every substitution refused; 30 checks fewer per SEV-SNP run and 20 per TDX run, the identifier case having nothing to substitute |
| 3. The same request offered twice to the same RRP (the CA; the Vault) | 12 runs, both passes in each: present-nonce refused (the Handle is used up); present-epoch, absent-epoch, absent-timestamp, absent-none issued or released twice | the same, in the same runs |
| 4. The Retrieval container: sealed by the conduit; swapped with the previous one; another workload's Hint; another group's Hint | 12 runs | 12 runs, the same verdicts word for word |
| 5. Redirection: Evidence made for one RRP offered to a second that trusts the same Verifier and serves a Target of the same name | 27 runs: the second RRP refused all 5 Freshness Kinds in every regime, including the two Handles it minted itself when the conduit started the exchange there | the same 27 runs: with a shared epoch marker, issued (CA, 9 runs) or released (Vault, 6 runs) for 4 of 5 kinds, all but present-nonce; with an epoch marker of the second RRP's own, 2 of 5 (absent-timestamp, absent-none; 6 runs); with the conduit starting the exchange at the second RRP, 4 of 5, all but absent-epoch, present-nonce included (6 runs) |

So the identifier changes one row, the fifth. Rows 1–4 are the same without it: 33 runs against the same runs with it.

### 3.1 The full exchange (row 1)

Each run: ten Targets of the fictional bank, Enrollment at the Credential Authority and Retrieval at the Secret Vault,
every Freshness Kind among them, each credential then used at the relying party; the verdict names each Target. With
the identifier:

- [20261008T134108Z-gcp-sev-snp-e2e-passport](../e2e/evidence/20261008T134108Z-gcp-sev-snp-e2e-passport) — GCP SEV-SNP, Passport
- [20261008T134423Z-aws-sev-snp-e2e-passport](../e2e/evidence/20261008T134423Z-aws-sev-snp-e2e-passport) — AWS SEV-SNP, Passport
- [20261008T134640Z-gcp-tdx-e2e-passport](../e2e/evidence/20261008T134640Z-gcp-tdx-e2e-passport) — GCP TDX, Passport
- [20261008T134939Z-gcp-sev-snp-e2e-background-check](../e2e/evidence/20261008T134939Z-gcp-sev-snp-e2e-background-check) — GCP SEV-SNP, Background Check
- [20261008T135240Z-aws-sev-snp-e2e-background-check](../e2e/evidence/20261008T135240Z-aws-sev-snp-e2e-background-check) — AWS SEV-SNP, Background Check
- [20261008T135441Z-gcp-tdx-e2e-background-check](../e2e/evidence/20261008T135441Z-gcp-tdx-e2e-background-check) — GCP TDX, Background Check
- [20261008T153259Z-gcp-sev-snp-e2e-passport](../e2e/evidence/20261008T153259Z-gcp-sev-snp-e2e-passport) — GCP SEV-SNP, Passport
- [20261008T153608Z-aws-sev-snp-e2e-passport](../e2e/evidence/20261008T153608Z-aws-sev-snp-e2e-passport) — AWS SEV-SNP, Passport
- [20261008T153811Z-gcp-tdx-e2e-passport](../e2e/evidence/20261008T153811Z-gcp-tdx-e2e-passport) — GCP TDX, Passport
- [20261008T154103Z-gcp-sev-snp-e2e-background-check](../e2e/evidence/20261008T154103Z-gcp-sev-snp-e2e-background-check) — GCP SEV-SNP, Background Check
- [20261008T154400Z-aws-sev-snp-e2e-background-check](../e2e/evidence/20261008T154400Z-aws-sev-snp-e2e-background-check) — AWS SEV-SNP, Background Check
- [20261008T154603Z-gcp-tdx-e2e-background-check](../e2e/evidence/20261008T154603Z-gcp-tdx-e2e-background-check) — GCP TDX, Background Check

Without it:

- [20261008T202206Z-gcp-sev-snp-e2e-passport-no-rrp-id](../e2e/evidence/20261008T202206Z-gcp-sev-snp-e2e-passport-no-rrp-id) — GCP SEV-SNP, Passport
- [20261008T202505Z-aws-sev-snp-e2e-passport-no-rrp-id](../e2e/evidence/20261008T202505Z-aws-sev-snp-e2e-passport-no-rrp-id) — AWS SEV-SNP, Passport
- [20261008T202708Z-gcp-tdx-e2e-passport-no-rrp-id](../e2e/evidence/20261008T202708Z-gcp-tdx-e2e-passport-no-rrp-id) — GCP TDX, Passport
- [20261008T215102Z-gcp-sev-snp-e2e-background-check-no-rrp-id](../e2e/evidence/20261008T215102Z-gcp-sev-snp-e2e-background-check-no-rrp-id) — GCP SEV-SNP, Background Check
- [20261008T215357Z-aws-sev-snp-e2e-background-check-no-rrp-id](../e2e/evidence/20261008T215357Z-aws-sev-snp-e2e-background-check-no-rrp-id) — AWS SEV-SNP, Background Check
- [20261008T215602Z-gcp-tdx-e2e-background-check-no-rrp-id](../e2e/evidence/20261008T215602Z-gcp-tdx-e2e-background-check-no-rrp-id) — GCP TDX, Background Check

### 3.2 Substitution (row 2)

The guest makes ten honest requests (5 Freshness Kinds × Enrollment, Retrieval); for each, the conduit's substitutions
are appraised twice: by the deployed Veraison, given the recomputed binding value as the session nonce (the service
path), and in-process, with the same checks and more (the forged trust anchor, the launch whose measurement differs by
one byte, the timestamp outside the window). Every row of the service path came out as its case expects:

| Run | Checks | Service path (deployed Veraison): rows | In-process appraisal: rows (file) |
|---|---|---|---|
| [20261008T154907Z-gcp-sev-snp](../hwcheck/evidence/20261008T154907Z-gcp-sev-snp) (with) | 262 | 50: honest 10, other Target 10, other CSR / CEKpub 10, other freshness element 10, other RRP identifier 10 | 162 (`rrpverify-veraison-v015.json`) |
| [20261008T155945Z-aws-sev-snp](../hwcheck/evidence/20261008T155945Z-aws-sev-snp) (with) | 262 | 50: honest 10, other Target 10, other CSR / CEKpub 10, other freshness element 10, other RRP identifier 10 | 162 (`rrpverify-veraison-v015.json`) |
| [20261008T160809Z-gcp-tdx](../hwcheck/evidence/20261008T160809Z-gcp-tdx) (with) | 162 | 50: honest 10, other Target 10, other CSR / CEKpub 10, other freshness element 10, other RRP identifier 10 | 82 (`rrpverify-tdx.json`) |
| [20261008T205230Z-gcp-sev-snp-no-rrp-id](../hwcheck/evidence/20261008T205230Z-gcp-sev-snp-no-rrp-id) (without) | 232 | 40: honest 10, other Target 10, other CSR / CEKpub 10, other freshness element 10 | 142 (`rrpverify-veraison-v015.json`) |
| [20261008T220040Z-aws-sev-snp-no-rrp-id](../hwcheck/evidence/20261008T220040Z-aws-sev-snp-no-rrp-id) (without) | 232 | 40: honest 10, other Target 10, other CSR / CEKpub 10, other freshness element 10 | 142 (`rrpverify-veraison-v015.json`) |
| [20261008T211132Z-gcp-tdx-no-rrp-id](../hwcheck/evidence/20261008T211132Z-gcp-tdx-no-rrp-id) (without) | 142 | 40: honest 10, other Target 10, other CSR / CEKpub 10, other freshness element 10 | 72 (`rrpverify-tdx.json`) |

The in-process cases on SEV-SNP (rows per case, `rrpverify-veraison-v015.json`), with the identifier and without:

| Case | With | Without |
|---|---|---|
| appraise: MEASUREMENT one byte different | 20 | 20 |
| appraise: reference values of this launch | 20 | 20 |
| honest | 20 | 20 |
| other CSR / CEKpub | 20 | 20 |
| other RRP identifier | 20 | 0 |
| other Target | 20 | 20 |
| other freshness element | 20 | 20 |
| timestamp an hour outside the window | 2 | 2 |
| trust anchor = ASK, not ARK | 20 | 20 |

On TDX (`rrpverify-tdx.json`): 82 rows with the identifier, 72 without; the one case that differs is the substituted identifier (10 rows), absent without it. The platform rule's checks and the pre-play of the guest's clock, also part of each run's verdict, are unchanged.

### 3.3 The same request twice (row 3)

The conduit holds every request it carried and offers it a second time to the RRP it was made for; each run makes the
pass with the identifier bound and the pass without it. Two verdict texts, one per RRP kind:

- "VERDICT PASS: the same request twice at ca1: the second offer with present-nonce refused for the Handle; with present-epoch, absent-epoch, absent-timestamp and absent-none the credential issued twice, with the RRP identifier bound and without it alike"
  - [20261008T194057Z-gcp-snp-redirect-replay](../hwcheck/evidence/20261008T194057Z-gcp-snp-redirect-replay)
  - [20261008T194502Z-gcp-snp-redirect-passport-replay](../hwcheck/evidence/20261008T194502Z-gcp-snp-redirect-passport-replay)
  - [20261008T195636Z-aws-snp-redirect-replay](../hwcheck/evidence/20261008T195636Z-aws-snp-redirect-replay)
  - [20261008T195930Z-aws-snp-redirect-passport-replay](../hwcheck/evidence/20261008T195930Z-aws-snp-redirect-passport-replay)
  - [20261008T200806Z-gcp-tdx-redirect-replay](../hwcheck/evidence/20261008T200806Z-gcp-tdx-redirect-replay)
  - [20261008T201133Z-gcp-tdx-redirect-passport-replay](../hwcheck/evidence/20261008T201133Z-gcp-tdx-redirect-passport-replay)
- "VERDICT PASS: the same request twice at vault1: the second offer with present-nonce refused for the Handle; with present-epoch, absent-epoch, absent-timestamp and absent-none the credential released twice, with the RRP identifier bound and without it alike"
  - [20261008T194859Z-gcp-snp-redirect-replay-vault](../hwcheck/evidence/20261008T194859Z-gcp-snp-redirect-replay-vault)
  - [20261008T195250Z-gcp-snp-redirect-passport-replay-vault](../hwcheck/evidence/20261008T195250Z-gcp-snp-redirect-passport-replay-vault)
  - [20261008T200229Z-aws-snp-redirect-replay-vault](../hwcheck/evidence/20261008T200229Z-aws-snp-redirect-replay-vault)
  - [20261008T200516Z-aws-snp-redirect-passport-replay-vault](../hwcheck/evidence/20261008T200516Z-aws-snp-redirect-passport-replay-vault)
  - [20261008T201457Z-gcp-tdx-redirect-replay-vault](../hwcheck/evidence/20261008T201457Z-gcp-tdx-redirect-replay-vault)
  - [20261008T201816Z-gcp-tdx-redirect-passport-replay-vault](../hwcheck/evidence/20261008T201816Z-gcp-tdx-redirect-passport-replay-vault)

### 3.4 The Retrieval container (row 4)

The four drills, each on the three platforms, with the identifier (12 runs) and without (12 runs); the verdict of each
kind is the same text on both sides:

- `seal`: "VERDICT PASS: 5 Retrievals given the conduit's own container, each refused by the CAI for its origin; the 5 other Targets admitted"
- `swap`: "VERDICT PASS: the first Retrieval admitted with its own container; 4 given the container of the one before, each refused by the CAI for its associated data; the 5 other Targets admitted"
- `hint`: "VERDICT PASS: 5 Retrievals asked with the Credential Hint of a workload the Target serves no group to, each refused by the Vault; the 5 other Targets admitted"
- `hint-group`: "VERDICT PASS: 5 Retrievals asked with the Credential Hint of another group the Target serves to the same launches: the Vault released that group's secret, and the CAI refused each for its associated data; the 5 other Targets admitted"

With the identifier: [GCP SEV-SNP, seal](../e2e/evidence/20261008T003630Z-gcp-sev-snp-e2e-passport-conduit-seal); [AWS SEV-SNP, seal](../e2e/evidence/20261008T003924Z-aws-sev-snp-e2e-passport-conduit-seal); [GCP TDX, seal](../e2e/evidence/20261008T004125Z-gcp-tdx-e2e-passport-conduit-seal); [GCP SEV-SNP, swap](../e2e/evidence/20261008T004403Z-gcp-sev-snp-e2e-passport-conduit-swap); [AWS SEV-SNP, swap](../e2e/evidence/20261008T004710Z-aws-sev-snp-e2e-passport-conduit-swap); [GCP TDX, swap](../e2e/evidence/20261008T004908Z-gcp-tdx-e2e-passport-conduit-swap); [GCP SEV-SNP, hint](../e2e/evidence/20261008T005144Z-gcp-sev-snp-e2e-passport-conduit-hint); [AWS SEV-SNP, hint](../e2e/evidence/20261008T005438Z-aws-sev-snp-e2e-passport-conduit-hint); [GCP TDX, hint](../e2e/evidence/20261008T005645Z-gcp-tdx-e2e-passport-conduit-hint); [GCP SEV-SNP, hint-group](../e2e/evidence/20261008T005910Z-gcp-sev-snp-e2e-passport-conduit-hint-group); [AWS SEV-SNP, hint-group](../e2e/evidence/20261008T010204Z-aws-sev-snp-e2e-passport-conduit-hint-group); [GCP TDX, hint-group](../e2e/evidence/20261008T010403Z-gcp-tdx-e2e-passport-conduit-hint-group).

Without it: [GCP SEV-SNP, seal](../e2e/evidence/20261008T212014Z-gcp-sev-snp-e2e-passport-no-rrp-id-conduit-seal); [AWS SEV-SNP, seal](../e2e/evidence/20261008T212315Z-aws-sev-snp-e2e-passport-no-rrp-id-conduit-seal); [GCP TDX, seal](../e2e/evidence/20261008T212519Z-gcp-tdx-e2e-passport-no-rrp-id-conduit-seal); [GCP SEV-SNP, swap](../e2e/evidence/20261008T212753Z-gcp-sev-snp-e2e-passport-no-rrp-id-conduit-swap); [AWS SEV-SNP, swap](../e2e/evidence/20261008T213051Z-aws-sev-snp-e2e-passport-no-rrp-id-conduit-swap); [GCP TDX, swap](../e2e/evidence/20261008T213253Z-gcp-tdx-e2e-passport-no-rrp-id-conduit-swap); [GCP SEV-SNP, hint](../e2e/evidence/20261008T213537Z-gcp-sev-snp-e2e-passport-no-rrp-id-conduit-hint); [AWS SEV-SNP, hint](../e2e/evidence/20261008T213840Z-aws-sev-snp-e2e-passport-no-rrp-id-conduit-hint); [GCP TDX, hint](../e2e/evidence/20261008T214046Z-gcp-tdx-e2e-passport-no-rrp-id-conduit-hint); [GCP SEV-SNP, hint-group](../e2e/evidence/20261008T214316Z-gcp-sev-snp-e2e-passport-no-rrp-id-conduit-hint-group); [AWS SEV-SNP, hint-group](../e2e/evidence/20261008T214614Z-aws-sev-snp-e2e-passport-no-rrp-id-conduit-hint-group); [GCP TDX, hint-group](../e2e/evidence/20261008T214815Z-gcp-tdx-e2e-passport-no-rrp-id-conduit-hint-group).

### 3.5 Redirection (row 5)

Evidence made for the first RRP is offered to a second that trusts the same Verifier and serves a Target of the same
name; each run measures both the pass with the identifier bound and the pass without it, for every Freshness Kind; the
verdict names each outcome and the reason of each refusal ([docs/attacks.md](attacks.md), section 2). The five verdict
texts, by regime:

- "VERDICT PASS: with the RRP identifier, ca2 refused all 5 Freshness Kinds; without it, all but present-nonce"
  - [20261006T225552Z-gcp-snp-redirect](../hwcheck/evidence/20261006T225552Z-gcp-snp-redirect)
  - [20261006T225943Z-gcp-tdx-redirect](../hwcheck/evidence/20261006T225943Z-gcp-tdx-redirect)
  - [20261006T230316Z-aws-snp-redirect](../hwcheck/evidence/20261006T230316Z-aws-snp-redirect)
- "VERDICT PASS: with the RRP identifier, ca2 refused all 5 Freshness Kinds; without it, all but present-nonce; of the conduit's 20 rewrites at ca1, the other credential type the Target offers was issued for every kind but present-nonce, and every other was refused for its own reason"
  - [20261007T204444Z-gcp-snp-redirect](../hwcheck/evidence/20261007T204444Z-gcp-snp-redirect)
  - [20261007T204937Z-gcp-tdx-redirect](../hwcheck/evidence/20261007T204937Z-gcp-tdx-redirect)
  - [20261007T205428Z-aws-snp-redirect](../hwcheck/evidence/20261007T205428Z-aws-snp-redirect)
  - [20261007T205826Z-gcp-snp-redirect-passport](../hwcheck/evidence/20261007T205826Z-gcp-snp-redirect-passport)
  - [20261007T210314Z-gcp-tdx-redirect-passport](../hwcheck/evidence/20261007T210314Z-gcp-tdx-redirect-passport)
  - [20261007T210728Z-aws-snp-redirect-passport](../hwcheck/evidence/20261007T210728Z-aws-snp-redirect-passport)
- "VERDICT PASS: ca2 with an epoch marker of its own: with the RRP identifier, ca2 refused all 5 Freshness Kinds; without it, it issued for absent-timestamp and absent-none alone, refusing present-nonce for the Handle and present-epoch and absent-epoch for the epoch marker"
  - [20261008T031349Z-gcp-snp-redirect-own-epochs](../hwcheck/evidence/20261008T031349Z-gcp-snp-redirect-own-epochs)
  - [20261008T032215Z-gcp-snp-redirect-passport-own-epochs](../hwcheck/evidence/20261008T032215Z-gcp-snp-redirect-passport-own-epochs)
  - [20261008T032611Z-gcp-tdx-redirect-own-epochs](../hwcheck/evidence/20261008T032611Z-gcp-tdx-redirect-own-epochs)
  - [20261008T032934Z-gcp-tdx-redirect-passport-own-epochs](../hwcheck/evidence/20261008T032934Z-gcp-tdx-redirect-passport-own-epochs)
  - [20261008T033255Z-aws-snp-redirect-own-epochs](../hwcheck/evidence/20261008T033255Z-aws-snp-redirect-own-epochs)
  - [20261008T033608Z-aws-snp-redirect-passport-own-epochs](../hwcheck/evidence/20261008T033608Z-aws-snp-redirect-passport-own-epochs)
- "VERDICT PASS: the conduit starting at ca2: with the RRP identifier, ca2 refused all 5 Freshness Kinds, the two whose Handles it minted itself for the binding; without it, ca2 issued for every kind but absent-epoch, whose marker the Attester holds, present-nonce included"
  - [20261008T031807Z-gcp-snp-redirect-start-ca2](../hwcheck/evidence/20261008T031807Z-gcp-snp-redirect-start-ca2)
  - [20261008T033907Z-gcp-snp-redirect-passport-start-ca2](../hwcheck/evidence/20261008T033907Z-gcp-snp-redirect-passport-start-ca2)
  - [20261008T034309Z-gcp-tdx-redirect-start-ca2](../hwcheck/evidence/20261008T034309Z-gcp-tdx-redirect-start-ca2)
  - [20261008T034636Z-gcp-tdx-redirect-passport-start-ca2](../hwcheck/evidence/20261008T034636Z-gcp-tdx-redirect-passport-start-ca2)
  - [20261008T035017Z-aws-snp-redirect-start-ca2](../hwcheck/evidence/20261008T035017Z-aws-snp-redirect-start-ca2)
  - [20261008T035308Z-aws-snp-redirect-passport-start-ca2](../hwcheck/evidence/20261008T035308Z-aws-snp-redirect-passport-start-ca2)
- "VERDICT PASS: the Secret Vaults: with the RRP identifier, vault2 refused all 5 Freshness Kinds; without it, it released the workload's group's key for every kind but present-nonce"
  - [20261008T041327Z-gcp-snp-redirect-vault](../hwcheck/evidence/20261008T041327Z-gcp-snp-redirect-vault)
  - [20261008T041741Z-gcp-snp-redirect-passport-vault](../hwcheck/evidence/20261008T041741Z-gcp-snp-redirect-passport-vault)
  - [20261008T042128Z-gcp-tdx-redirect-vault](../hwcheck/evidence/20261008T042128Z-gcp-tdx-redirect-vault)
  - [20261008T042456Z-gcp-tdx-redirect-passport-vault](../hwcheck/evidence/20261008T042456Z-gcp-tdx-redirect-passport-vault)
  - [20261008T042814Z-aws-snp-redirect-vault](../hwcheck/evidence/20261008T042814Z-aws-snp-redirect-vault)
  - [20261008T043101Z-aws-snp-redirect-passport-vault](../hwcheck/evidence/20261008T043101Z-aws-snp-redirect-passport-vault)

## 4. What the identifier buys, and what it costs

(a) Bound, as 4.5 stands: the deployment decides, through the CAI's configuration, which RRP serves each Target, for
all five Freshness Kinds, whoever starts the exchange. The cost is configuration in two places: the CAI, per Target and
per mode (Enrollment's CA, Retrieval's Vault); and, in Passport, the CAS Server, which computes the Verifier's session
nonce from the binding's inputs and so has to hold the same string the CAI bound — any difference is refused exactly as
the substituted identifier is (row 2). In Background Check the RRP recomputes the binding itself and needs nothing
new. Nothing travels on the wire either way.

(b) Left out: which RRP serves the Attester, among the RRPs that trust the same Verifier and serve the Target's name,
is the CAS Server's choice; and one Evidence can serve two RRPs for every kind but present-nonce when they share an
epoch marker. What the second RRP issues or releases is bound to the Attester's keys — the certificate to CSKpub, the
container sealed to CEKpub (row 4) — so the CAS Server obtains nothing it can use. What exists is a second credential
or release the deployment did not intend, which a deployment that counts or audits them has to know about.
present-nonce limits one Evidence to the RRP that minted the Handle, but that RRP is the one the CAS Server went to
first (row 5, the third regime).

## 5. Weighing, and the text that follows

In TACRA's model the CAS is the deployment's own, untrusted for integrity, and it is the CAS Server that selects the
Verifier and the RRP. Row 5 without the identifier is the CAS Server choosing among the deployment's own RRPs, which
it does in any case; the integrity of what is issued (rows 1–4) does not depend on the identifier; and the identifier's
cost is a configuration coupling between the CAI and the CAS Server that the protocol otherwise does not have. That is
how the data reads. If the identifier is left out, three sentences in the text follow from it:

1. Section 4.5: the binding is the freshness element, the Target and the subject (CSR or CEKpub); the CAS Server's
   Passport session nonce is computed from the same inputs.
2. Security Considerations: which RRP serves the Attester is, among the RRPs that trust the same Verifier and serve
   the Target's name, the CAS Server's choice; a deployment that must not see one Evidence issued or released twice
   uses present-nonce, which limits one Evidence to the RRP that minted the Handle.
3. A deployment that needs the Attester to pin its RRP gives each RRP Target names of its own: the Target is bound,
   and a request for a Target an RRP does not serve is refused. (By construction; every redirection run above used a
   shared Target name, so this one is not measured separately.)

If the group wants the Attester to pin the RRP in the protocol itself, (a) is measured and costs what is listed above;
the sentence on the CAS Server's session nonce is then needed with the identifier among its inputs. Either way, one
text rather than two options. The choice is the group's: both sides are measured on the same events, and either text
can be backed by the runs.

## 6. What this does not cover

- One implementation on both sides: the bench's CAI, EST server and RRPs. The group's proof of concept was not
  measured.
- Pinning by Target names (5, sentence 3) is not measured; three runs would measure it.
- The confidentiality half — what the CAS Server reads in the Evidence and, in Passport, in the Attestation Results —
  is the same with and without the identifier ([docs/attacks.md](attacks.md), section 7), and is a separate choice.
- What a run does not prove in general: [docs/limits.md](limits.md).

## 7. Two faults the series found in the bench, kept with their READMEs

- [20261008T202943Z-gcp-sev-snp-no-rrp-id](../hwcheck/evidence/20261008T202943Z-gcp-sev-snp-no-rrp-id): rrpverify's service path still made the "other RRP identifier" case when there was no
  identifier to substitute, so the honest request was counted as an accepted substitution, ten times. Fixed in
  `c3909630`; the GCP and TDX attack runs above came after it.
- [20261008T210307Z-aws-sev-snp-no-rrp-id](../hwcheck/evidence/20261008T210307Z-aws-sev-snp-no-rrp-id): the AWS script's `verify` line had not been given the empty identifiers its hwrun, pre-play
  and `service` lines were given, so the in-process appraisals recomputed the binding with an identifier the guest had
  not bound and refused the honest Evidence; the service path of that run, given them, came out 40 of 40 as expected.
  Fixed in `1c1df049`; the AWS attack run above came after it.

Neither is a finding about the protocol; both are kept because a bench that hides its own faults cannot be trusted
with a protocol's.

## 8. The decision and the code (11 October 2026)

Mark Novak, reviewing the transfer of this backend to the group's repository (TWI-Unified-Model/globalsign-est#4, 11 October,
02:19Z and 06:14Z): the decision of 6 October was to drop the RRP identifier and the EST Server's identifier alike, and to look
at adding them back after the threat model is agreed and documented; at 14:31Z, on the question whether an empty field should
stay in the layout: "Let's rip it all out. For now: once we have a comprehensive end to end understanding, then we put in
only what's needed. Keeps the code clean." The code follows:

- the EST server computes the Verifier session's nonce over three length-prefixed fields, the freshness element, the Target
  and the subject (the transfer branch's `b531556`; EST patch 0018 here); its configuration names no `rrp_id` and the server
  checks none against the RRP's attest-initiate answer; the per-RRP switch of the day before is gone;
- the mock CA of the group's repository drops `server_id` from its binding digest and from the EncryptedCredentialBundle
  (`7e4224c`), and its digest is now the same octets as the backend's;
- this bench binds the same three fields: the CAI (`platform.EvidenceRequest` carries no Relying Party), the RRP gateways
  (whose attest-initiate answer names no identifier either), hwrun and rrpverify, the pre-play and the redirection
  experiment, now one pass; the Secret Vault's container carries no `rrp_id` in its associated data or HPKE info, the Vault's
  key being its identity to the Attester; `BIND_RRP_ID` and `omit_rrp_id_in_binding` exist no more;
- every run from 12 October records its layout (`binding_layout` in `cases.json`), and rrpverify appraises each committed run
  by the layout its record names, so the runs of 6 to 11 October (with the identifier, or with an empty fourth field) are
  still appraised as they ran (`make test-live`).

The measurement of sections 3 to 7 stands as the comparison the decision can be read against; the side with the identifier
is reproducible from the code of 11 October morning (`2a3777a3`, `BIND_RRP_ID=1`). The runs of 11 October evening on the new
code are listed in `docs/verification.md`: the demo in both RATS models and the attacks on the three platforms as before, and
the conduit's redirect drill (attacks.md, 6.3), which measures what carries the pin now: with a second RRP issuing under the
PKI, or sealing under the keys, the Attester already trusts, the CAI admits; with keys of its own, it refuses. The pin is the
Attester's anchors and the Target's name, as 3.3 of the threat model and the text of section 5 say.

## 9. How to repeat

```bash
make demo                                   # the mock trust zone on a laptop, free, in minutes
make config && make start                   # the trust zone: no identifier in the binding (the code since 12 October 2026)
make demo PLATFORM=gcp-snp                  # also aws-snp, gcp-tdx; RATS_MODEL=passport; make attacks
git checkout 2a3777a3                       # the side with the identifier: the code of 11 October morning, BIND_RRP_ID=1
REDIRECT_VARIANT=replay make redirect PLATFORM=gcp-snp   # both passes in one run; also replay-vault, own-epochs, start-ca2, vault
CONDUIT_ATTACK=seal make demo PLATFORM=gcp-snp           # also swap, hint, hint-group
```

The hardware runs use your own cloud account and delete the VM they create ([docs/getting-started.md](getting-started.md));
the mock reproduces the protocol logic without hardware. Reading a run: [docs/results.md](results.md).
