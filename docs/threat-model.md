# TACRA: the Credential Acquisition System as the attacker — a threat model draft

Sent to the TWI SIG on 8 October 2026 for its meeting of 13 October; 3.5 measured the same night. Everything measured below was run on real hardware: Google Cloud SEV-SNP,
AWS SEV-SNP and Google Cloud TDX, 6–8 October 2026, in both RATS models, with EST as the CAS. The models are the
ProVerif models published with the reference implementation.

## 1. Scope and the attacker

TACRA makes the Credential Acquisition System a conduit it does not trust (Section 7, "Credential Acquisition System
Considered Untrustworthy"). This is the case RATS already provides for: Section 12.2 of RFC 9334 requires end-to-end
integrity protection and replay protection for every conceptual message, and expects an entity that relays Evidence
without being the Attester or the intended Verifier not to have access to it. So the model has two halves: integrity
across the CAS, which the binding of Section 4.5 is for; and confidentiality from the CAS, which TACRA has not
decided.

The attacker is the CAS Client, the CAS Server and the network between them and the RATS roles. It can read, delay,
replay, reorder, rewrite and redirect every message, start exchanges of its own at any RRP it can reach, and run
machines of its own, on genuine confidential hardware or not. It does not control the Attester's TEE, the Verifier,
the Credential Authority or the Secret Vault, or the hardware vendors' roots. (TACRA Section 7 also says the CAS is
"expected to remain benevolent"; this model drops that expectation and asks what a malicious CAS gets.)

## 2. What each role holds, and what bounds it

| Role | Holds | Can do on its own | Bounded by |
|---|---|---|---|
| Attester, with its CAI | CSKpri or CEKpri; the Attesting Environment; its configuration per Target (Credential Type, Hint, and today the RRP identifier) | produce Evidence over any value it chooses as the freshness input; choose its Target | the Verifier appraises the launch and the platform; the CA and the Vault decide by their policy, not by what the Attester asks |
| CAS Client and CAS Server (the conduit) | every message in transit: the Handle, the Evidence, the CSR or CEKpub, the Credential Type and Hint, the Attestation Results (Passport), the credential or the sealed container | delay, replay, reorder; obtain a Handle from any RRP for any Target; carry a request to another RRP; change what the binding does not cover; in Passport, choose the Verifier it sends Evidence to | the binding, recomputed by the RRP; the freshness element; the RRP's policy; the Verifier keys the RRP holds for the Target; the container sealed to CEKpub |
| Verifier | reference values; the vendors' roots; its Handles, if it mints them | appraise Evidence; report the freshness input it read | it decides nothing about issuance; the RRP takes its Attestation Results only under a key it holds for the Target, and compares the report with its own recomputation |
| Credential Authority | its signing key; its issuance policy | issue for a CSR | recomputes the binding with its own identifier, the freshness element, the Target and the CSR; checks the freshness element under the Target's Freshness Kind |
| Secret Vault | the group's secrets; its origin key | release to a CEKpub | the same recomputation with CEKpub; seals to CEKpub |

## 3. The integrity half: closed by the binding, and measured

### 3.1 Substitution of what the binding covers

The conduit changes one input of a request and offers the rest as made: another Target, another CSR or CEKpub,
another freshness element (an old or foreign Handle, another epoch marker). Each is refused because the RRP's
recomputed digest no longer matches the one the Verifier read from the Evidence. Measured for all five Freshness Kinds
in both modes on the three platforms (30 checks per platform per run; 40 committed runs of 6–8 October re-appraised by
the live verifiers, 2000 checks, every substitution refused for its own reason). A forged report that does not chain
to the vendor's root, and a launch whose measurement differs by one byte, are refused by the Verifier before the
binding is reached. That is also what meets a machine of the conduit's own: not genuine, it does not chain to the
root; genuine and running another launch, it fails the Target's reference values; genuine and running the same
launch, it is an instance of the attested workload, with keys of its own, and what it obtains is a credential for
that instance, never for the Attester's keys. The same substitutions were offered to the protocol run without the RRP identifier in the
binding (the CAI, the CAS Server and the RRPs all leaving it out; 8 October, one run per platform): every
substitution of the Target, the CSR or CEKpub and the freshness element was refused as before. There was no
identifier to substitute.

### 3.2 The same request again, at the same RRP

The conduit holds every request it carried and offers it a second time to the RRP it was made for. The RRP keeps no
record of a CSR or CEKpub it served; only the freshness element can refuse the second offer. Measured 8 October in
12 runs, the three platforms × Enrollment at the Credential Authority and Retrieval at the Secret Vault × both RATS
models, 10 of 10 outcomes each as the table says:

| Freshness Kind | second offer | why |
|---|---|---|
| `present-nonce` | refused | the Handle is deleted on its first use |
| `present-epoch`, `absent-epoch` | served again | the epoch marker is current until the epoch moves |
| `absent-timestamp` | served again | inside the window (`max_age`; on the platforms measured, Evidence made Δ ahead of the RRP's clock is taken from Δ − skew to Δ + `max_age` after it was made) |
| `absent-none` | served again | nothing to compare |

Both credentials are for the Attester's own key, so the conduit obtains nothing it can use. What it obtains is a
second credential, or a second release of the same secret, from one Evidence: a deployment that counts or audits
credentials has to know that only `present-nonce` makes one Evidence serve once. Each of the 12 runs made both
passes, with the RRP identifier bound and without it: the table holds for both; the identifier plays no part in
whether a second offer at the same RRP is served.

### 3.3 Redirection: the same Evidence at another RRP

The conduit offers Evidence made for one RRP to a second RRP that trusts the same Verifier and serves a Target of the
same name (a second bank). Measured 7–8 October on the three platforms, in both models, with two Credential
Authorities and with two Secret Vaults, 27 runs:

- with the RRP identifier in the binding (Section 4.5 as it stands), the second RRP refuses every Freshness Kind, its
  own Handles included when the conduit starts the exchange there;
- without it: when the two RRPs share an epoch marker, only `present-nonce` stops the second RRP (it never minted the
  Handle); the other four kinds are issued or released twice. When the second RRP keeps an epoch marker of its own,
  only `absent-timestamp` and `absent-none` are issued twice. And a conduit that starts the exchange at the second RRP
  gets `present-nonce` and `present-epoch` served there too, since that RRP minted the Handles; only `absent-epoch`,
  whose marker the Attester holds, is refused.

Either way the credential or the secret is bound to the Attester's keys: the conduit cannot use it. What the RRP
identifier decides is who chooses which RRP serves the Attester, the Attester or the conduit.

### 3.4 What the binding does not cover

The Credential Type and the Credential Hint travel unbound (Section 4.5 says so). Measured on Evidence made for the
first CA: a credential type the Target does not offer is refused by policy; another workload's Hint is refused because
the CA names the attested workload itself; the other credential type the Target does offer is issued for every kind
but `present-nonce`, whose Handle the RRP minted for one Target and type. Retrieval adds the Hint's use at the Vault: a
Hint of another group the Target serves to the same launches made the Vault release that group's secret, which only the
Attester's own check of the Hint it asked for refused. So Section 7's rule that the Hint is a request, not an
authorization, has to be carried by the RRP's policy and by the Attester's check of what came back. Nor does the
conduit choose the Freshness Kind: the kind is the Target's, by the RRP's policy, and a request rewritten to
`absent-none` for a Target of another kind is refused (`freshness-kind-mismatch`); a Handle the conduit makes up is
refused because the RRP knows the Handles it minted (6 runs of 7 October, both models).

### 3.5 The conduit's choice of Verifier (Passport)

In Passport the CAS Server chooses the Verifier it sends Evidence to and relays the Attestation Results. What bounds
the choice is the RRP: in my setup it holds, per Target, the keys of the Verifiers it takes results from, checks the
signature of every result against them and refuses any other; the result's nonce must also equal the binding the RRP
recomputes (3.1). A Verifier of the conduit's own therefore needs a key the RRP was provisioned with. Measured 8
October on the three platforms, in Passport: the CAS Server signed the Attestation Results of each of the five
Enrollments again with a key of its own, header and payload unchanged, and sent them on; the Credential Authority
refused each ("not signed by the verifier's key: none of the verifiers this RRP takes for the Target signed it"),
and the five Retrievals, relayed as the Verifier signed them, were admitted (3 runs, 10 of 10 outcomes each).
TACRA's text should say where the RRP's trusted Verifiers come from, since in Passport nothing else bounds the
conduit's choice.

### 3.6 What is left to the conduit when the binding holds

Delay and denial, including the cheap form: Handles minted and never used, exchanges started and abandoned, at every
RRP the conduit can reach; an RRP has to bound what it mints per client, which is where authentication of the CAS to
the RRP, the open item of Section 7, matters. It does not change the integrity half: the binding does not depend on
who carried the request. (Not measured.) Then: choosing the RRP, if the identifier is not bound (3.3); choosing the
Verifier, in Passport, within the keys the RRP holds (3.5); a second credential from one Evidence, for the kinds that
are not single-use (3.2); and what 3.4 lists. None of it yields a credential the conduit can use.

## 4. The confidentiality half: the open choice

### 4.1 What the conduit reads

Evidence is signed, not encrypted; the CAS Client reads it on the way out, and the CAS Server reads it and, in
Passport, the Attestation Results as well. From the Evidence of the 8 October runs, parsed with the platforms' own
libraries:

| The conduit learns | GCP SEV-SNP | AWS SEV-SNP | GCP TDX |
|---|---|---|---|
| the machine | yes: `CHIP_ID` and the VCEK's hwID name the chip | not the machine: VLEK-signed, `CHIP_ID` zero; the VLEK's cspID names the provider's key domain and region | yes: the PCK certificate names the platform (PPID, FMSPC, PCE-ID) |
| the launch | `MEASUREMENT`, the owner's `ID_KEY_DIGEST`, `HOST_DATA` | the same | `MRTD`, the RTMRs, `MROWNER`, `MRCONFIGID` |
| the firmware level | the TCB versions, the mitigation vectors, the SNP firmware version | the same | `TEE_TCB_SVN`, the TDX module's `MRSEAM`, the Quoting Enclave's signer and SVN |
| the policy | debug, migration, SMT | the same | `TDATTRIBUTES`, `XFAM` |
| in Passport, besides | the verifier's verdict and annotated claims | the same | the same, with the launch claims in the clear |

This is "system identifiable information" in the words of Section 7.2 of RFC 9334, and Section 11 warns that the
firmware level tells an attacker where to aim. On GCP SEV-SNP and GCP TDX the conduit can also link one machine's
Evidence across Targets and RRPs, by `CHIP_ID` or by the PCK's PPID; on AWS the VLEK's cspID links the provider's
key domain and region, not the machine. What the conduit cannot read is what the architecture keeps from it:
CSKpri, CEKpri and the secret the Vault sealed to CEKpub.

### 4.2 The two options, and what each costs

1. **Accept it.** The deployment treats the CAS as a trusted-for-confidentiality intermediary, as a bank's managed CAS
   may well be (discussed 29 September and 6 October). Security Considerations then say what the CAS learns (4.1) and
   that the deployment accepts it. No change to the protocol or the PoC.
2. **Encrypt Evidence to the Verifier.** This is what Section 12.2 expects of a relay. It needs the Attester to hold
   the Verifier's public key before it produces Evidence: in configuration per Target, the way Section 4.5 has the CAI
   hold the RRP identifier, or taken from the Initiate response, which lets the conduit choose the Verifier. In
   Passport it is the CAS Server's configuration that names the Verifier today, so this option moves that choice to the
   Attester's side; in Background Check the RRP chooses the Verifier and would have to tell the Attester through the
   CAS. The cost is a key in the Attester's configuration and a mechanism in every CAS; the gain is that the conduit
   learns nothing of 4.1 but the Attestation Results in Passport, unless those are encrypted to the RRP as well.

The data does not decide between them; it says what each buys. A decision can be deferred without loss to the PoC,
which is option 1 as it runs.

## 5. The RRP identifier: the two texts for Security Considerations

(a) **Held by the Attester's CAI and bound (Section 4.5 as it stands).** Evidence serves only the RRP the deployment
intended, for every Freshness Kind, whoever starts the exchange. Cost: the identifier in the Attester's configuration
per Target and mode, and a configuration change when a Target moves from Enrollment to Retrieval.

(b) **Left out.** The conduit chooses, among the RRPs that trust the same Verifier, which one serves the Attester;
nothing it obtains is usable without the Attester's keys. `present-nonce`, originated by the RRP, keeps one Evidence
from serving a second RRP as well, but not from serving the RRP the conduit chose to start at. Security Considerations
then say both: that a deployment which must not see one Evidence issued twice requires `present-nonce`; and that which
RRP serves the Attester is, without the identifier, the conduit's choice among the RRPs that trust the same Verifier.
Cost: none in the protocol; the two limits above in the text.

Both are measured (3.3). Which one TACRA wants is the group's choice.

To see what else leaving it out changes, the protocol was run end to end without the identifier, the CAI leaving
it out of the binding, the CAS Server computing its Passport session nonce without it, the RRPs recomputing the
binding without it, on the three platforms, 8 October: the full exchange in both RATS models (10 of 10 Targets in
each of 6 runs), the substitutions of 3.1 (3 runs), the second offers of 3.2 (12 runs) and the container drills of
Section 6 (12 runs) all end as they do with the identifier. What differs is 3.3 alone. One consequence for the text:
in Passport the CAS Server computes the Verifier's session nonce from the binding's inputs, so whether the identifier
is bound is a property of the CAS Server as well as of Section 4.5; a CAS Server that keeps the identifier in its
nonce refuses an Attester that left it out, the mismatch being the "other RRP identifier" case of 3.1, refused by
the Verifier. Leaving the identifier out therefore wants one sentence on the CAS Server's nonce, not only the change
to 4.5.

## 6. The Retrieval container, in one paragraph

The container is sealed to CEKpub, which the conduit saw; anyone who saw it can seal a container to it. Measured 8
October on the three platforms: a container the conduit sealed itself was refused, because the Attester opens only what
the Vault key it holds sealed or signed; the Vault's container of another Retrieval was refused, because its associated
data names another Target and freshness element. With a new CEK for each Retrieval, as the CAI makes one, another
Retrieval's container does not open at all; with one CEK kept across Retrievals, what refuses it is the Target in the
associated data or in the signature. Repeated without the RRP identifier in the binding (12 runs, 8 October), the
drills end the same way. This belongs with the container's definition in TACRA (the thread of 8 October on
pull request #1), not with the two halves above.

## 7. Assumptions and what this model does not cover

- A leaked platform attestation key breaks every guarantee; the Verifier's only handles on it are the vendor's root,
  the refusal of debug-enabled guests and the TCB it reports.
- `absent-timestamp` is only as fresh as the Attester's clock, which on these platforms the host serves (issue #22).
- The credential's scope after issuance is the RRP's policy (Section 7, Credential Scope), not the binding's.
- The CAAPI between the CAI and the CAS Client inside the guest is plaintext by design; the CAS Client is the attacker.
- Independent CAS implementations were not tested; the measurements are of one CAS (EST) and one set of RRPs.

## Appendix. Coverage: what the conduit can do to each value, and what stops it

m = measured on hardware; c = by construction (tested, not run on hardware); — = nothing to do.

| Value | Rewrite or substitute | Replay | Redirect to another RRP | Originate its own | Read |
|---|---|---|---|---|---|
| Handle (`present-nonce`) | refused: an old or foreign Handle breaks the binding (3.1, m) | refused: deleted on first use (3.2, m) | refused at an RRP that did not mint it; served at the RRP the conduit started at (3.3, m) | a made-up Handle: the RRP knows the Handles it minted (3.4, m) | the Handle alone |
| Epoch marker (`present-epoch`, `absent-epoch`) | refused: not the current marker (3.1, m) | served until the epoch moves (3.2, m) | served where the marker is shared, refused where the second RRP keeps its own; `absent-epoch` refused when the conduit starts at the second RRP (3.3, m) | — | the marker alone |
| Timestamp (`absent-timestamp`) | refused: binding (3.1, m) | served inside the window (3.2, m) | served (3.3, m); the window follows the Attester's clock (7) | — | the time |
| Freshness Kind | refused: `freshness-kind-mismatch`, the kind is the Target's (3.4, m) | — | — | — | — |
| Evidence as a whole | any bound input changed → refused (3.1, m); a report off the vendor's root, another launch → refused by the Verifier (3.1, m) | as the Freshness Kind says (3.2, m) | as the Freshness Kind and the identifier say (3.3, m) | its own machine: another launch refused; the same launch is an instance with keys of its own (3.1, c) | read in full (4.1, m) |
| CSR or CEKpub | refused: binding (3.1, m) | — | — | its own key: binding mismatch (3.1, m) | public values |
| Credential Type | an unoffered type refused; the other offered type issued for every kind but `present-nonce` (3.4, m) | — | — | — | — |
| Credential Hint | another workload's refused by the CA; another group's secret released by the Vault, refused by the CAI (3.4, m) | — | — | — | — |
| Attestation Results (Passport) | signature under a key the RRP holds for the Target; nonce = the binding (3.5, m; 3.1, m) | as Evidence (3.2, m, both models) | as Evidence (3.3, m) | a Verifier of its own: not a key the RRP holds (3.5, m) | read in full (4.1, m) |
| Certificate | bound to CSKpub: nothing to change | — | — | — | public |
| Sealed container | swapped: refused by the associated data; sealed by the conduit: refused for its origin (6, m) | — | — | — | sealed to CEKpub |
| The RRP that serves | — | — | the identifier, if bound; else the conduit's choice (3.3, 5, m) | — | — |
| The Verifier (Passport) | — | — | — | — | within the RRP's trusted keys (3.5, m) |
| Availability | — | — | — | Handles minted and abandoned, exchanges dropped (3.6, not measured) | — |
