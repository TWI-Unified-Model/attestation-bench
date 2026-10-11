# Changelog

What changed, newest first. Dates are UTC.

## Unreleased: the data the group's open questions need

### Changed

- **The identifiers ripped out** (11 October 2026): the group decided on 6 October to leave the RRP identifier out of the
  binding (TheBankster/rats-tacra#20) and Mark Novak asked on 11 October, in TWI-Unified-Model/globalsign-est#4, to rip the RRP
  identifier and the EST Server's identifier out altogether, with no empty field kept. The binding is now three length-prefixed
  fields, the freshness element, the Target and the subject, in the group's EST server (EST patch 0018, after 0017's empty
  field) and in every component of this bench: the CAI, the RRP gateways (whose attest-initiate answer names no identifier),
  hwrun and rrpverify, the pre-play and the redirection experiment, now one pass; the Secret Vault's container carries no
  `rrp_id` in its associated data or HPKE info. No switch is left (`BIND_RRP_ID`, `omit_rrp_id_in_binding`, `-rrp-ca`,
  `-rrp-vault` are gone); the side with the identifier is history, reproducible from `2a3777a3`. Every run from 12 October
  records its layout (`binding_layout` in `cases.json`); rrpverify appraises each committed run by the layout its record names,
  so `make test-live` holds the runs of 6 to 11 October as they ran ([docs/rrp-identifier.md](docs/rrp-identifier.md), section 8).
- **The conduit's redirect drill** (`CONDUIT_ATTACK=redirect make config`; `COPIES_OWN_KEYS=1` for the second Vault's own keys):
  the EST server routes every request to the second Credential Authority and the second Secret Vault, the RRPs the Attester did
  not ask for; the run is judged by what the CAI does with what comes back (`scripts/verdict.py conduit --attack redirect`,
  from the routing the run records in `bench-logs/est-routing.json`).

### Added

- **The new default, run on hardware** (11 October 2026): the EST server of the group's code with both identifiers gone
  (`7e4224c`) in the trust zone binding none: the demo on GCP SEV-SNP, AWS SEV-SNP and GCP TDX in both RATS models, 10 of 10
  Targets in each of the 6 runs, and the substitution suite on the three platforms, 232, 232 and 142 checks, every attack
  refused for its own reason (the "other RRP identifier" case is the honest one again and is left out); then the bench's own
  tree (patch 0017), the demo in Passport on the three platforms, 10 of 10 each. Each run's EST source record names its tree
  ([docs/verification.md](docs/verification.md)); `make check` holds the 12 runs (`NO_ID_DEFAULT_RUNS`, `NO_ID_BENCH_TREE_RUNS`).
- **The wire is the draft's**: the attest-* wire this bench runs (EST patch 0014, [e2e/est-attest.cddl](e2e/est-attest.cddl)) was
  merged into draft-novak-lamps-tacra-est's master on 10 October 2026 (TheBankster/lamps-tacra-est#10, `4fa3883`); `UPSTREAM` and
  [docs/verification.md](docs/verification.md) say so.
- **The transfer branch verified in the trust zone**: the EST server built from the branch prepared for the group's
  repository (TWI-Unified-Model/globalsign-est: the mock CA kept beside the TACRA backend, the wire of the draft's
  pull request) at `96a919cfece9`, run with `EST_REPO` on 9 October: the demo on the three platforms in Passport,
  10 of 10 Targets each, and the substitution suite on GCP SEV-SNP, every attack refused; each run's EST source
  record names that tree.
- **The threat model** ([docs/threat-model.md](docs/threat-model.md)): the CAS as the attacker, sent to the TWI SIG on
  8 October for its meeting of 13 October: the roles and what bounds each, the integrity half with every claim
  measured on hardware (the verifier drill closed the last one the same night), the confidentiality half as the
  open choice with the cost of each option, the two texts for the RRP identifier, and the coverage table.
- **The conduit's verifier drill** (`CONDUIT_ATTACK=verifier make config && make start`, then `make demo`): the EST
  server, as the attacking conduit in Passport, signs each Enrollment's Attestation Results again with a key of its
  own before the Credential Authority sees them (EST patch 0016); the Credential Authority refuses each, none of the
  verifiers it takes having signed them, and the five Retrievals are admitted. Three platforms, 8 October: the
  measurement of the threat model's "choice of Verifier" ([docs/attacks.md](docs/attacks.md), section 6).
- **The report on the RRP identifier, both ways** ([docs/rrp-identifier.md](docs/rrp-identifier.md)): the protocol
  with the identifier in the binding and without it on the same events, row by row with every run named, what the
  identifier buys and costs, the text that follows either way, what the report does not cover, and the two bench
  faults the series found. Written for TACRA issue #20.
- **The protocol without the RRP identifier, end to end** (`OMIT_RRP_ID=1`; TACRA #20): one switch reaches the
  workload's CAI (`WithoutRelyingPartyBinding`), the EST server (patch 0015: the Passport nonce without the
  identifier) and the RRPs, so the same demos, attacks, replays and drills run with the identifier bound and
  without it. On the three platforms, 8 October: 33 runs, each as the run of its kind with the identifier; what
  differs is which RRP serves the Attester ([docs/attacks.md](docs/attacks.md), section 8). Leaving the identifier
  out is a change to the CAS Server as well as to the text: its nonce must match what the RRP recomputes.
- **The replay variants of `make redirect`** (`REDIRECT_VARIANT=replay`, `replay-vault`): the same request offered
  twice at the same RRP, `ca1` or `vault1`, for each Freshness Kind, in Background Check and in Passport. The RRP
  keeps no record of a CSR or CEKpub it served, so only the freshness element can refuse the second offer: a
  present-nonce Handle serves once; an epoch marker serves while it is current, a timestamp while its window holds,
  absent-none always. Both credentials are for the Attester's own key, so the conduit obtains nothing it can use:
  what the replay measures is double issuance or release from one Evidence
  ([docs/attacks.md](docs/attacks.md), section 2). `scripts/verdict.py` judges each outcome against that table. On the three platforms, 8 October: 12 runs, 10 of 10 outcomes each.
- **`hwcheck/cmd/conduit-view`**: what the conduit sees of a run's Evidence and, in Passport, of its Attestation
  Results, field by field as the platform's own library parses it, with what each field tells (the machine, the
  launch, the firmware, the policy, the Attester's choice) and the certificates that travel with it. On the runs
  of 8 October the conduit learns the chip on GCP SEV-SNP (`CHIP_ID`, the VCEK's hwID), the provider's key domain
  and region on AWS (the VLEK's cspID, `CHIP_ID` zero) and the platform on GCP TDX (the PCK certificate's PPID and
  FMSPC), and on every platform the launch, the firmware level and the policy
  ([docs/attacks.md](docs/attacks.md), section 7). Its test reads those three runs.
- **The conduit's rewrites** in `make redirect` (TACRA #19): on Evidence made for `ca1`, the conduit sends, one at a
  time, a made-up Handle, the Freshness Kind `absent-none`, a credential type the Target does not offer, another
  workload's Credential Hint, and the other credential type the Target offers. Each is refused for its own reason but
  the last, which is issued for every kind but present-nonce: the credential type is neither in the binding nor used by
  the Credential Authority, and only a present-nonce Handle, minted for one Target and type, catches it
  ([docs/attacks.md](docs/attacks.md), section 2). Run on the three platforms in both RATS models: 20 of 20 each time.
- **Redirection in Passport**: `PASSPORT=1 make redirect`. The conduit gets the Attestation Results for each Evidence
  from the verifier, as an honest CAS does for `ca1` (`rrpverify ears`), and offers them to `ca2`: the same outcomes as
  in Background Check, `ca2` refusing for `eat_nonce is not the binding value` when the RRP identifier is bound.
- **The pre-play moves the guest's clock both ways** and measures the absent-timestamp window at its edges; the other
  four Freshness Kinds' Evidence, made with the clock ahead, is offered at once. On the three platforms: the four other
  kinds taken at once; absent-timestamp made 300 s ahead taken from 295 s to 420 s after it was made, the same
  Evidence each time; made 300 s behind, refused ([docs/limits.md](docs/limits.md), "Time").
- **The demo times Initiate**: each Target's `initiate_ms` and `second_leg_ms` in `results.json`. Of 60 acquisitions
  on the three platforms in both models, the median Initiate took 259 ms from the guest, through the bench's SSH
  tunnel, of a 564 ms acquisition; the EST server and the RRP spent 1.35 ms of it (their log).

- **The EST wire log** (EST patch 0013, `wire_log` in the EST server's configuration): every exchange on an attest-*
  resource, request and response, as it crossed the wire, one JSON object per line; a demo run keeps its part in
  `bench-logs/est-wire.log`. The record does not change the exchange: the patch's test serves each request with the
  log and without it and gets the same answer; `make test-live` checks that the log holds its own exchanges octet
  for octet. `e2e/scripts/est-wire-cddl.py` checks the logged messages against a CDDL with the cddl tool, after
  showing that the tool refuses a message without a required member, with a member the CDDL does not define, or
  with a byte string in standard base64.

- **The conduit's drills on the Retrieval container** (`CONDUIT_ATTACK=seal|swap|hint|hint-group make demo`;
  [docs/attacks.md](docs/attacks.md), section 6): the workload's CAS Client returns a container it sealed itself
  (TACRA's option of the CAS Server encrypting to CEKpub), the Vault's container of the Retrieval before, or asks the
  Vault with another Credential Hint, one the Target serves no group to or one of another group it serves to the
  same launches (the bench pack's new `other_groups`, `audit.workload.tacra.example`; `scripts/setup.sh` stores its
  key). `scripts/verdict.py conduit` judges each run from the workload's results and the conduit's log. Unit tests of
  the container (`bundle/keptcek_test.go`) show which check refuses a container meant for another request: with a new
  CEK for each Retrieval, none is needed; with a CEK kept across Retrievals, the hpke-auth container needs the
  associated data's Target check, and the hpke-base-signed container's signature covers the Target. On the three platforms,
  8 October, 12 runs: each as its drill expects ([docs/attacks.md](docs/attacks.md), section 6).

- **The redirection experiment's variants** (`REDIRECT_VARIANT`, TACRA #20). The default run fixes two things: its two
  Credential Authorities share one epoch marker, and the conduit offers Evidence made for `ca1`. In `own-epochs`
  `ca2` keeps an epoch marker of its own; in `start-ca2` the conduit also starts the exchange at `ca2`, whose Handles
  the Evidence then binds. Without the RRP identifier `ca2` issues, with an epoch of its own, for absent-timestamp and
  absent-none alone, and, when the conduit starts there, for every kind but absent-epoch, present-nonce included; with
  the identifier it refuses all five in both. The verdict checks each refusal's reason: the Handle, the epoch marker
  or the binding. On the three platforms in both RATS models, 8 October, 12 runs, 20 of 20 each
  ([docs/attacks.md](docs/attacks.md), section 2).
- **The redirection on the Secret Vaults** (`REDIRECT_VARIANT=vault`): Retrieval had never been redirected. A second
  Vault, `vault-2`, in the bench's pack (its own RRP identifier and listener; `bench.sh` starts it once the first
  Vault listens, as it reads the key files the first creates), and `rrp-issue retrieve`, the Retrieval's second leg.
  `--omit-rrp-id` now leaves the identifier out of every RRP's binding, the Secret Vaults' too. As on the Credential
  Authorities: with the RRP identifier `vault2` refuses every kind; without it, it releases the workload's group's key
  for every kind but present-nonce, each container sealed to the Attester's CEKpub. 6 runs, 20 of 20 each.

- **The attest-* wire as proposed for the EST draft** (EST patch 0014; [e2e/est-attest.cddl](e2e/est-attest.cddl)):
  a media type for each message type, as EST has one for each (RFC 7030, Section 3.2.4), with the names of the
  reference implementation: `application/est-attest-initiate+json`, `-enroll+json`, `-retrieve+json` and
  `-bundle+json`, with a CA label or without; any other request type, `application/json` included, gets 415 with an
  `Accept` header. No `rrp_id`, `required_bindings` or `server_id` in the attest-initiate response, no `endorsements`
  in the requests; `credential_type` is optional in both requests, as in the draft's Retrieval request and the
  group's fork (whether it travels at all is TACRA #19). The EST server refuses with 400, saying why, any request that
  is not what the CDDL defines (a member in another case or twice, null, invalid UTF-8, a byte string that is not
  unpadded base64url as `.b64u` takes it, a handle where its Freshness Kind takes none or none where it takes one,
  data after the object), and a body over its limit with 413. `make test-live` checks the types, the 415s and four of
  these refusals on the live server, none of which uses up a Handle, and the 415 for Evidence of a format not
  accepted, after which the same Handle still reaches the RRP; `e2e/scripts/est-wire-cddl.py` takes the repository's
  CDDL and checks each message's media type. A test of the patch, `TestUnreachable`, gets the server's 502 for an RRP
  and its 503 for a verifier, each a local port nothing listens on. On the three platforms in both RATS models, 8
  October, at `bee2ae9`: 6 demos, 10 of 10 Targets each, 120 messages valid against the CDDL, 180 media types as their
  place's, 84 altered messages refused; 3 attack runs, 262, 262 and 162 checks, each PASS, the pre-play's 72 messages
  valid against the CDDL with their media types. The same at `6bf2b37` and `dae1fb0`, before the check against what
  the group asked ([docs/verification.md](docs/verification.md)).

### Fixed

- rrpverify's service path (the deployed Veraison given the binding value as the expected nonce) still made the
  "other RRP identifier" case when no identifier was bound, so the honest request counted as an accepted
  substitution, ten times: the first attack run without the identifier found it
  ([its README](hwcheck/evidence/20261008T202943Z-gcp-sev-snp-no-rrp-id/README.md)). The case is left out there too, as the verify path
  already left it out.
- The AWS SEV-SNP attack script gave the empty identifiers of `OMIT_RRP_ID=1` to hwrun, the pre-play and
  rrpverify's service path, but not to its verify path, which then refused the honest Evidence of every request:
  the first AWS attack run without the identifier found it ([its README](hwcheck/evidence/20261008T210307Z-aws-sev-snp-no-rrp-id/README.md)).
  The verify line takes the same flags as the service line, as the GCP scripts' lines did.
- A request the EST server refused for its Evidence format (415) used up its present-nonce Handle: since
  patch 0001 the server correlated the Handle first. It now checks the format first, as the draft's processing
  has it (syntax, media type and size limits, then the Handle); `TestFormatRefusalLeavesTheHandle` fails under
  the old order.
- A demo run whose SSH reverse tunnel did not come up ran its workload anyway and ended in a verdict about the
  Targets ("10 of 10 Targets not admitted") for a failure of the network: on 8 October the tunnel's session to an AWS
  instance timed out during the banner exchange. The demo scripts now open the tunnel again, up to three times, when
  its session ends, and a run whose tunnel never comes up stops, saying so.
- The pre-play took the Credential Hint as the Target's one identity or credential group, and stopped at a Vault Target
  with two, which every Vault Target has had since the conduit's drills added `other_groups`: the first attack run
  after them found it ([its README](hwcheck/evidence/20261008T135750Z-gcp-sev-snp/README.md)). It now sends the
  workload's own hint (`packs/tacra-bench`, `workload.hint`).
- README, [docs/attacks.md](docs/attacks.md) and [docs/getting-started.md](docs/getting-started.md) said that without
  the RRP identifier only a nonce stops the redirection. That holds for RRPs that share one epoch marker, on Evidence
  made for the first; they now say so, and what the variants found.

- The EST server kept one attest-initiate session per Handle, so an attest-initiate for a second Target's
  present-epoch, whose Handle is the epoch every Target shares, replaced the first Target's session and refused its
  second leg (403). Found by the new pre-play on GCP SEV-SNP
  (`hwcheck/evidence/20261007T211305Z-gcp-sev-snp`, its README); EST patch 0012 keeps a session per Target, Credential
  Type and kind under each Handle, with a test that fails on the old behaviour.
- A pre-play refusal whose answer spanned lines broke the run's `VERDICT` line (`scripts/verdict.py`); found by its
  test.

## 0.1.1 (7 October 2026): the first page from the release's runs

### Changed

- README's Status table and Quick start, the guide's outputs (steps 5 to 9), the example verdict of
  [docs/attacks.md](docs/attacks.md) and the platform pages now quote the release check's runs. On SEV-SNP the hosts
  are admitted only under the bench's waiver of AMD-SB-3034's bit 4, and every verdict says so; attack runs carry the
  platform rule's checks and the guest's-clock exposure; the Demo Bank pays from TDX and refuses SEV-SNP. They showed
  runs made before the rule required the bit, found by a review of v0.1.0.
- [docs/verification.md](docs/verification.md) says that the release's demos and redirect runs were compared with runs
  made before that rule: the same outcomes, admitted then without the waiver. [docs/limits.md](docs/limits.md) gives
  the release's pre-play ages beside the earlier runs'.

### Added

- The Demo Bank in Background Check and a bank of one's own (`make bank-new NAME=acme-bank`), run again under the
  rule: in both, TDX pays and SEV-SNP is refused for bit 4. The verdict tests judge their payments.

## 0.1.0 (7 October 2026): the release for the group

The bench as a repository of its own, with the TACRA proof of concept's history. Everything below was added on
6 and 7 October 2026 and checked on real hardware: gate 5 (every earlier hardware run repeated from a bench set up
from zero, all identical), gate 6 (the Demo Bank) and gate 7 (every command in the docs run as written, on the
release's code; the hardware runs identical to gate 5's, check by check). The release itself was checked from a
fresh clone of the repository: the whole hardware matrix and the Demo Bank, 25 runs, 25 PASS, each identical to the
run of its kind before it, check by check ([docs/verification.md](docs/verification.md), "v0.1.0").

### Added

- **One command per job**: `make doctor`, `setup`, `start`, `stop`, `status`, `config`; `make demo`, `attacks` and
  `redirect` on real hardware, `PLATFORM=gcp-snp|gcp-tdx|aws-snp`;
  `make bank-new`, `bank-up`, `bank-pay`, `bank-audit`, `bank-down`; `make check-mtls`, `trust-check`, `cloud-check`;
  `make report`; `make lint`, `test`, `check`. `make help` lists them.
- **Every run judges itself** (`scripts/verdict.py`): its verdict, `VERDICT PASS` or `VERDICT FAIL`, is kept in the
  sealed run directory, and on FAIL the run, `make` and CI fail. Its tests judge every reference run of 6 October.
  `make report` lists runs, one row each with its verdict, the reference runs included.
- **Refusal scenarios of `make demo`** on hardware, each refused for its own reason: `UNAPPROVED=1` (an SEV-SNP
  launch the bench does not approve: four vCPUs) and `OTHER_PLATFORM=1` (the Targets of another platform's verifier,
  tacra-est N24).
- **Banks of your own**: `make bank-new NAME=…` makes a bank's pack from the Demo Bank's under its own names;
  `BANK=… make bank-up` brings it up.
- **Your own cloud**: hardware runs use the project or account your `gcloud` or `aws` CLI is signed in to
  (`GCP_PROJECT`, `GCP_ZONE`, `AWS_REGION`, `AWS_AZ`), and check it before creating anything.
- **A platform rule** (`trust/platform-policy.json`) that every RRP applies besides the verifier's verdict: on
  SEV-SNP the product line, the minimum TCB from AMD's bulletins (on REPORTED_TCB and COMMITTED_TCB) and SMT only
  with the microcode floor met; on TDX a TD under debug, profiled or migratable is refused. Each `make demo` run keeps
  the rule it ran under (`platform-rule.json`).
- **`hwcheck/cmd/snpreport`**: the launch measurement and the platform fields of the SEV-SNP reports a hardware run
  kept, as go-sev-guest reads them: the MEASUREMENT, the TCBs, the CPUID, the CHIP_ID and the mitigation vectors
  ([docs/results.md](docs/results.md)).
- **The mitigation vectors reach the RRP.** go-gen-ref patch 0002 annotates LAUNCH_MIT_VECTOR and CURRENT_MIT_VECTOR
  of a version 5 report (measurement keys 4032 and 4096, by AMD's CoRIM profile's bit-position rule; the profile names
  none for them), Veraison patch 0006 leaves them out of its reference-value matching, and the platform rule can
  require bits of them (`required_mitigation_bits`, in both vectors) and of PLATFORM_INFO
  (`required_platform_info_bits`). The bench's rule requires PLATFORM_INFO bit 5 (BadRAM, AMD-SB-3015) for Milan and
  Genoa, and the mitigation bits AMD names (Changed, below). `rrpverify service -save-ears DIR`
  keeps the EAR of each honest check.
- **`trust/`**: the approved launches, each with its endorsement and the record of the check, and the vendor roots
  and CoRIM the verifiers trust, each with its source; `make trust-check` compares them with their origins.
- **`packs/` and `scripts/trustzone.py`**: a bank's Targets and policy as data, and one program that writes every
  trust zone's configuration, the bench's and the Demo Bank's alike.
- **Third-party components as pinned upstream commits plus our patches** (`third_party/`), each checked against the
  tree it was tested with.
- **CI** on every push and pull request: `make check`, then the trust zone from zero on Ubuntu 24.04, live, and its
  mutual TLS in Passport and in Background Check. CI runs no protocol: it has no hardware.
- **A secrets scan in `make lint`**: gitleaks over the git history, with `.gitleaks.toml` allowing, by narrow
  patterns and with the reason for each, the things that look like secrets and are not.
- **`make test-live`**: the tests that need the running bench and no hardware. Through the live EST server: the media
  types each attest-* resource takes, the 415 it answers to any other, the Handle as unpadded base64url, a Handle that
  serves one request only. And the Evidence of every committed attack run from 6 October 2026 on, appraised again by
  the live Veraison and TDX verifier with each run's own records: the honest Evidence passes and every changed binding
  fails, as when the run was made (23 runs, 1150 checks). It fails, never skips, when the bench is not up; CI runs it
  in both RATS models.
- **The guest's clock, recorded and attacked.** Every hardware run, attack, demo and redirect, records what the guest's
  clock rests on (`clock.txt`: the clocksource, the boot lines on SEV, TDX and the TSC, the time service and how its
  sources are authenticated) and its offset from the RRP's (`clock-offset.txt`). Every attack run also pre-plays
  absent-timestamp Evidence: made
  in the guest with its clock set 300 s ahead (`hwcheck/scripts/preplay-guest.sh`), presented to the live RRPs through
  the EST server at once, refused (409, freshness), and again when their clock reaches the timestamp, accepted, older
  than the Target's `max_age`. `verdict.py` reports that as an exposure, not a pass ([docs/limits.md](docs/limits.md),
  "Time").
- **The platform rule in every attack run** (`rrp/cmd/platform-check`): the run applies the RRPs' platform rule to the
  honest Attestation Results it kept, with the key that signed them: the bench's rule admits them, a bank's without
  waivers refuses SEV-SNP Milan for AMD-SB-3034's bit 4, a rule one step stricter than the host refuses them for that
  reason. Each is a check of the run (`rrpverify-platform.json`), judged with the others. The run keeps the rule
  (`platform-rule.json`), and a SEV-SNP run's verdict names the waiver, as a demo's does.
- **Documentation**: [README.md](README.md) and [docs/](docs/getting-started.md), with how the release was checked:
  [docs/verification.md](docs/verification.md).

### Changed

- **The platform rule requires the mitigation bits AMD's bulletins name**, in both vectors: Milan bits 1 (AMD-SB-3020)
  and 4 (AMD-SB-3034), Genoa bit 1, Turin bit 0. A pack can admit hosts without a required bit under a named waiver
  (`platform_waivers`), which the RRP writes in its log line of each issuance and release and the verdict of each
  SEV-SNP demo and attack run names. The bench's own pack waives Milan's bit 4, which no Google Cloud or AWS host sets; the Demo Bank's
  waives nothing, so its SEV-SNP payments are refused for bit 4 and only its TDX payment goes through
  ([docs/limits.md](docs/limits.md)).
- The attack runs need the running bench: their checks through the live Veraison no longer skip when it is down, and
  TDX attack runs check through the live TDX verifier too. `hwrun` takes `-kinds`, `-modes` and `-cek`.
- The Demo Bank runs on the bench's configuration: mutual TLS between its components, the verifiers' keys given to
  the gateways as files, the API key in the signed container, pinned and checked tool versions.
- P-256 keys are read and written strictly with the standard library (`rrp/internal/jwk`): full-length coordinates,
  the point on the curve, a private key matching its public key.
- Every run directory is sealed the same way (`sha256sums.txt`) and ends with `== run directory: <path>`.
- The TACRA proof of concept's own guides moved from the repository root to `docs/tacra-poc/`, and later left the
  tree (Removed, below).
- `make redirect` puts the bench back as it was (its RATS model, the RRP identifier in the binding) when it ends,
  fails or is interrupted; it used to leave the bench in Background Check.
- `make test` (and so `make check` and CI) also runs, in each third-party component, the tests our patches add, and
  no others. It checks that each of them ran and that none of their test binaries links a mock; upstream's tests,
  some of them on mocks, are not run ([CONTRIBUTING.md](CONTRIBUTING.md), "Tests").
- **The approved AWS launch rests on AWS's published firmware**, no longer on trust on first use:
  `approved-launches.json` pins the binary of AWS's EC2 SEV-SNP UEFI, release 20260814 (its SHA-256), and how
  `sev-snp-measure` 0.0.13 measures it for a c6a.large; `make trust-check` and the Demo Bank at start download it and
  compute the measurement again (`trust/firmware-check.sh`). `trust/aws-uefi-rebuild.sh` rebuilds that firmware from
  AWS's source as AWS's README says (Nix) and compares: the rebuild is not the published binary, for release 20240809
  either, so the launch is not called reproduced ([trust/README.md](trust/README.md)).

### Fixed

- The approved TDX launches include both of Google's TDX firmware builds; with one, every VM that got the other build
  was refused.
- AWS VLEK reports are checked by the bench's Veraison build, which gives go-sev-guest AMD's roots.
- A run exited 0 whatever happened: `make demo` could print "0 of 10 Targets" and succeed.
- The bench's own modules and scripts used releases with known vulnerabilities, as Dependabot and govulncheck
  reported: `golang.org/x/crypto` v0.17.0 in `platform` and `hwcheck/vlekcheck` (now v0.56.0, as in the other
  modules), grpc v1.79.3 and x/text v0.37.0 in `hwcheck` (now v1.83.2 and v0.41.0), and `cryptography` 42.0.8 for
  the scripts (now 50.0.2).
- A copy to or from a VM that failed once, for a reason of the cloud's, ended the whole run, and its error went
  nowhere. Copies are now tried up to three times, and each failure is written to the run directory.
- Veraison affirmed a debuggable SEV-SNP guest and never checked AMD's intermediate for revocation. Patch 0005 (our
  earlier Veraison commit `6bbeaf9`, ported onto the chain check up to AMD's roots) refuses a guest whose policy
  allows debugging or a migration agent, and checks the intermediate that signed the report's certificate against
  AMD's CRL, fetched once per validity period; the check fails closed. Each check that passes is logged by the
  plugin at INFO; Veraison's trust service records its plugins' INFO lines at debug level, so at the bench's log
  level (info) they are not in `vts.log`, and a run shows the check by the plugin's build in `code-revs.txt`.
- Veraison and the EST server ran releases with known vulnerabilities that their code reaches: grpc, otel and x/text
  in Veraison, chi v4 in the EST server, which no chi v4 release fixes. Patches 0007 move them to fixed releases (chi
  to v5); `govulncheck` now finds no vulnerability reached anywhere in the bench ([docs/limits.md](docs/limits.md)).
- `make setup` left services running the programs and configuration they started with after it rebuilt them.
  `make start` now records what it starts the services with, and `make setup` restarts them when that changed.
- `make setup` kept a Veraison built from older sources after a patch changed them. The deployment now records the
  source trees it was built from, Veraison's and go-gen-ref's, and `make setup` builds it again when either
  changes, keeping its keys, certificates and stores.
- The secrets scan saw only what was committed: a dependency patch of 7 October carried `go.sum` lines that gitleaks
  takes for API keys (a module named `oauth2`), found only after the commit, before it was pushed. `make lint` now
  also scans the changes not yet committed, staged or not, and `.gitleaks.toml` allows `go.sum` lines in our patches
  by their form (a module, its version and a hash), and nothing else in them.
- The bench's RRPs accepted the software stand-in's results whenever the bench ran, hardware runs included:
  `bench.sh` wrote their configuration with `allow_simulated_tee`, and the stand-in's verifier ran beside the real
  ones. No hardware run used that path; the path is gone with the stand-in (the Demo Bank's trust zone never had it).
- A hardware run whose SSH session to the VM broke ended without a verdict
  (`e2e/evidence/20261007T045819Z-gcp-sev-snp-e2e-background-check`). The workload now runs in the VM detached from
  any session (`bench_guest_run`, `scripts/lib.sh`): the bench reads its output and its end with short calls, each
  made again when it fails, and starts it once, even when the call that started it broke after the VM ran it. It is
  tested live: with `BENCH_CHAOS_SSH=1` a real VM breaks the bench's SSH sessions on purpose
  ([docs/troubleshooting.md](docs/troubleshooting.md)). The SEV-SNP hardware checks also keep what the checker
  logged (`rrpverify-*.stderr.log`) and the EAR of each honest check (`ears/`).
- The verdict of a Demo Bank payment refused by the platform rule ended with the gateway's line break, so its
  `VERDICT` line was followed by an empty one (`scripts/verdict.py`); found in the release check, tested on its
  runs.

### Removed

- **The proof of concept's simulated parts**, as the bench runs nothing that stands in for the real thing: the
  Simulated plug-in (`platform/sim.go`) and its EAT reader, the CAI sidecar, the HTTP client and the PoC's CAAPI
  server with their Docker deployment, the `deploy/` scripts and the `est/` module with their mock CA, the PoC's
  guides, and the CAI's and the plug-in interface's tests, which ran on the Simulated plug-in and on stand-ins for
  the CAAPI and the CA ([CONTRIBUTING.md](CONTRIBUTING.md)). The CAI and the SEV-SNP and TDX plug-ins run in every
  hardware run. `git log` keeps what was removed.
- **The software stand-in TEE** (`platform.SimTEE`) and its verifier (`sim-verifier`), and with them the local mode
  (`PLATFORM=local`, the default until then), the stand-in's refusal scenarios (`SIM_DEBUG`, `SIM_LABEL`) and every
  test built on it: the bench runs nothing that stands in for the hardware. `UNAPPROVED=1 make demo` shows on
  hardware what `SIM_LABEL` showed on the stand-in; no cloud launches a debuggable guest, so no run shows that refusal
  ([docs/limits.md](docs/limits.md)).
- **Tests on stand-ins**, and `gateway.SignTestEAR`, which forged EARs and was compiled into the gateways: the
  gateways' tests on a fake Veraison or a fake Vault, the mutual TLS test on a CA of its own, the plug-ins' tests on a
  fake TSM device and made-up AMD certificates, the TDX verifier's on a fake Intel service. In their place, tests on
  real data and live services: the plug-in reads the reports and certificate tables of real Google Cloud and AWS runs,
  and checks their signatures; the certificate chain is completed on AWS's real table; the identity and group rules
  run on the approved launches; the TDX verifier fetches Intel's real revocation list; `make check-mtls` checks the
  live trust zone. The rule is in [CONTRIBUTING.md](CONTRIBUTING.md), "Tests".
- **The EST server's mock CA** (EST patch 0009). The fork's server made a mock CA at every start, issued its own TLS
  certificate from it when its configuration had no `tls` section, and used it as its CA unless a `tacra` or `attest`
  section replaced it. The bench's server runs only with the TACRA backend: it needs its `tls` and `tacra` sections,
  and refuses `mock_ca`, `attest` and any field it does not know. Patch 0011 takes the proof of concept's mock TEE
  (its Evidence format, the code that made it and the code that appraised it) and its mock attested CA out of the EST
  library, with the dependencies only they needed (`veraison/eat`, `go-cose`). `make test` now checks that no program
  the bench builds, its own or a third-party one, links a package named mock, fake or stub.
- **The tests of our third-party patches on stand-ins.** The EST backend's tests ran on a verifier, RRPs and a CA of
  their own (EST patch 0008). Veraison's revocation tests ran on a snapshot of AMD's CRLs at a stopped clock, its DER
  certificate table was made by re-encoding a PEM one, and its mitigation vectors were made up (Veraison patch 0008).
  go-gen-ref's parser tests built their reports from scratch (go-gen-ref patch 0003). They run now on AMD's CRLs
  fetched from its key server at the time of the test, on real Google Cloud and AWS reports and on the bench's CoRIM.
  The tests on the reference implementation's EST messages moved to a package of their own (EST patch 0010): their
  test binary had held the fork's tests, whose start creates a mock CA. The checks of the EST server's media types
  and Handle encoding through the server went with the removed tests; `make test-live` makes them on the running
  server (Added).
- **Made-up runs in the verdict tests**: two refused Targets with invented reasons, a result list written empty, an
  empty directory. The tests judge real runs instead: the six runs of the refusal scenarios, each refused for its own
  reason; one of them with one Target's reason taken from another; a real run with its Targets taken out; an attack
  run holding only the compared builds' results; and the run of 7 October that stopped before it wrote its results.

## Before: the TACRA proof of concept and the bench's first stages

The TWI SIG's proof of concept (from 12 August 2026), then the bench built on it from 28 September 2026 and rebuilt
and run again on 6 October (stages S1 to S5): the RRP gateways, the TDX verifier, the end-to-end and attack runs on
three platforms, the Demo Bank, mutual TLS between the components, Background Check, the redirection experiment. The
git history has each step; the runs are under `e2e/evidence/` and `hwcheck/evidence/`.
