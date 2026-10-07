# What a run does not prove

A passing run shows that the protocol's checks hold on the platforms and configurations it ran. It does not show more.
Read this page before you cite a result.

## What the trust zone does not check yet

- **The platform rule is the bench's, not a bank's.** Every RRP checks what the Attestation Results report about the
  platform ([../trust/README.md](../trust/README.md)): on SEV-SNP the product line, the minimum TCB from AMD's
  bulletins, the BadRAM bit of PLATFORM_INFO and SMT only with the microcode floor met; on TDX a TD under debug,
  profiled or migratable is refused. A
  bank would be stricter: the bench names no machine, since AWS's VLEK-signed reports carry no CHIP_ID, and it admits
  every product line it has floors for, EPYC Milan among them. Its floors are those of the bulletins read on
  7 October 2026: a new bulletin needs someone to raise them.
- **A TCB floor is not every mitigation, and the bench does not yet require AMD's mitigation bits.** For EPYC Milan,
  AMD-SB-3034 gives the attestation value of the fix for CVE-2025-54510 as TCB[SNP] 0x1D together with mitigation
  bit 4; AMD-SB-3020 names bit 1 for its own. The bits are in the report's mitigation vectors (report version 5). The
  Attestation Results carry both vectors (our go-gen-ref patch 0002), and the rule can require bits
  (`required_mitigation_bits`), but the bench's rule requires none of these yet: no SEV-SNP host the bench has met sets
  bit 4 (0x10), though every one has TCB[SNP] 0x1D or above. Google Cloud's vector was 0xb in every run, AWS's 0xf,
  0x10f or 0xfef, from 28 September to 7 October 2026 (the reports under `hwcheck/evidence/*-sev-snp/`, read by
  `hwcheck/cmd/snpreport`: [results.md](results.md)). By AMD's value none of them attests that fix. Under a rule that
  asks for AMD's bits, every one is refused, naming bit 4 and its bulletin (tested on the real results of both clouds:
  `TestMitigationAndPlatformInfoBits`, `rrp/internal/gateway`). The rule does require PLATFORM_INFO bit 5, the
  evidence of the BadRAM fix (AMD-SB-3015), which every host sets.
- **No hardware run shows a debuggable SEV-SNP guest refused.** Veraison, with our patch 0005, does not affirm a
  guest whose policy lets the hypervisor debug it or binds it to a migration agent, and it checks the AMD intermediate
  that signed the report's certificate (the ASK, or the ASVK for a VLEK) against AMD's revocation list. The clouds
  launch no debuggable guest, so no run shows the first; the patch's tests do (`make test`). The revocation list comes
  from AMD's key server (kdsintf.amd.com), once per validity period; while it cannot be fetched, SEV-SNP Evidence is
  refused.
- **Veraison and step-ca keep no list of callers.** Veraison's verification API takes any client certificate of the
  bench's root; step-ca authenticates the Credential Authority gateway by its provisioner's token alone.

## Reference values

- **The AWS SEV-SNP launch rests on AWS's published binary, not on a reproduced build.** Google signs endorsements
  for its own firmware, and each Google launch was approved only after its endorsement checked out (the Demo Bank
  checks them again at start). AWS signs none. The approved AWS value is the measurement of AWS's published EC2
  SEV-SNP firmware (release 20260814), which `make trust-check` and the Demo Bank compute again from that binary. A
  rebuild from AWS's source, as AWS's README says, gives a different binary and a different measurement, and the
  bench has not found why. So the reports show that EC2 runs the binary AWS published; that this binary is what AWS's
  published source builds rests on AWS's word, which the bench could not check
  ([../trust/README.md](../trust/README.md)).
- **New firmware needs an operator.** When a cloud deploys a new firmware build, its VMs are refused until someone
  checks the endorsement and approves the build. The verifiers do not consult endorsements by themselves.

## Time

The `absent-timestamp` kind takes the guest's own clock as the trusted clock the draft calls for. Whether a confidential
VM's clock can be trusted depends on the platform and its configuration; the bench does not test it.

## Keys and secrets

- The trust zone's keys are files on its disk, and Vault runs with a single unseal key there. A bank would keep them in
  an HSM or a cloud KMS (tacra-est requirement N5).
- The trust zone itself runs in a SEV-SNP VM in the Demo Bank, but attests itself to no one.

## Third-party versions

- **No known vulnerability reached, two left unreached.** `govulncheck` (golang.org/x/vuln v1.8.0, 7 October 2026)
  finds no vulnerability that the bench's code reaches: none in its eleven Go modules (the three builds of `hwcheck`
  among them), none in the programs it deploys from Veraison and the EST server. Our patches moved them to fixed
  releases:
  - Veraison, patch 0007: `google.golang.org/grpc` v1.79.3 to v1.83.2 (GO-2026-6061, GO-2026-6348, GO-2026-6443),
    `go.opentelemetry.io/otel` v1.39.0 to v1.45.0 (GO-2026-4394, GO-2026-6505), `golang.org/x/text` v0.37.0 to
    v0.41.0 (GO-2026-5970), and, for findings not reached, `filippo.io/edwards25519` v1.1.1, `golang.org/x/crypto`
    v0.56.0, `golang.org/x/mod` v0.40.0.
  - The EST server, patch 0007: `github.com/go-chi/chi` v4.1.2, which no release fixes (GO-2026-4316), to
    `github.com/go-chi/chi/v5` v5.3.2, and `golang.org/x/crypto` v0.56.0; the bench's `e2e` module follows.

  Left, and not reached: GO-2026-5932 in `golang.org/x/crypto` (no fixed release exists) and, in Veraison,
  GO-2025-3660 in `github.com/open-policy-agent/opa` v0.68.0 (fixed in v1.4.0, a major version that changes how Rego
  policies are read). The builds `hwcheck` compares with (Veraison as forked, and with the DER fixes only) keep their
  upstream pins: they are compared, never deployed.

## Coverage

- **Three machine types**: Google Cloud `n2d-standard-2` (AMD Milan) and `c3-standard-4` (Intel TDX), AWS
  `c6a.large` (AMD Milan), in one zone each. Other instance types, processor generations, regions and clouds are not
  tested.
- **One Credential Acquisition System**: EST, through the GlobalSign EST server with TACRA's resources.
- **The channel between the CAI and the CAS Client inside the guest** is plain gRPC: the CAS is untrusted by design,
  so the bench does not protect it.
- **The EST server's wire format is checked on the reference implementation's messages, not through the running
  server.** Our EST patches take the reference implementation's media types (`application/est-attest-enroll+json`,
  `application/est-attest-retrieve+json`) and `application/json`, answer any other with 415, and send the Handle of
  `attest-initiate` as unpadded base64url. The test that showed this through the server ran it with a CA of its own
  and was removed (EST patch 0008). The message types are still checked on the reference implementation's messages
  (`internal/refvectors`), and every hardware run goes through the server with the bench's own client; the media
  types, the 415 and the Handle's encoding wait for a test against the live server.
- **The plug-in's own refusals of a wrong device answer are not tested.** The SEV-SNP and TDX plug-ins refuse a
  report from another provider and one whose report data is not the binding value they asked for. No confidential
  VM answers that way, and the bench runs nothing that stands in for the device, so no test reaches those branches.
  An RRP refuses such Evidence anyway (`make attacks`).

## Open questions this bench informs but does not settle

- Whether the RRP identifier belongs in the binding:
  [TACRA issue #20](https://github.com/TheBankster/rats-tacra/issues/20). `make redirect` measures what it prevents.
