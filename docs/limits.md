# What a run does not prove

A passing run shows that the protocol's checks hold on the platforms and configurations it ran. It does not show more.
Read this page before you cite a result.

## The software stand-in TEE proves the protocol, not the hardware

Locally, the "hardware" is a key in a file. A local run shows that every flow and every check works as specified; it
shows nothing about isolation, since anyone with the file can make the stand-in's reports. Only hardware runs
(`PLATFORM=gcp-snp`, `gcp-tdx`, `aws-snp`) involve a real TEE.

## What the trust zone does not check yet

- **The platform rule is the bench's, not a bank's.** Every RRP checks what the Attestation Results report about the
  platform ([../trust/README.md](../trust/README.md)): on SEV-SNP the product line, the minimum TCB from AMD's
  bulletins and SMT only with the microcode floor met; on TDX a TD under debug, profiled or migratable is refused. A
  bank would be stricter: the bench names no machine, since AWS's VLEK-signed reports carry no CHIP_ID, and it admits
  every product line it has floors for, EPYC Milan among them. Its floors are those of the bulletins read on
  7 October 2026: a new bulletin needs someone to raise them.
- **A TCB floor is not every mitigation.** For EPYC Milan, AMD-SB-3034 gives the attestation value of the fix for
  CVE-2025-54510 as TCB[SNP] 0x1D together with mitigation bit 4; AMD-SB-3020 names bit 1 for its own. The bits are in
  the report's mitigation vector (report version 5), which Veraison's Attestation Results do not carry, so no RRP
  rule can require them. The reports show them: no SEV-SNP host the bench has met sets bit 4 (0x10), though every one
  has TCB[SNP] 0x1D or above; Google Cloud's vector was 0xb in every run, AWS's 0xf, 0x10f or 0xfef, from 28 September
  to 7 October 2026 (the reports under `hwcheck/evidence/*-sev-snp/`). By AMD's value none of them attests that fix,
  and the bench admitted them all.
- **No hardware run shows a debuggable SEV-SNP guest refused.** Veraison, with our patch 0005, does not affirm a
  guest whose policy lets the hypervisor debug it or binds it to a migration agent, and it checks the AMD intermediate
  that signed the report's certificate (the ASK, or the ASVK for a VLEK) against AMD's revocation list. The clouds
  launch no debuggable guest, so the first is shown by Veraison's tests (`make test`), not on hardware; the stand-in's
  verifier refuses a debuggable instance in a run (`SIM_DEBUG=1 make demo`). The revocation list comes from AMD's key
  server (kdsintf.amd.com), once per validity period; while it cannot be fetched, SEV-SNP Evidence is refused.
- **Veraison and step-ca keep no list of callers.** Veraison's verification API takes any client certificate of the
  bench's root; step-ca authenticates the Credential Authority gateway by its provisioner's token alone.

## Reference values

- **The AWS SEV-SNP launch is trusted on first use.** Its measurement was taken from the first hardware run. Google
  signs endorsements for its own firmware, and each Google launch was approved only after its endorsement checked out
  (the Demo Bank checks them again at start); for AWS's firmware the bench has no endorsement
  and has not established the value independently, for example by a reproducible build
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

- **Known vulnerabilities in the pinned dependencies.** `govulncheck` (golang.org/x/vuln v1.8.0, 7 October 2026)
  finds these in code the bench reaches, each fixed in a later release:
  - Veraison, as pinned with our patches: `google.golang.org/grpc` v1.79.3 (GO-2026-6061, GO-2026-6348, GO-2026-6443;
    fixed in v1.82.1, v1.83.1, v1.82.2), `go.opentelemetry.io/otel/sdk` v1.39.0 (GO-2026-4394, GO-2026-6505; fixed in
    v1.40.0, v1.45.0), `golang.org/x/text` v0.37.0 (GO-2026-5970; fixed in v0.39.0). The bench's own modules, which
    build Veraison's code in, use fixed releases (grpc v1.83.2, x/text v0.41.0).
  - The EST server and the bench's `e2e` module: `github.com/go-chi/chi` v4.1.2 (GO-2026-4316, an open redirect in its
    RedirectSlashes middleware, which the code does not use: only the package's initialisation is reached). No release
    of chi v4 fixes it.

  The trust zone's services listen on 127.0.0.1; in the Demo Bank, the one port of the trust zone that workloads reach
  is the EST server's. Updating a component changes the tree the hardware runs tested, so it waits for a release with
  those runs repeated.

## Coverage

- **Three machine types**: Google Cloud `n2d-standard-2` (AMD Milan) and `c3-standard-4` (Intel TDX), AWS
  `c6a.large` (AMD Milan), in one zone each. Other instance types, processor generations, regions and clouds are not
  tested.
- **One Credential Acquisition System**: EST, through the GlobalSign EST server with TACRA's resources.
- **The channel between the CAI and the CAS Client inside the guest** is plain gRPC: the CAS is untrusted by design,
  so the bench does not protect it.

## Open questions this bench informs but does not settle

- Whether the RRP identifier belongs in the binding:
  [TACRA issue #20](https://github.com/TheBankster/rats-tacra/issues/20). `make redirect` measures what it prevents.
