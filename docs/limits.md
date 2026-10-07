# What a run does not prove

A passing run shows that the protocol's checks hold on the platforms and configurations it ran. It does not show more.
Read this page before you cite a result.

## The software stand-in TEE proves the protocol, not the hardware

Locally, the "hardware" is a key in a file. A local run shows that every flow and every check works as specified; it
shows nothing about isolation, since anyone with the file can make the stand-in's reports. Only hardware runs
(`PLATFORM=gcp-snp`, `gcp-tdx`, `aws-snp`) involve a real TEE.

## What the trust zone does not check yet

- **No platform policy on SEV-SNP and TDX.** The gateways accept a result when the verifier affirms it and the launch
  is approved. They set no minimum TCB (firmware and microcode versions), and no rule on the machine or the product.
  A platform with known-vulnerable firmware passes if its verifier affirms it.
- **A debuggable SEV-SNP guest is not refused, and AMD's intermediate is not checked for revocation.** The fix exists
  in an earlier branch of our Veraison work (commit `6bbeaf9`: refuse a debuggable guest; check the intermediate
  against AMD's CRL), but is not among the patches the bench applies (`third_party/veraison-services/patches/`). The
  stand-in's verifier does refuse a debuggable instance (`SIM_DEBUG=1 make demo`).
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
