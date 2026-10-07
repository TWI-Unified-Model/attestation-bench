# trust/: what the bench verifies against

Every file here is an input that the verifiers and the Relying Parties' policies trust. None is a secret. Each has a
source you can check again: `trust/check.sh` (or `make trust-check`) downloads the online ones, compares them byte for
byte, and checks that the approved SEV-SNP launches and Veraison's CoRIM agree.

| File | What it is | Source | Used by |
|---|---|---|---|
| `approved-launches.json` | The launches the packs approve: SEV-SNP launch measurements and TDX MRTDs. Each entry names its launch, its endorsement and the record of the check. | This repository's evidence, linked from each entry | `scripts/trustzone.py`: the policy of every Target, the TDX verifier's reference MRTDs |
| `amd-kds-milan-cert_chain.pem` | AMD's ASK (`SEV-Milan`) and ARK (`ARK-Milan`) | `https://kdsintf.amd.com/vcek/v1/Milan/cert_chain` | `hwcheck` (`rrpverify -ark`) |
| `veraison-corim-milan.cbor` | The CoRIM Veraison is provisioned with: the `ARK-Milan` trust anchor and a reference value for each approved SEV-SNP launch | Made with `hwcheck/cmd/mkcorim` from the AMD chain and SEV-SNP reports of the two launches (commit `d278459`, 28.09.2026) | `scripts/setup.sh`, the Demo Bank's trust zone |
| `platform-policy.json` | The platform rule every RRP applies besides the verifier's verdict: the SEV-SNP product lines and minimum TCB, SMT, the refused TD attributes. `sources` says where each value comes from. | AMD's and Google's security bulletins, cited in the file; the hosts the hardware runs met | `scripts/trustzone.py`: the `platform` of every gateway |
| `GCE-cc-tcb-root_1.crt` | Google's root for its signed launch endorsements (`GCE-cc-tcb-root`, valid until 2048) | `https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt` | `rrp/cmd/gce-endorsement`, the Demo Bank's `approve` |

SHA-256, as `trust/check.sh` prints them:

```
22e62f8d2c21a156470145fc75f7b5a377cb053ced3e97f0bd3f8d8ca5941ce6  amd-kds-milan-cert_chain.pem
77c4da9cec5c9213a8b5a8f9522cbafe7dc8c3cd762172dcc3d421040042166d  veraison-corim-milan.cbor
e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c  GCE-cc-tcb-root_1.crt
45cca58880e3adf0ca0c036b5c5b3b09f8d9816a28dd22155043d89a510ff455  platform-policy.json
```

## Where the approved launches come from

| Platform | Value | Endorsement |
|---|---|---|
| Google Cloud SEV-SNP, n2d-standard-2 | `ccdc5cf0…26fa` | Google's signature, checked 28.09.2026 |
| AWS SEV-SNP, c6a.large | `7a89ccea…c766` | **None.** Trust on first use, from the AWS hardware runs. Google does not endorse AWS firmware, and we have not yet established this value independently. |
| Google Cloud TDX, firmware build 1 | `c1ee9c16…70a5` | Google's signature, checked 28.09 and 06.10.2026 |
| Google Cloud TDX, firmware build 2 | `f21e6b48…e5d3` | Google's signature, checked 28.09 and 06.10.2026 |

A new Google Cloud VM may get either TDX firmware build; both were met on 06.10.2026.

## The platform rule

`platform-policy.json` is what the RRPs require of the platform, in the Attestation Results, besides the verifier's
"affirming" (`rrp/internal/gateway/platform.go`). What the bench requires, why, and what a bank would require instead:

| Rule | The bench | Why | A bank |
|---|---|---|---|
| SEV-SNP product lines | Milan, Genoa, Turin | every line AMD's bulletins give floors for; every SEV-SNP host the bench has run on, on Google Cloud and on AWS, is an EPYC Milan | only the lines it has assessed |
| A named machine | not required | AWS signs its reports with its VLEK, which names no machine | required, from its own list of CHIP_IDs |
| Minimum TCB, on REPORTED_TCB and COMMITTED_TCB | Milan: bootloader 4, SNP 0x1D, microcode 0xDE; Genoa: SNP 0x1C, microcode 0x56; Turin: SNP 0x5, microcode 0x51 | the highest values AMD-SB-3027 and AMD-SB-3034 print for each line; Google's GCP-2025-007 for Milan's bootloader | the same, kept current |
| SMT | only with the microcode floor met | every host the bench has run on has SMT on | the same, or forbidden |
| SEV mitigation vector bits | carried in the results (go-gen-ref patch 0002), none required yet | no host the bench has met sets bit 4, which AMD-SB-3034 names for Milan: requiring it refuses every SEV-SNP run ([../docs/limits.md](../docs/limits.md)) | the bits AMD-SB-3020 and AMD-SB-3034 name, in both vectors |
| PLATFORM_INFO bits | Milan and Genoa: bit 5, ALIAS_CHECK_COMPLETE | AMD-SB-3015's attestation evidence of the BadRAM fix; every host sets it | the same |
| TDX | a TD under debug (bits 3:0), profiled (bits 15:4) or migratable (bit 29) is refused | what the bench's TDX verifier refuses by default, checked again by the RRP | the same |

The hosts the hardware runs met on 7 October 2026 sit exactly at the Milan floors: REPORTED_TCB bootloader 4, TEE 0,
SNP 29 (0x1D), microcode 222 (0xDE), on Google Cloud and on AWS. When AMD publishes a new bulletin, raise the floors
with its values and source, then write the configuration again: `make config && make stop start`. A host below a
floor is refused, and the refusal names the component, its value and the floor.

## Approving a new launch

1. Establish where the value comes from. For Google Cloud, Google's signed endorsement must verify to the pinned
   root:
   `(cd rrp && GOWORK=off go run ./cmd/gce-endorsement -root ../trust/GCE-cc-tcb-root_1.crt -tdx <MRTD>)` (or
   `-snp <MEASUREMENT>`).
2. Add it to `approved-launches.json` with its launch, its endorsement and the record of the check.
3. For SEV-SNP, Veraison needs a reference value for it as well: make a new `veraison-corim-milan.cbor` with
   `hwcheck/cmd/mkcorim`. `trust/check.sh` and `scripts/trustzone.py` refuse an approved SEV-SNP launch that the
   CoRIM lacks.
4. Write the configuration again and restart the trust zone: `make config && make stop start`.
