# trust/: what the bench verifies against

Every file here is an input that the verifiers and the Relying Parties' policies trust. None is a secret. Each has a
source you can check again: `trust/check.sh` (or `make trust-check`) downloads the online ones, compares them byte for
byte, and checks that the approved SEV-SNP launches and Veraison's CoRIM agree.

| File | What it is | Source | Used by |
|---|---|---|---|
| `approved-launches.json` | The launches the packs approve: SEV-SNP launch measurements and TDX MRTDs. Each entry names its launch, its endorsement and the record of the check. | This repository's evidence, linked from each entry | `scripts/trustzone.py`: the policy of every Target, the TDX verifier's reference MRTDs |
| `amd-kds-milan-cert_chain.pem` | AMD's ASK (`SEV-Milan`) and ARK (`ARK-Milan`) | `https://kdsintf.amd.com/vcek/v1/Milan/cert_chain` | `hwcheck` (`rrpverify -ark`) |
| `veraison-corim-milan.cbor` | The CoRIM Veraison is provisioned with: the `ARK-Milan` trust anchor and a reference value for each approved SEV-SNP launch | Made with `hwcheck/cmd/mkcorim` from the AMD chain and SEV-SNP reports of the two launches (commit `d278459`, 28.09.2026) | `scripts/setup.sh`, the Demo Bank's trust zone |
| `GCE-cc-tcb-root_1.crt` | Google's root for its signed launch endorsements (`GCE-cc-tcb-root`, valid until 2048) | `https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt` | `rrp/cmd/gce-endorsement`, the Demo Bank's `approve` |

SHA-256, as `trust/check.sh` prints them:

```
22e62f8d2c21a156470145fc75f7b5a377cb053ced3e97f0bd3f8d8ca5941ce6  amd-kds-milan-cert_chain.pem
77c4da9cec5c9213a8b5a8f9522cbafe7dc8c3cd762172dcc3d421040042166d  veraison-corim-milan.cbor
e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c  GCE-cc-tcb-root_1.crt
```

## Where the approved launches come from

| Platform | Value | Endorsement |
|---|---|---|
| Google Cloud SEV-SNP, n2d-standard-2 | `ccdc5cf0…26fa` | Google's signature, checked 28.09.2026 |
| AWS SEV-SNP, c6a.large | `7a89ccea…c766` | **None.** Trust on first use, from the AWS hardware runs. Google does not endorse AWS firmware, and we have not yet established this value independently. |
| Google Cloud TDX, firmware build 1 | `c1ee9c16…70a5` | Google's signature, checked 28.09 and 06.10.2026 |
| Google Cloud TDX, firmware build 2 | `f21e6b48…e5d3` | Google's signature, checked 28.09 and 06.10.2026 |

A new Google Cloud VM may get either TDX firmware build; both were met on 06.10.2026.

## Approving a new launch

1. Establish where the value comes from. For Google Cloud, Google's signed endorsement must verify to the pinned
   root:
   `(cd rrp && go run ./cmd/gce-endorsement -root ../trust/GCE-cc-tcb-root_1.crt -tdx <MRTD>)` (or `-snp <MEASUREMENT>`).
2. Add it to `approved-launches.json` with its launch, its endorsement and the record of the check.
3. For SEV-SNP, Veraison needs a reference value for it as well: make a new `veraison-corim-milan.cbor` with
   `hwcheck/cmd/mkcorim`. `trust/check.sh` and `scripts/trustzone.py` refuse an approved SEV-SNP launch that the
   CoRIM lacks.
4. Write the configuration again and restart the trust zone: `make config && make stop start`.
