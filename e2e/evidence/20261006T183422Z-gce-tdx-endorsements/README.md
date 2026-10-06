# Google's signed endorsements of the two GCP TDX firmware builds (06.10.2026, 18:34Z)

**Why:** the TDX e2e run `20261006T183028Z-gcp-tdx-e2e-passport` met MRTD `f21e6b48743fe14c…`.
- The bench admitted only `c1ee9c16e3afc506…`, so the TDX verifier refused every Target as `contraindicated` (fail
  closed, as the policy requires).
- The morning TDX runs had met `c1ee9c16…`.
- The demo-bank run of 28.09 (`20260928T212732Z-demo-bank`, "Reference values") had already met and approved both
  builds after checking their endorsements. The rebuilt bench's `bench.sh` carried over only the first. That gap was
  ours, from the port.

**Check:** `rrp/cmd/gce-endorsement`, which uses google/gce-tcb-verifier. For each MRTD it:
1. fetches the VMLaunchEndorsement Google publishes (bucket `gce_tcb_integrity`);
2. verifies that the signing certificate chains to the pinned root `e2e/bank/refvals/GCE-cc-tcb-root_1.crt`;
3. verifies that the signature over the golden measurement holds;
4. checks that the measurement is listed.

Before the check, the pinned root's SHA-256 `e876bc69…f18c` was compared with a fresh fetch from
`https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt` and found equal (`root-sha256.txt`).

| MRTD | Endorsed | Endorsement timestamp | SVN | Signer | File |
|---|---|---|---|---|---|
| `c1ee9c16e3afc506…70a5` | yes | 2026-05-21T23:52:45Z | 2 | GCE-uefi-signer, serial 30 | `tdx-c1ee9c16e3afc506.txt` |
| `f21e6b48743fe14c…e5d3` | yes | 2026-07-31T09:52:02Z | 2 | GCE-uefi-signer, serial 32 | `tdx-f21e6b48743fe14c.txt` |

**Decision:** `e2e/scripts/bench.sh` admits both, with a comment pointing here.
- It is the same operator step the demo bank's `approve` performs: a reference value that rests on the firmware
  builder's signature, not on a first observation.
- Both builds have the same SVN.

**For comparison, SEV-SNP** (launch MEASUREMENT read from today's saved reports at offset 0x90):
- GCP showed `ccdc5cf0…`, endorsed by Google on 2026-07-24.
- AWS showed `7a89ccea…`. It is in the bench list on first observation only: Google does not endorse AWS firmware,
  and we have not yet established it independently, for example from a reproducible build of that firmware.

  That remains an open caveat.
