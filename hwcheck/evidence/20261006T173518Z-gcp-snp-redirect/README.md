# The #19/#20 redirection experiment on GCP SEV-SNP: does the RRP identifier belong in the binding? (06.10.2026)

**Question (TheBankster/rats-tacra#20).** The conduit (CAS) is untrusted. If it takes Evidence the Attester produced
for one Relying Party and offers it to a second one, does the second RRP issue? And does the RRP identifier in the
binding change the answer?

**Method.** One Evidence per Freshness Kind, produced in a real SEV-SNP guest (n2d-standard-2, Milan, VCEK), is offered
through the deployed gateways to the CA it was made for (ca1) and to a second CA (ca2, a different rrp_id, the same
step-ca, verifiers and Target policy). Two passes:
- **with-rrp-id:** each CA binds its own rrp_id (TACRA as written).
- **no-rrp-id:** both CAs bind no rrp_id (`omit_rrp_id_in_binding`, the variant #20 asks about).

Background Check, so the conduit holds the Evidence and routes it. Code `code-rev.txt`. The guest ran hwrun offline;
`rrp-issue` (the conduit) posted to both CAs from this machine.

## Result (`results.jsonl`)
| Pass | Kind | ca1 (its own CA) | ca2 (another CA) | Why ca2 behaves so |
|---|---|---|---|---|
| with-rrp-id | present-nonce | ISSUED | refused | freshness: ca2 never minted that nonce |
| with-rrp-id | present-epoch | ISSUED | refused | binding: ca2 recomputes with its rrp_id → contraindicated |
| with-rrp-id | absent-epoch | ISSUED | refused | binding: contraindicated |
| with-rrp-id | absent-timestamp | ISSUED | refused | binding: contraindicated |
| with-rrp-id | absent-none | ISSUED | refused | binding: contraindicated |
| no-rrp-id | present-nonce | ISSUED | **refused** | freshness: ca2 never minted that nonce |
| no-rrp-id | present-epoch | ISSUED | **ISSUED** | nothing ties the Evidence to one RRP |
| no-rrp-id | absent-epoch | ISSUED | **ISSUED** | — |
| no-rrp-id | absent-timestamp | ISSUED | **ISSUED** | — |
| no-rrp-id | absent-none | ISSUED | **ISSUED** | — |

## What it shows
1. **With the RRP identifier in the binding, redirection is refused for every Freshness Kind.** ca2 recomputes the
   binding with its own identifier, so the Evidence does not match and the Verifier returns "contraindicated".
2. **Without it, the only thing that still stops redirection is an RRP-issued, single-use nonce** (`present-nonce`):
   ca2 never minted it, so it refuses on freshness. For every other kind — a shared epoch, a locally-held epoch, a
   timestamp, or no freshness at all — one Evidence is accepted at **two** CAs, and both issue a credential.
3. So the RRP identifier is what binds Evidence to one RRP when freshness is not an RRP's own nonce. This matches the
   ProVerif models (`~/dev/tacra-est-pub/formal/`, enrollment-*-norrp vs -rrp) and the precedent survey
   (`_LIBRARY/attestation/rp-identity-in-attestation-precedents.md`), now on real hardware through the deployed CAs.

Every credential ca1 issued is a real certificate from the bench's step-ca (`results.jsonl`, cert_serial/cert_issuer).

**Cloud:** the VM was deleted (`vm-deleted.txt`); checked again afterwards: 0 instances, 0 disks.
**Not covered here:** TDX and AWS (separate runs); the Secret Vault (Retrieval) side; the attack is on the CA path.
