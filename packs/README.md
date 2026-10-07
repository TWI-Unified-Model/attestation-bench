# packs/: what a bank issues, as data

A pack describes one bank's trust zone: which Targets it serves, which RRP serves each Target, what the workload is
called and how fresh an EAR must be. `scripts/trustzone.py` turns a pack, plus the launches in
`trust/approved-launches.json`, into the configuration of every service. The local bench and the cloud Demo Bank use
the same program, so a pack behaves the same in both.

| Pack | Used by | What it holds |
|---|---|---|
| `tacra-bench/pack.json` | the local bench (`make setup`, `make config`) | 12 Targets: one per Freshness Kind for each RRP, plus two Targets that take one platform's verifier only; a second Credential Authority for the #20 experiment |
| `demo-bank/pack.json` | the cloud Demo Bank (`make bank-up`) | 2 Targets: the ledger database's client certificate, and the fraud service's API key in the signed container |

`make bank-new NAME=…` makes another bank's pack from the Demo Bank's, under its own names; `BANK=… make bank-up`
brings it up ([../docs/demo-bank.md](../docs/demo-bank.md)).

## Fields

```jsonc
{
 "name": "tacra-bench",
 "infra_domain": "bench.tacra.example",          // client certificates are named <component>.<infra_domain>
 "workload": {"hint": "...", "sans": ["..."]},    // the workload's name, and the SANs of its certificate
 "ear": {"max_age": 120, "skew": 5},              // how old an EAR may be, and the clock skew allowed (seconds)
 "rrps": [ ... ],
 "targets": [ ... ]
}
```

**An RRP** is a Credential Authority gateway (issues X.509 certificates through step-ca) or a Secret Vault gateway
(releases secrets from HashiCorp Vault, in the signed container).

| Field | Meaning |
|---|---|
| `name` | how Targets refer to it |
| `kind` | `credential-authority` or `secret-vault`; one of each at most |
| `rrp_id` | the RRP identifier it binds into the Evidence |
| `listen` | its address, `127.0.0.1:<port>` |
| `same_as`, `service` | instead of `kind`: a copy of another RRP with its own `rrp_id`, `listen` and service name, which the EST server never routes to (a second bank, for the redirection experiment) |

**A Target** is what a workload asks for.

| Field | Meaning |
|---|---|
| `target` | its URL |
| `rrp` | the RRP that serves it |
| `credential_types` | `x509`, `api-key` |
| `freshness_kind` | `present-nonce`, `present-epoch`, `absent-epoch`, `absent-timestamp`, `absent-none` |
| `expires_in` | for `present-*`: how long a Freshness Handle lives (seconds) |
| `max_age`, `clock_skew` | for `absent-timestamp`: how old the timestamp may be, and the skew allowed (seconds) |
| `verifiers` | `"all"`, or the verifiers it takes by name: `veraison` (SEV-SNP), `tdx` (TDX), `sim` (the software stand-in, laptop only) |
| `acceptable` | the algorithms it accepts: `ecdsa-p256-sha256` for a CSR; `MLKEM768-P256+HKDF-SHA256+AES-256-GCM` for the signed container |
| `certificate_validity` | Credential Authority Targets: how long the certificate is valid, e.g. `1h` |
| `secret` | Secret Vault Targets: `path` in Vault (mount `secret`), `policy_version`, and the key block's `purpose`, `algorithm`, `validity_seconds` |

Every Target admits the workload only from an approved launch: the measurements in `trust/approved-launches.json`,
plus, on a laptop, the software stand-in's one launch; and only on a platform the rule in `trust/platform-policy.json`
admits, which applies to every pack.

## Changing a pack

1. Edit the pack. `scripts/trustzone.py` refuses a pack that does not hold together and says what is wrong: a Target
   whose RRP does not exist, an unknown Freshness Kind, a verifier the trust zone does not run, a Secret Vault Target
   without a `secret`.
2. Write the configuration again and restart: `make config && make stop start`.

The end-to-end runs (`make demo`, on a laptop or on hardware) ask for every Target whose `verifiers` is `"all"`, each
for the credential its RRP issues: `e2e/scripts/guest_config.py` reads the same pack.
