# Security

## Reporting a vulnerability

Report it privately to the repository's owner, [@nikolaichuk7](https://github.com/nikolaichuk7), not in an issue or a
pull request. Say what you found, how to reproduce it (a run directory, if you have one), and what it lets an attacker
do. You will get an answer, and credit if you want it.

A weakness in TACRA itself, not in this bench, concerns the drafts' authors as well: say so, and it will be taken to
them with your agreement.

## What is in scope

- The bench's own code: the RRP gateways, the TDX and stand-in verifiers, the signed container, the scripts, the
  configuration generator, and our patches to the third-party components.
- A run that passes when it should not: an attack the bench says it refuses that gets through
  ([docs/attacks.md](docs/attacks.md)), or a check that cannot fail.

## What is not

- **The software stand-in TEE.** It gives no security by design ([docs/concepts.md](docs/concepts.md)).
- **The local trust zone as a production deployment.** It runs on one machine, with keys in files and a single Vault
  unseal key, for testing ([docs/limits.md](docs/limits.md)).
- The limits [docs/limits.md](docs/limits.md) already names.

## Supported versions

The `main` branch.
