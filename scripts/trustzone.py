#!/usr/bin/env python3
"""Writes a trust zone's configuration from a pack and the approved launches.

    trustzone.py --home DIR --veraison DIR --pack packs/NAME/pack.json [options]

A trust zone is what one bank runs to give credentials to attested workloads (tacra-est): the EST server, the one
port workloads reach; the Credential Authority and Secret Vault gateways, the RRPs; the verifiers (Veraison for
SEV-SNP, the TDX verifier); step-ca and HashiCorp Vault. The local
bench (e2e/scripts/bench.sh config) and the Demo Bank's trust VM (e2e/bank/remote/trust.sh) both write their
configuration with this program, so the two cannot drift apart.

The pack says what the bank issues: its Targets, the RRPs that serve them, the workload's names and the EAR policy
(packs/README.md). trust/approved-launches.json says which launches the bank admits, and trust/platform-policy.json
which platforms: the product lines, the minimum TCB, the PLATFORM_INFO and mitigation bits and SMT on SEV-SNP, the
TD attributes on TDX, which every RRP checks in the Attestation Results besides the verifier's "affirming". The options say where the trust zone lives and
how it runs.

Under --home it writes:
  config/<service>.json           the gateways, the EST server, the TDX verifier
  tls/clients/<name>.crt|.key     each component's client certificate under the home's TLS root, tls/root.crt (mutual
                                  TLS, tacra-est N23); issued when absent or within 14 days of its end
  gateways/veraison.ear.jwk       Veraison's EAR key, given to the RRPs as a file (N24: never fetched from Veraison)
  vault/config.hcl                Vault: TLS 1.3, a client certificate of the home's root required
and it edits two files the services own: Veraison's config.yaml (its verification API requires a client certificate
of the home's root) and step-ca's ca.json (TLS 1.3). Everything else under --home (the TLS root and the services'
server certificates, step-ca, Vault's data, the gateways' keys and tokens) the caller creates.

It refuses an approved SEV-SNP launch that Veraison's CoRIM (--corim) holds no reference value for: Veraison would not
affirm it, so the bank would approve a launch it can never admit.
"""

import argparse
import datetime
import json
import os
import re
import sys
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KINDS = ("present-nonce", "present-epoch", "absent-epoch", "absent-timestamp", "absent-none")
FRESHNESS_PARAMS = ("expires_in", "max_age", "clock_skew")
INFRA = ("est-server", "ca-gateway", "vault-gateway", "operator")  # the components with a client certificate
SERVICE = {"credential-authority": "ca-gateway", "secret-vault": "vault-gateway"}  # an RRP kind's program


class PackError(Exception):
    pass


def main():
    a = parse_args()
    home = os.path.abspath(a.home)
    logs = os.path.abspath(a.logs or home)
    vd = os.path.abspath(a.veraison)
    pack = load_pack(a.pack)
    approved = json.loads(Path(a.approved).read_text())
    platform = with_waivers(load_platform(a.platform), pack)
    snp = [e["measurement"] for e in approved["sev-snp"]]
    tdx = [e["mrtd"] for e in approved["tdx"]]
    check_corim(snp, a.corim)

    client_certificates(home, pack["infra_domain"])
    measurements = snp + tdx

    root = f"{home}/tls/root.crt"
    infra = {n: f"{n}.{pack['infra_domain']}" for n in INFRA}
    verifiers = site_verifiers(home, vd, root)
    everyone = [v["name"] for v in verifiers]
    common = {
        "verifiers": verifiers,
        "ear": pack["ear"],
        "epoch_file": f"{home}/epoch.hex",
        "rats_model": a.rats_model,
        "client_ca": root,
        "clients": [infra["est-server"]],
        "platform": platform,
    }

    rrps, est_rrps, est_targets = {}, {}, {}
    for r in pack["rrps"]:
        if "same_as" in r:
            continue
        targets = {
            t["target"]: target_config(t, pack["workload"], measurements, everyone)
            for t in pack["targets"]
            if t["rrp"] == r["name"]
        }
        svc = SERVICE[r["kind"]]
        c = dict(
            common,
            **identity(home, svc),
            rrp_id=r["rrp_id"],
            listen=r["listen"],
            tls_cert=f"{home}/tls/{svc}.crt",
            tls_key=f"{home}/tls/{svc}.key",
            targets=targets,
        )
        if r["kind"] == "credential-authority":
            c["step_ca"] = {
                "url": "https://127.0.0.1:9000",
                "root": f"{home}/step/certs/root_ca.crt",
                "provisioner": "tacra-ca-gateway",
                "provisioner_key": f"{home}/gateways/ca-provisioner.jwk",
            }
        else:
            c.update(
                vault={
                    "addr": "https://127.0.0.1:8200",
                    "ca": root,
                    "mount": "secret",
                    "token_file": f"{home}/gateways/vault-gateway.token",
                },
                kem_keys=f"{home}/gateways/vault-kem.json",
                sign_key=f"{home}/gateways/vault-sign.key",
            )
        rrps[r["name"]] = c
        est_rrps[r["name"]] = {
            "url": f"https://{r['listen']}",
            "ca": root,
            "rrp_id": r["rrp_id"],
            "mode": "enroll" if r["kind"] == "credential-authority" else "retrieve",
            "rats_model": a.rats_model,
            "verifiers": everyone,
        }
        est_targets.update({t: r["name"] for t in targets})
    # An RRP "same_as" another is a copy of it with its own identifier and listener, which the honest EST server never
    # routes to: the second Credential Authority of the #19/#20 redirection experiment ("another bank").
    for r in pack["rrps"]:
        if "same_as" in r:
            rrps[r["name"]] = dict(rrps[r["same_as"]], rrp_id=r["rrp_id"], listen=r["listen"])
    redirection_variants(pack, rrps, omit_rrp_id=a.omit_rrp_id, own_epochs=a.own_epochs, est_rrps=est_rrps)

    est = est_server(home, logs, a.est_listen, vd, root, verifiers, est_rrps, est_targets)
    others = [infra["est-server"], infra["ca-gateway"], infra["vault-gateway"]]
    files = [(r.get("service") or SERVICE[r["kind"]], rrps[r["name"]]) for r in pack["rrps"]]
    files.append(("est-server", est))
    files.append(
        (
            "tdx-verifier",
            {
                "listen": "127.0.0.1:8453",
                "tls_cert": f"{home}/tls/tdx-verifier.crt",
                "tls_key": f"{home}/tls/tdx-verifier.key",
                "client_ca": root,
                "clients": others,
                "signing_key": f"{home}/secrets/tdx-verifier.jwk",
                "reference_mrtd": tdx,
            },
        )
    )
    os.makedirs(f"{home}/config", exist_ok=True)
    for name, c in files:
        p = f"{home}/config/{name}.json"
        with open(p, "w") as f:
            json.dump(c, f, indent=1)
        os.chmod(p, 0o600)

    veraison_ear_key(home, vd)
    veraison_client_ca(vd, root)
    vault_hcl(home, root)
    step_ca_tls13(home)
    print(f"configuration written to {home}/config (pack {pack['name']}, RATS model: {a.rats_model})")


def parse_args():
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0], epilog="See the module's header for what it writes."
    )
    p.add_argument("--home", required=True, help="the trust zone's directory (BENCH_HOME on the bench)")
    p.add_argument("--veraison", required=True, help="the Veraison deployment (VERAISON_DEPLOYMENT on the bench)")
    p.add_argument("--pack", required=True, help="the pack, packs/<name>/pack.json")
    p.add_argument(
        "--approved",
        default=os.path.join(REPO, "trust", "approved-launches.json"),
        help="the approved launches (default trust/approved-launches.json)",
    )
    p.add_argument(
        "--platform",
        default=os.path.join(REPO, "trust", "platform-policy.json"),
        help="the platform rule every RRP applies (default trust/platform-policy.json)",
    )
    p.add_argument(
        "--corim",
        default=os.path.join(REPO, "trust", "veraison-corim-milan.cbor"),
        help="the CoRIM Veraison is provisioned with (default trust/veraison-corim-milan.cbor)",
    )
    p.add_argument("--logs", help="where the EST server writes its log (default: --home)")
    p.add_argument("--est-listen", default="127.0.0.1:18443", help="the EST server's address (default 127.0.0.1:18443)")
    p.add_argument(
        "--rats-model",
        choices=("passport", "background-check"),
        default="passport",
        help="who asks the verifiers: the EST server (passport) or the gateways (background-check)",
    )
    p.add_argument("--omit-rrp-id", action="store_true", help="the #20 variant: the RRPs bind no RRP identifier")
    p.add_argument(
        "--own-epochs",
        action="store_true",
        help="a redirection variant: each copy of an RRP (same_as) keeps an epoch marker of its own",
    )
    return p.parse_args()


def load_platform(path):
    """The platform rule as the gateways take it (rrp/internal/gateway/platform.go): the file's sevsnp and tdx parts.
    The rest of the file says where each value comes from."""
    p = json.loads(Path(path).read_text())
    rule = {k: p[k] for k in ("sevsnp", "tdx") if k in p}
    if not rule:
        sys.exit(f"{path}: neither a sevsnp nor a tdx rule")
    return rule


def with_waivers(platform, pack):
    """The platform rule with the pack's named waivers (platform_waivers): required SEV-SNP mitigation bits the pack's
    RRPs admit Evidence without, each recorded by the RRP whenever it applies it. A pack can waive a required bit and
    nothing else; a bank's pack names none (packs/README.md)."""
    waivers = pack.get("platform_waivers") or {}
    if set(waivers) - {"sevsnp"} or set(waivers.get("sevsnp") or {}) - {"mitigation_waivers"}:
        raise PackError("platform_waivers: only sevsnp.mitigation_waivers can be waived")
    named = (waivers.get("sevsnp") or {}).get("mitigation_waivers") or {}
    required = (platform.get("sevsnp") or {}).get("required_mitigation_bits") or {}
    for product, bits in named.items():
        for bit, name in bits.items():
            if bit not in (required.get(product) or {}):
                raise PackError(
                    f"platform_waivers: {product} bit {bit} is waived but the platform rule does not require it"
                )
            if not str(name).strip():
                raise PackError(f"platform_waivers: {product} bit {bit} has no name")
    if named:
        platform = json.loads(json.dumps(platform))
        platform["sevsnp"]["mitigation_waivers"] = named
    return platform


def load_pack(path):
    """Reads a pack and refuses one that does not hold together, saying what is wrong."""
    pack = json.loads(Path(path).read_text())
    for k in ("name", "infra_domain", "workload", "ear", "rrps", "targets"):
        if k not in pack:
            raise PackError(f"{path}: no {k!r}")
    names = [r["name"] for r in pack["rrps"]]
    if len(set(names)) != len(names):
        raise PackError(f"{path}: two RRPs share a name")
    # one plain RRP of each kind (the trust zone runs one ca-gateway and one vault-gateway, each with its client
    # certificate); an RRP "same_as" a plain one is a copy of it, run as its own service under its own name
    kinds, services = [], list(SERVICE.values())
    for r in pack["rrps"]:
        if "same_as" in r:
            if r["same_as"] not in names or "same_as" in by_name(pack, r["same_as"]):
                raise PackError(f"{path}: RRP {r['name']!r} is the same as {r['same_as']!r}, which is not a plain RRP")
            if not r.get("service") or r["service"] in services:
                raise PackError(f"{path}: RRP {r['name']!r} needs a service name of its own")
            services.append(r["service"])
        elif r.get("kind") not in SERVICE:
            raise PackError(f"{path}: RRP {r.get('name')!r}: kind must be credential-authority or secret-vault")
        elif r["kind"] in kinds:
            raise PackError(f"{path}: two {r['kind']} RRPs; the second can only be a same_as copy of the first")
        else:
            kinds.append(r["kind"])
    available = ["veraison", "tdx"]
    seen = set()
    for t in pack["targets"]:
        where = f"{path}: Target {t.get('target')!r}"
        if t["target"] in seen:
            raise PackError(f"{where} appears twice")
        seen.add(t["target"])
        if t.get("rrp") not in names or "same_as" in by_name(pack, t["rrp"]):
            raise PackError(f"{where}: rrp must name a plain RRP of the pack")
        if t.get("freshness_kind") not in KINDS:
            raise PackError(f"{where}: freshness_kind must be one of {', '.join(KINDS)}")
        if t["verifiers"] != "all" and not set(t["verifiers"]) <= set(available):
            raise PackError(f"{where}: takes a verifier this trust zone does not run (it runs {', '.join(available)})")
        vault = by_name(pack, t["rrp"])["kind"] == "secret-vault"
        if vault != ("secret" in t) or vault == ("certificate_validity" in t):
            raise PackError(
                f"{where}: a Secret Vault Target needs 'secret', a Credential Authority Target "
                "'certificate_validity', and neither the other"
            )
        others = t.get("other_groups", {})
        if others and not vault:
            raise PackError(f"{where}: other_groups belong to a Secret Vault Target")
        if pack["workload"]["hint"] in others or not all("path" in g for g in others.values()):
            raise PackError(
                f"{where}: each of other_groups names another Credential Hint than the workload's, and a path"
            )
    return pack


def by_name(pack, name):
    return next(r for r in pack["rrps"] if r["name"] == name)


def rrp_kind(pack, r):
    return by_name(pack, r["same_as"])["kind"] if "same_as" in r else r["kind"]


def redirection_variants(pack, rrps, omit_rrp_id=False, own_epochs=False, est_rrps=None):
    """The variants of the redirection experiment (hwcheck/scripts/redirect.sh), applied to the RRPs' configurations in
    place. omit_rrp_id: the RRPs, Credential Authorities and Secret Vaults, bind no RRP identifier, the variant #20 is
    about. own_epochs: each copy of an RRP ("same_as", another bank) keeps an epoch marker of its own, as a gateway does
    without an epoch file, instead of the one the deployment's RRPs share. est_rrps: the EST server's view of the RRPs
    (its tacra.rrps), whose Passport nonce must omit the identifier too, or the Verifier's session would not match."""
    for r in pack["rrps"]:
        if omit_rrp_id:
            rrps[r["name"]]["omit_rrp_id_in_binding"] = True
        if own_epochs and "same_as" in r:
            rrps[r["name"]].pop("epoch_file", None)
    if omit_rrp_id and est_rrps:
        for e in est_rrps.values():
            e["omit_rrp_id_in_binding"] = True


def check_corim(snp, corim_path):
    corim = Path(corim_path).read_bytes()
    missing = [m for m in snp if bytes.fromhex(m) not in corim]
    if missing:
        sys.exit(
            "approved SEV-SNP launch(es) without a reference value in {}: {} (make one with hwcheck/cmd/mkcorim; "
            "trust/README.md)".format(corim_path, ", ".join(m[:16] + "..." for m in missing))
        )


def site_verifiers(home, vd, root):
    """The verifiers the RRPs may take, by name, each with its EAR key as a provisioned file (N24)."""
    v = [
        {
            "url": "https://localhost:8443",
            "ca": f"{vd}/certs/rootCA.crt",
            "name": "veraison",
            "ear_key": f"{home}/gateways/veraison.ear.jwk",
            "submods": ["SEVSNP"],
            "provider": "sev_guest",
        },
        {
            "url": "https://localhost:8453",
            "ca": root,
            "name": "tdx",
            "ear_key": f"{home}/gateways/tdx-verifier.ear.jwk",
            "submods": ["TDX"],
            "provider": "tdx_guest",
        },
    ]
    return v


def identity(home, name):
    """A component's client certificate on its calls (N23)."""
    return {"client_cert": f"{home}/tls/clients/{name}.crt", "client_key": f"{home}/tls/clients/{name}.key"}


def target_config(t, workload, measurements, everyone):
    c = {"credential_types": t["credential_types"], "freshness_kind": t["freshness_kind"]}
    c.update({k: t[k] for k in FRESHNESS_PARAMS if k in t})
    c["verifiers"] = everyone if t["verifiers"] == "all" else t["verifiers"]
    c["acceptable"] = t["acceptable"]
    if "secret" in t:
        # the workload's group, and the Target's other groups: the same launches, under other Credential Hints
        c["groups"] = {
            hint: {
                "secret_path": s["path"],
                "measurements": measurements,
                **{k: v for k, v in s.items() if k != "path"},
            }
            for hint, s in {workload["hint"]: t["secret"], **t.get("other_groups", {})}.items()
        }
    else:
        c["identities"] = {
            workload["hint"]: {
                "sans": workload["sans"],
                "measurements": measurements,
                "validity": t["certificate_validity"],
            }
        }
    return c


def est_server(home, logs, listen, vd, root, verifiers, rrps, targets):
    # the health-check password: kept from an earlier run, so writing the configuration again changes nothing
    try:
        hc = json.loads(Path(home, "config", "est-server.json").read_text())["healthcheck_password"]
    except (OSError, KeyError, ValueError):
        hc = os.urandom(16).hex()
    return {
        "tls": {
            "listen_address": listen,
            "certificates": f"{home}/tls/est-server.crt",
            "private_key": f"{home}/tls/est-server.key",
        },
        "healthcheck_password": hc,
        "timeout": 60,
        "rate_limit": 0,
        "log_file": f"{logs}/est-server.log",
        # every attest-* exchange, request and response, as it crossed the wire; a run keeps its part
        # (bench-logs/est-wire.log)
        "wire_log": f"{logs}/est-wire.log",
        "tacra": dict(
            identity(home, "est-server"),
            verifiers={v["name"]: {"url": v["url"], "ca": v["ca"], "provider": v["provider"]} for v in verifiers},
            acceptable_evidence=["application/vnd.veraison.tsm-report+cbor"],
            ca_certs=f"{home}/step/certs/intermediate_ca.crt",
            rrps=rrps,
            targets=targets,
        ),
    }


def client_certificates(home, domain):
    """The infrastructure's identities (mutual TLS, tacra-est N23): a client certificate under the home's TLS root for
    the EST server, each gateway and the operator, named <name>.<infra_domain>."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    root = x509.load_pem_x509_certificate(Path(home, "tls", "root.crt").read_bytes())
    root_key = serialization.load_pem_private_key(Path(home, "tls", "root.key").read_bytes(), None)
    now = datetime.datetime.now(datetime.timezone.utc)
    os.makedirs(f"{home}/tls/clients", exist_ok=True)
    for name in INFRA:
        cp, kp, dns = f"{home}/tls/clients/{name}.crt", f"{home}/tls/clients/{name}.key", f"{name}.{domain}"
        if os.path.exists(cp):
            old = x509.load_pem_x509_certificate(Path(cp).read_bytes())
            if old.not_valid_after_utc > now + datetime.timedelta(days=14) and dns_names(old) == [dns]:
                continue
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)]))
            .issuer_name(root.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(root_key, hashes.SHA256())
        )
        old_umask = os.umask(0o077)
        with open(kp, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        with open(cp, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        os.umask(old_umask)
        print("client certificate", dns, "until", cert.not_valid_after_utc.date())


def dns_names(cert):
    from cryptography import x509

    try:
        return cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName
        )
    except x509.ExtensionNotFound:
        return []


def veraison_ear_key(home, vd):
    """Veraison's EAR key, given to the gateways as a file: the public half of the deployment's signing key."""
    sk = json.loads(Path(vd, "signing", "skey.jwk").read_text())
    with open(f"{home}/gateways/veraison.ear.jwk", "w") as f:
        json.dump({k: v for k, v in sk.items() if k in ("kty", "crv", "x", "y", "alg", "kid")}, f)


def veraison_client_ca(vd, root):
    """Veraison's verification API takes only callers with a certificate of the home's root (its client-ca option)."""
    vy = f"{vd}/config/services/config.yaml"
    y = Path(vy).read_text()
    blk = re.search(r"^verification:\n((?:  .*\n)+)", y, re.MULTILINE)
    if blk and "client-ca:" not in blk.group(1):
        with open(vy, "w") as f:
            f.write(y[: blk.end()] + "  client-ca: " + root + "\n" + y[blk.end() :])


def vault_hcl(home, root):
    """HashiCorp Vault: TLS 1.3, a client certificate of the home's root required."""
    hcl = [
        'storage "file" {',
        f'  path = "{home}/vault/data"',
        "}",
        'listener "tcp" {',
        '  address                            = "127.0.0.1:8200"',
        f'  tls_cert_file                      = "{home}/tls/vault.crt"',
        f'  tls_key_file                       = "{home}/tls/vault.key"',
        '  tls_min_version                    = "tls13"',
        '  tls_require_and_verify_client_cert = "true"',
        f'  tls_client_ca_file                 = "{root}"',
        "}",
        'api_addr      = "https://127.0.0.1:8200"',
        "disable_mlock = true",
        "ui            = false",
    ]
    os.makedirs(f"{home}/vault", exist_ok=True)
    with open(f"{home}/vault/config.hcl", "w") as f:
        f.write("\n".join(hcl) + "\n")


def step_ca_tls13(home):
    """step-ca: TLS 1.3. The CA gateway authenticates with its provisioner's one-time token and presents its
    certificate."""
    sc = f"{home}/step/config/ca.json"
    c = json.loads(Path(sc).read_text())
    if c.get("tls", {}).get("minVersion") != 1.3:
        c.setdefault("tls", {})["minVersion"] = 1.3
        with open(sc, "w") as f:
            json.dump(c, f, indent=1)


if __name__ == "__main__":
    try:
        main()
    except PackError as e:
        sys.exit(f"pack: {e}")
