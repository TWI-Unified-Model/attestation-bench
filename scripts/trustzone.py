#!/usr/bin/env python3
"""Writes a trust zone's configuration from a pack and the approved launches.

    trustzone.py --home DIR --veraison DIR --pack packs/NAME/pack.json [options]

A trust zone is what one bank runs to give credentials to attested workloads (tacra-est): the EST server, the one
port workloads reach; the Credential Authority and Secret Vault gateways, the RRPs; the verifiers (Veraison for
SEV-SNP, the TDX verifier and, on a laptop, the software stand-in's verifier); step-ca and HashiCorp Vault. The local
bench (e2e/scripts/bench.sh config) and the Demo Bank's trust VM (e2e/bank/remote/trust.sh) both write their
configuration with this program, so the two cannot drift apart.

The pack says what the bank issues: its Targets, the RRPs that serve them, the workload's names and the EAR policy
(packs/README.md). trust/approved-launches.json says which launches the bank admits. The options say where the trust
zone lives and how it runs.

Under --home it writes:
  config/<service>.json           the gateways, the EST server, the TDX verifier, the stand-in's verifier
  tls/clients/<name>.crt|.key     each component's client certificate under the home's TLS root, tls/root.crt (mutual
                                  TLS, tacra-est N23); issued when absent or within 14 days of its end
  gateways/veraison.ear.jwk       Veraison's EAR key, given to the RRPs as a file (N24: never fetched from Veraison)
  vault/config.hcl                Vault: TLS 1.3, a client certificate of the home's root required
  sim-measurement.hex, secrets/sim-tee-ak.jwk, gateways/sim-tee-ak.pub.jwk     (--simulated-tee only)
and it edits two files the services own: Veraison's config.yaml (its verification API requires a client certificate
of the home's root) and step-ca's ca.json (TLS 1.3). Everything else under --home (the TLS root and the services'
server certificates, step-ca, Vault's data, the gateways' keys and tokens) the caller creates.

It refuses an approved SEV-SNP launch that Veraison's CoRIM (--corim) holds no reference value for: Veraison would not
affirm it, so the bank would approve a launch it can never admit.
"""

import argparse
import base64
import datetime
import hashlib
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
# The software stand-in TEE (platform/simtee.go: NO isolation, NO security) has one approved launch: SHA-384 of a
# fixed label. A real RRP never accepts its results (allow_simulated_tee).
SIM_LABEL = b"attestation-bench simulated TEE: approved workload"


class PackError(Exception):
    pass


def main():
    a = parse_args()
    home = os.path.abspath(a.home)
    logs = os.path.abspath(a.logs or home)
    vd = os.path.abspath(a.veraison)
    pack = load_pack(a.pack, a.simulated_tee)
    approved = json.loads(Path(a.approved).read_text())
    snp = [e["measurement"] for e in approved["sev-snp"]]
    tdx = [e["mrtd"] for e in approved["tdx"]]
    check_corim(snp, a.corim)

    client_certificates(home, pack["infra_domain"])
    sim = simulated_tee(home) if a.simulated_tee else None
    measurements = snp + tdx + ([sim["measurement"]] if sim else [])

    root = f"{home}/tls/root.crt"
    infra = {n: f"{n}.{pack['infra_domain']}" for n in INFRA}
    verifiers = site_verifiers(home, vd, root, a.simulated_tee)
    everyone = [v["name"] for v in verifiers]
    common = {
        "verifiers": verifiers,
        "ear": pack["ear"],
        "epoch_file": f"{home}/epoch.hex",
        "rats_model": a.rats_model,
        "client_ca": root,
        "clients": [infra["est-server"]],
    }
    if a.simulated_tee:
        # bench only: accept the software stand-in TEE's results (submodule SIM); a production RRP never sets it
        common["allow_simulated_tee"] = True

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
    if a.omit_rrp_id:  # the variant #20 is about: the Credential Authorities bind no RRP identifier
        for r in pack["rrps"]:
            if rrp_kind(pack, r) == "credential-authority":
                rrps[r["name"]]["omit_rrp_id_in_binding"] = True

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
    if sim:
        files.append(
            (
                "sim-verifier",
                {
                    "listen": "127.0.0.1:8463",
                    "tls_cert": f"{home}/tls/sim-verifier.crt",
                    "tls_key": f"{home}/tls/sim-verifier.key",
                    "client_ca": root,
                    "clients": others,
                    "signing_key": f"{home}/secrets/sim-verifier.jwk",
                    "attestation_keys": [sim["public_key"]],
                    "reference_measurements": [sim["measurement"]],
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
        "--corim",
        default=os.path.join(REPO, "trust", "veraison-corim-milan.cbor"),
        help="the CoRIM Veraison is provisioned with (default trust/veraison-corim-milan.cbor)",
    )
    p.add_argument("--logs", help="where the EST server writes its log (default: --home)")
    p.add_argument("--est-listen", default="127.0.0.1:18443", help="the EST server's address (default 127.0.0.1:18443)")
    p.add_argument(
        "--simulated-tee",
        action="store_true",
        help="laptop only: run the software stand-in TEE's verifier and accept its results (NO security)",
    )
    p.add_argument(
        "--rats-model",
        choices=("passport", "background-check"),
        default="passport",
        help="who asks the verifiers: the EST server (passport) or the gateways (background-check)",
    )
    p.add_argument(
        "--omit-rrp-id", action="store_true", help="the #20 variant: the Credential Authorities bind no RRP identifier"
    )
    return p.parse_args()


def load_pack(path, simulated):
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
    available = ["veraison", "tdx"] + (["sim"] if simulated else [])
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
    return pack


def by_name(pack, name):
    return next(r for r in pack["rrps"] if r["name"] == name)


def rrp_kind(pack, r):
    return by_name(pack, r["same_as"])["kind"] if "same_as" in r else r["kind"]


def check_corim(snp, corim_path):
    corim = Path(corim_path).read_bytes()
    missing = [m for m in snp if bytes.fromhex(m) not in corim]
    if missing:
        sys.exit(
            "approved SEV-SNP launch(es) without a reference value in {}: {} (make one with hwcheck/cmd/mkcorim; "
            "trust/README.md)".format(corim_path, ", ".join(m[:16] + "..." for m in missing))
        )


def site_verifiers(home, vd, root, simulated):
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
    if simulated:
        v.append(
            {
                "url": "https://localhost:8463",
                "ca": root,
                "name": "sim",
                "ear_key": f"{home}/gateways/sim-verifier.ear.jwk",
                "submods": ["SIM"],
                "provider": "sim_guest",
            }
        )
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
        s = t["secret"]
        c["groups"] = {
            workload["hint"]: {
                "secret_path": s["path"],
                "measurements": measurements,
                **{k: v for k, v in s.items() if k != "path"},
            }
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


def simulated_tee(home):
    """The software stand-in TEE's attestation key (an ordinary file: the local attester holds it, the stand-in's
    verifier trusts its public half) and its one approved launch measurement."""
    m = hashlib.sha384(SIM_LABEL).hexdigest()
    with open(f"{home}/sim-measurement.hex", "w") as f:
        f.write(m + "\n")
    ak, ak_pub = f"{home}/secrets/sim-tee-ak.jwk", f"{home}/gateways/sim-tee-ak.pub.jwk"
    if not os.path.exists(ak):
        from cryptography.hazmat.primitives.asymmetric import ec

        n = ec.generate_private_key(ec.SECP256R1()).private_numbers()
        b64 = lambda v: base64.urlsafe_b64encode(v.to_bytes(32, "big")).rstrip(b"=").decode()
        old_umask = os.umask(0o077)
        with open(ak, "w") as f:
            json.dump(
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": b64(n.public_numbers.x),
                    "y": b64(n.public_numbers.y),
                    "d": b64(n.private_value),
                },
                f,
            )
        os.umask(old_umask)
    j = json.loads(Path(ak).read_text())
    with open(ak_pub, "w") as f:
        json.dump({k: j[k] for k in ("kty", "crv", "x", "y")}, f)
    return {"measurement": m, "public_key": ak_pub}


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
