// Command vault-gateway is the test bench's Secret Vault as a RATS Relying Party: it answers attest-initiate for its
// Targets with Handles it mints, and for attest-retrieve it checks the Target's policy, freshness, and the binding
// value it recomputes with its own identifier and CEKpub against verified Attestation Results; it derives the
// credential group from the Attestation Results, reads that group's secret from HashiCorp Vault, and returns it
// sealed to CEKpub: in the hpke-base container, with its origin authentication under the Vault's own ECDSA key
// unless the Target says "sign": false, when CEKpub is an MLKEM768-P256 encapsulation key or a P-256 key and the
// Target accepts that suite; otherwise in the hpke-auth container under its own static KEM key. Under the bank profile
// only the signed hpke-base container is released (tacra-est decision 4).
//
//	vault-gateway -config vault-gateway.json
package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/tacra/bundle"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/fresh"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/gateway"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/mtls"
)

type fileConfig struct {
	gateway.Config
	Vault   vaultConfig `json:"vault"`
	KEMKeys string      `json:"kem_keys"` // file holding this Vault's static KEM keys (created if absent)
	SignKey string      `json:"sign_key"` // file holding this Vault's ECDSA P-256 signature key (created if absent)
}

// RetrieveRequest is attest-retrieve as the EST Server forwards it to this RRP.
type RetrieveRequest struct {
	gateway.SecondLeg
	CEKPub bundle.B64 `json:"cek_pub"`
}

// secrets is where the gateway reads a group's secret: HashiCorp Vault's KV (vault.go), or a fake in tests.
type secrets interface {
	read(path string) (map[string]string, int, error)
}

type server struct {
	g      *gateway.Gateway
	kv     secrets
	sender *bundle.SenderKeys
	signer *ecdsa.PrivateKey // signs the hpke-base container's origin member
}

// groupID derives the credential group from the Attestation Results and the Target, as the reference implementation
// does: SHA-256 of measurement | platform | Target | hint | policy version. The Target is part of the group (tacra-est
// N2; the draft: a group ID "distinct across security domains, tenants, and credential selections"). Each Target's
// policy names the secret each of its groups releases; two Targets release one secret only where their policies name
// the same one.
func groupID(measurement []byte, platform, target, hint, policyVersion string) string {
	s := sha256.Sum256([]byte(hex.EncodeToString(measurement) + "|" + platform + "|" + target + "|" + hint + "|" + policyVersion))
	return hex.EncodeToString(s[:])
}

func (s *server) retrieve(req *RetrieveRequest) (*bundle.Bundle, []string, error) {
	res, t, err := s.g.Check(&req.SecondLeg, req.CEKPub)
	if err != nil {
		return nil, nil, err
	}
	grp, ok := t.Groups[req.CredentialHint]
	if !ok {
		return nil, nil, &gateway.Error{Status: http.StatusForbidden, Code: "credential-hint",
			Err: errors.New("no credential group for this Credential Hint at this Target")}
	}
	if !gateway.Allowed(res.Measurement, grp.Measurements) {
		return nil, nil, &gateway.Error{Status: http.StatusForbidden, Code: "group",
			Err: errors.New("the attested launch may not receive this group's credential")}
	}
	secret, version, err := s.kv.read(grp.SecretPath)
	if err != nil {
		return nil, nil, &gateway.Error{Status: http.StatusBadGateway, Code: "secret-vault", Err: err}
	}
	gid := groupID(res.Measurement, gateway.Platform(res.Submod), req.Target, req.CredentialHint, grp.PolicyVersion)
	// The item carries its key-block attributes from the group's policy and never leaves the TEE; a private key is
	// shared by the group's instances, which the bank profile allows only for a declared replicated service.
	shared := secret["type"] == "private-key"
	if shared && !grp.Replicated && s.g.Config.Profile == "bank" {
		return nil, nil, &gateway.Error{Status: http.StatusForbidden, Code: "group",
			Err: errors.New("bank profile: a shared private key only for a group declared a replicated service")}
	}
	no := false
	validity := grp.ValidityS
	if validity == 0 {
		validity = int(gateway.BankMaxValidity / time.Second)
	}
	content := bundle.Content{CredentialItems: []bundle.Item{{Type: secret["type"], Format: secret["format"],
		Value: secret["value"], Kid: gid[:16], Purpose: grp.Purpose, Algorithm: grp.Algorithm, Exportable: &no, Shared: shared}},
		Metadata: map[string]any{"secret_version": strconv.Itoa(version), "validity_seconds": validity}}
	aad := bundle.AAD{GroupID: gid, Target: req.Target, Handle: req.Handle, CredentialHint: req.CredentialHint}
	// the origin authentication is the Target's policy: its signature key, unless the Target says "sign": false
	signer := s.signer
	if !t.Signs() {
		signer = nil
	}
	var b *bundle.Bundle
	if bundle.IsP256CEK(req.CEKPub) && slices.Contains(t.Acceptable, bundle.AcceptableDHKEMP256) {
		// the hpke-base container under DHKEM(P-256, HKDF-SHA256), where the Target accepts that suite (issue #15 of the
		// EST draft, 28 October 2026); a P-256 CEK at a Target that accepts only hpke-auth suites takes the branch below
		if signer == nil && t.Signs() {
			return nil, nil, &gateway.Error{Status: http.StatusInternalServerError, Code: "internal",
				Err: errors.New("no signature key for the hpke-base container")}
		}
		b, err = bundle.SealBase(signer, req.CEKPub, aad, content)
	} else if bundle.IsMLKEM768P256CEK(req.CEKPub) {
		if !slices.Contains(t.Acceptable, bundle.AcceptableMLKEM768P256) {
			return nil, nil, &gateway.Error{Status: http.StatusBadRequest, Code: "cek",
				Err: errors.New("the Target does not accept the hpke-base container under MLKEM768-P256")}
		}
		if signer == nil && t.Signs() {
			return nil, nil, &gateway.Error{Status: http.StatusInternalServerError, Code: "internal",
				Err: errors.New("no signature key for the hpke-base container")}
		}
		b, err = bundle.SealBase(signer, req.CEKPub, aad, content)
	} else {
		if s.g.Config.Profile == "bank" {
			return nil, nil, &gateway.Error{Status: http.StatusBadRequest, Code: "cek",
				Err: errors.New("bank profile: only the hpke-base container, to an MLKEM768-P256 CEK")}
		}
		if !slices.ContainsFunc(t.Acceptable, func(a string) bool { return strings.HasPrefix(a, "DHKEM(") }) {
			return nil, nil, &gateway.Error{Status: http.StatusBadRequest, Code: "cek",
				Err: errors.New("the Target accepts no hpke-auth suite: an MLKEM768-P256 CEK and the hpke-base container only")}
		}
		b, err = bundle.Seal(s.sender, req.CEKPub, aad, content)
	}
	if err != nil {
		return nil, nil, &gateway.Error{Status: http.StatusBadRequest, Code: "cek", Err: err}
	}
	return b, res.Waived, nil
}

// loadOrCreateSignKey keeps the Vault's ECDSA P-256 signature key across restarts (PKCS#8, base64url): the
// Attesters hold its public half as the trust anchor of the hpke-base container's origin member.
func loadOrCreateSignKey(path string) (*ecdsa.PrivateKey, error) {
	if raw, err := os.ReadFile(path); err == nil {
		der, err := base64.RawURLEncoding.DecodeString(string(raw))
		if err != nil {
			return nil, errors.New("sign key: not base64url")
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok || ek.Curve != elliptic.P256() {
			return nil, errors.New("sign key: not an ECDSA P-256 key")
		}
		return ek, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(der)), 0o600)
}

// loadOrCreateKEMKeys keeps the Vault's static KEM keys across restarts: the Attesters hold their public halves
// as trust anchors.
func loadOrCreateKEMKeys(path string) (*bundle.SenderKeys, error) {
	type file struct{ X25519, P256 string }
	if raw, err := os.ReadFile(path); err == nil {
		var f file
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, err
		}
		x, err1 := base64.RawURLEncoding.DecodeString(f.X25519)
		p, err2 := base64.RawURLEncoding.DecodeString(f.P256)
		if err1 != nil || err2 != nil {
			return nil, errors.New("kem keys: not base64url")
		}
		xk, err := ecdh.X25519().NewPrivateKey(x)
		if err != nil {
			return nil, err
		}
		pk, err := ecdh.P256().NewPrivateKey(p)
		if err != nil {
			return nil, err
		}
		return &bundle.SenderKeys{X25519: xk, P256: pk}, nil
	}
	k, err := bundle.GenerateSenderKeys()
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(file{base64.RawURLEncoding.EncodeToString(k.X25519.Bytes()),
		base64.RawURLEncoding.EncodeToString(k.P256.Bytes())})
	return k, os.WriteFile(path, raw, 0o600)
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tacra/v1/initiate", func(w http.ResponseWriter, r *http.Request) {
		var req gateway.InitiateRequest
		if err := gateway.DecodeJSON(r, &req); err != nil {
			gateway.WriteError(w, err)
			return
		}
		resp, err := s.g.Initiate(req)
		if err != nil {
			gateway.WriteError(w, err)
			return
		}
		gateway.WriteJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("POST /tacra/v1/retrieve", func(w http.ResponseWriter, r *http.Request) {
		var req RetrieveRequest
		if err := gateway.DecodeJSON(r, &req); err != nil {
			gateway.WriteError(w, err)
			return
		}
		b, waived, err := s.retrieve(&req)
		if err != nil {
			log.Printf("retrieve refused: target=%s kind=%s caller=%v: %v", req.Target, req.FreshnessKind, mtls.Names(r), err)
			gateway.WriteError(w, err)
			return
		}
		log.Printf("released: target=%s kind=%s group=%s container=%s kem=%s origin=%t caller=%v%s", req.Target, req.FreshnessKind,
			b.AAD.GroupID[:16], b.Container, b.Suite.KEM, b.Origin != nil, mtls.Names(r), gateway.WaiverNote(waived))
		gateway.WriteJSON(w, http.StatusOK, b)
	})
	// The Vault's origin keys, for provisioning Attesters' trust anchors out of band: its static KEM keys (hpke-auth)
	// and its signature key (the hpke-base container's origin member), each as SubjectPublicKeyInfo.
	mux.HandleFunc("GET /tacra/v1/origin-keys", func(w http.ResponseWriter, r *http.Request) {
		x, _ := s.sender.PublicSPKI(bundle.KEMX25519)
		p, _ := s.sender.PublicSPKI(bundle.KEMP256)
		keys := map[string]bundle.B64{bundle.KEMX25519: x, bundle.KEMP256: p}
		if s.signer != nil {
			sig, _ := x509.MarshalPKIXPublicKey(&s.signer.PublicKey)
			keys[bundle.OriginAlg] = sig
		}
		gateway.WriteJSON(w, http.StatusOK, keys)
	})
	return mux
}

func main() {
	path := flag.String("config", "vault-gateway.json", "configuration file")
	flag.Parse()
	var fc fileConfig
	if err := gateway.DecodeConfigFile(*path, &fc); err != nil {
		log.Fatal(err)
	}
	if err := fc.Validate(); err != nil {
		log.Fatal(err)
	}
	keys, err := fc.TrustedKeys()
	if err != nil {
		log.Fatal(err)
	}
	kv, err := newVaultKV(fc.Vault, fc.ClientCert, fc.ClientKey)
	if err != nil {
		log.Fatal(err)
	}
	sender, err := loadOrCreateKEMKeys(fc.KEMKeys)
	if err != nil {
		log.Fatal(err)
	}
	var signer *ecdsa.PrivateKey
	if fc.SignKey != "" {
		if signer, err = loadOrCreateSignKey(fc.SignKey); err != nil {
			log.Fatal(err)
		}
	}
	if fc.Profile == "bank" { // decision 4: the bank's Targets take the signed hpke-base container, and only it
		if signer == nil {
			log.Fatal("bank profile: sign_key is required (the hpke-base container's origin member)")
		}
		for name, t := range fc.Targets {
			if len(t.Acceptable) != 1 || t.Acceptable[0] != bundle.AcceptableMLKEM768P256 || !t.Signs() {
				log.Fatalf("bank profile: Target %s must accept exactly %s and sign its containers", name, bundle.AcceptableMLKEM768P256)
			}
		}
	}
	g := &gateway.Gateway{Config: &fc.Config, Mode: "retrieve", Fresh: fresh.New(nil),
		EAR: &ear.Verifier{Keys: keys, MaxAge: time.Duration(fc.EAR.MaxAgeS) * time.Second,
			Skew: time.Duration(fc.EAR.SkewS) * time.Second}}
	if fc.RATSModel == gateway.BackgroundCheck {
		if g.Appraiser, err = gateway.NewAppraiser(&fc.Config); err != nil {
			log.Fatal(err)
		}
	}
	if err := g.LoadEpoch(); err != nil {
		log.Fatal(err)
	}
	tc, err := fc.ServerTLS()
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: fc.Listen, Handler: fc.Guard((&server{g: g, kv: kv, sender: sender, signer: signer}).routes()),
		ReadHeaderTimeout: 10 * time.Second, TLSConfig: tc}
	log.Printf("vault-gateway %s listening on %s; client CA %q, protocol callers %v", fc.RRPID, fc.Listen, fc.ClientCA, fc.Clients)
	log.Fatal(srv.ListenAndServeTLS(fc.TLSCert, fc.TLSKey))
}
