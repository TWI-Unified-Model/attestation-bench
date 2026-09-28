// Command vault-gateway is the test bench's Secret Vault as a RATS Relying Party: it answers attest-initiate for its
// Targets with Handles it mints, and for attest-retrieve it checks the Target's policy, freshness, and the binding
// value it recomputes with its own identifier and CEKpub against verified Attestation Results; it derives the
// credential group from the Attestation Results, reads that group's secret from HashiCorp Vault, and returns it
// sealed to CEKpub in the hpke-auth container under its own static key.
//
//	vault-gateway -config vault-gateway.json
package main

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/TWI-Unified-Model/tacra/bundle"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/fresh"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/gateway"
)

type fileConfig struct {
	gateway.Config
	Vault   vaultConfig `json:"vault"`
	KEMKeys string      `json:"kem_keys"` // file holding this Vault's static KEM keys (created if absent)
}

// RetrieveRequest is attest-retrieve as the EST Server forwards it to this RRP.
type RetrieveRequest struct {
	gateway.SecondLeg
	CEKPub bundle.B64 `json:"cek_pub"`
}

type server struct {
	g      *gateway.Gateway
	kv     *vaultKV
	sender *bundle.SenderKeys
}

// groupID derives the credential group from the Attestation Results, as the reference implementation does:
// SHA-256 of measurement | platform | hint | policy version.
func groupID(measurement []byte, platform, hint, policyVersion string) string {
	s := sha256.Sum256([]byte(hex.EncodeToString(measurement) + "|" + platform + "|" + hint + "|" + policyVersion))
	return hex.EncodeToString(s[:])
}

func (s *server) retrieve(req *RetrieveRequest) (*bundle.Bundle, error) {
	res, t, err := s.g.Check(&req.SecondLeg, req.CEKPub)
	if err != nil {
		return nil, err
	}
	grp, ok := t.Groups[req.CredentialHint]
	if !ok {
		return nil, &gateway.Error{Status: http.StatusForbidden, Code: "credential-hint",
			Err: errors.New("no credential group for this Credential Hint at this Target")}
	}
	if !gateway.Allowed(res.Measurement, grp.Measurements) {
		return nil, &gateway.Error{Status: http.StatusForbidden, Code: "group",
			Err: errors.New("the attested launch may not receive this group's credential")}
	}
	secret, version, err := s.kv.read(grp.SecretPath)
	if err != nil {
		return nil, &gateway.Error{Status: http.StatusBadGateway, Code: "secret-vault", Err: err}
	}
	content := bundle.Content{CredentialItems: []bundle.Item{{Type: secret["type"], Format: secret["format"],
		Value: secret["value"]}}, Metadata: map[string]any{"secret_version": strconv.Itoa(version)}}
	aad := bundle.AAD{GroupID: groupID(res.Measurement, gateway.Platform(res.Submod), req.CredentialHint, grp.PolicyVersion),
		RRPID: s.g.Config.RRPID, Target: req.Target, Handle: req.Handle, CredentialHint: req.CredentialHint}
	b, err := bundle.Seal(s.sender, req.CEKPub, aad, content)
	if err != nil {
		return nil, &gateway.Error{Status: http.StatusBadRequest, Code: "cek", Err: err}
	}
	return b, nil
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
		b, err := s.retrieve(&req)
		if err != nil {
			log.Printf("retrieve refused: target=%s kind=%s: %v", req.Target, req.FreshnessKind, err)
			gateway.WriteError(w, err)
			return
		}
		log.Printf("released: target=%s kind=%s group=%s", req.Target, req.FreshnessKind, b.AAD.GroupID[:16])
		gateway.WriteJSON(w, http.StatusOK, b)
	})
	// The Vault's origin keys, for provisioning Attesters' trust anchors out of band.
	mux.HandleFunc("GET /tacra/v1/origin-keys", func(w http.ResponseWriter, r *http.Request) {
		x, _ := s.sender.PublicSPKI(bundle.KEMX25519)
		p, _ := s.sender.PublicSPKI(bundle.KEMP256)
		gateway.WriteJSON(w, http.StatusOK, map[string]bundle.B64{bundle.KEMX25519: x, bundle.KEMP256: p})
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
	kv, err := newVaultKV(fc.Vault)
	if err != nil {
		log.Fatal(err)
	}
	sender, err := loadOrCreateKEMKeys(fc.KEMKeys)
	if err != nil {
		log.Fatal(err)
	}
	g := &gateway.Gateway{Config: &fc.Config, Mode: "retrieve", Fresh: fresh.New(nil),
		EAR: &ear.Verifier{Keys: keys, MaxAge: time.Duration(fc.EAR.MaxAgeS) * time.Second,
			Skew: time.Duration(fc.EAR.SkewS) * time.Second}}
	if err := g.LoadEpoch(); err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: fc.Listen, Handler: (&server{g: g, kv: kv, sender: sender}).routes(),
		ReadHeaderTimeout: 10 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	log.Printf("vault-gateway %s listening on %s", fc.RRPID, fc.Listen)
	log.Fatal(srv.ListenAndServeTLS(fc.TLSCert, fc.TLSKey))
}
