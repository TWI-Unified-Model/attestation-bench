package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TWI-Unified-Model/tacra/bundle"
	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/fresh"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/gateway"
)

const (
	rrpID  = "https://vault1.tacra.example"
	target = "https://ledger.tacra.example"
	hint   = "payments.workload.tacra.example"
)

func benchKV(t *testing.T) *vaultKV {
	t.Helper()
	b := filepath.Join(os.Getenv("HOME"), "tacra-bench")
	kv, err := newVaultKV(vaultConfig{Addr: "https://127.0.0.1:8200", CA: filepath.Join(b, "tls/root.crt"),
		Mount: "secret", TokenFile: filepath.Join(b, "gateways/vault-gateway.token")})
	if err != nil {
		t.Skipf("test bench not present: %v", err)
	}
	if _, _, err := kv.read("tacra/payments"); err != nil {
		t.Skipf("Vault not reachable or sealed: %v", err)
	}
	return kv
}

func status(err error) int {
	var e *gateway.Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func TestRetrieveThroughVault(t *testing.T) {
	kv := benchKV(t)
	want, _, _ := kv.read("tacra/payments")
	measHex, _ := os.ReadFile("../../internal/ear/testdata/measurement.hex")
	tmplRaw, _ := os.ReadFile("../../internal/ear/testdata/ear-gcp-sevsnp.jws")
	tmpl := strings.TrimSpace(string(tmplRaw))
	earKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg := &gateway.Config{RRPID: rrpID, Targets: map[string]*gateway.Target{target: {
		CredentialTypes: []string{"api-key"}, FreshnessKind: fresh.PresentNonce, ExpiresInS: 300,
		Acceptable: []string{"DHKEM(X25519,HKDF-SHA256)+HKDF-SHA256+AES-256-GCM"},
		Groups: map[string]*gateway.Group{
			hint:                            {SecretPath: "tacra/payments", Measurements: []string{strings.TrimSpace(string(measHex))}, PolicyVersion: "1"},
			"ledger.workload.tacra.example": {SecretPath: "tacra/ledger", Measurements: []string{strings.Repeat("00", 48)}, PolicyVersion: "1"},
		}}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	sender, _ := bundle.GenerateSenderKeys()
	s := &server{kv: kv, sender: sender, g: &gateway.Gateway{Config: cfg, Mode: "retrieve", Fresh: fresh.New(nil),
		EAR: &ear.Verifier{Key: &earKey.PublicKey, MaxAge: 2 * time.Minute, Skew: 5 * time.Second, Submods: []string{"SEVSNP"}}}}

	handle := func() []byte {
		r, err := s.g.Initiate(gateway.InitiateRequest{Target: target, CredentialType: "api-key"})
		if err != nil || r.Mode != "retrieve" {
			t.Fatalf("initiate: %+v %v", r, err)
		}
		return r.Handle
	}
	request := func(h, cekPub []byte, rrp, hnt string, key *ecdsa.PrivateKey) *RetrieveRequest {
		bv := platform.BindingValue(h, rrp, target, cekPub)
		jws, err := gateway.SignTestEAR(key, tmpl, bv[:], time.Now(), "")
		if err != nil {
			t.Fatal(err)
		}
		return &RetrieveRequest{SecondLeg: gateway.SecondLeg{FreshnessKind: fresh.PresentNonce, Target: target,
			CredentialType: "api-key", Handle: h, CredentialHint: hnt, EAR: jws}, CEKPub: cekPub}
	}

	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xSPKI, _ := x509.MarshalPKIXPublicKey(x.PublicKey())
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pSPKI, _ := x509.MarshalPKIXPublicKey(&pk.PublicKey)
	pECDH, _ := pk.ECDH()
	for _, c := range []struct {
		name string
		spki []byte
		priv *ecdh.PrivateKey
		kem  string
	}{{"X25519 CEK", xSPKI, x, bundle.KEMX25519}, {"P-256 CEK", pSPKI, pECDH, bundle.KEMP256}} {
		h := handle()
		b, err := s.retrieve(request(h, c.spki, rrpID, hint, earKey))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		vaultSPKI, _ := sender.PublicSPKI(c.kem)
		got, err := bundle.Open(b, c.priv, bundle.Expect{RRPID: rrpID, Target: target, Handle: h, CredentialHint: hint, VaultSPKI: vaultSPKI})
		if err != nil {
			t.Fatalf("%s: open: %v", c.name, err)
		}
		if got.CredentialItems[0].Value != want["value"] || got.CredentialItems[0].Type != "api-key" {
			t.Fatalf("%s: released %+v, Vault holds %v", c.name, got.CredentialItems, want)
		}
		if b.Suite.KEM != c.kem {
			t.Fatalf("%s: suite %s", c.name, b.Suite.KEM)
		}
		// the same Handle again: 409
		if _, err := s.retrieve(request(h, c.spki, rrpID, hint, earKey)); status(err) != http.StatusConflict {
			t.Fatalf("%s: replayed Handle: %v", c.name, err)
		}
	}
	// Attestation Results for a binding over another RRP: 403
	if _, err := s.retrieve(request(handle(), xSPKI, "https://ca1.tacra.example", hint, earKey)); status(err) != http.StatusForbidden {
		t.Fatalf("binding over another RRP: %v", err)
	}
	// a group the attested launch may not receive: 403
	if _, err := s.retrieve(request(handle(), xSPKI, rrpID, "ledger.workload.tacra.example", earKey)); status(err) != http.StatusForbidden {
		t.Fatalf("group of another launch: %v", err)
	}
	// results that are not affirming: 403
	h := handle()
	bv := platform.BindingValue(h, rrpID, target, xSPKI)
	jws, _ := gateway.SignTestEAR(earKey, tmpl, bv[:], time.Now(), "contraindicated")
	req := &RetrieveRequest{SecondLeg: gateway.SecondLeg{FreshnessKind: fresh.PresentNonce, Target: target,
		CredentialType: "api-key", Handle: h, CredentialHint: hint, EAR: jws}, CEKPub: xSPKI}
	if _, err := s.retrieve(req); status(err) != http.StatusForbidden {
		t.Fatalf("contraindicated results: %v", err)
	}
}
