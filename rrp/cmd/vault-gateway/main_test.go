package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
		EAR: &ear.Verifier{Keys: []ear.TrustedKey{{Key: &earKey.PublicKey, Submods: []string{"SEVSNP"}}},
			MaxAge: 2 * time.Minute, Skew: 5 * time.Second}}}

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

// fakeSecrets stands in for HashiCorp Vault's KV.
type fakeSecrets map[string]map[string]string

func (f fakeSecrets) read(path string) (map[string]string, int, error) {
	s, ok := f[path]
	if !ok {
		return nil, 0, errors.New("no such secret")
	}
	return s, 1, nil
}

// TestRetrieveSigned: an MLKEM768-P256 CEK gets the hpke-base-signed container, signed with the Vault's key, which the
// Attester opens with that key as its trust anchor; a Target that does not accept the container, and a hpke-auth
// request under the bank profile, are refused (tacra-est decision 4). Needs no bench.
func TestRetrieveSigned(t *testing.T) {
	measHex, _ := os.ReadFile("../../internal/ear/testdata/measurement.hex")
	tmplRaw, _ := os.ReadFile("../../internal/ear/testdata/ear-gcp-sevsnp.jws")
	tmpl := strings.TrimSpace(string(tmplRaw))
	earKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sender, _ := bundle.GenerateSenderKeys()
	kv := fakeSecrets{"tacra/payments": {"type": "api-key", "format": "raw", "value": "the-secret"}}
	newServer := func(acceptable []string, profile string) *server {
		cfg := &gateway.Config{RRPID: rrpID, Profile: profile, Targets: map[string]*gateway.Target{target: {
			CredentialTypes: []string{"api-key"}, FreshnessKind: fresh.PresentNonce, ExpiresInS: 300, Acceptable: acceptable,
			Groups: map[string]*gateway.Group{hint: {SecretPath: "tacra/payments", Measurements: []string{strings.TrimSpace(string(measHex))},
				PolicyVersion: "1", Purpose: []string{"authenticate"}, Algorithm: "API-KEY", ValidityS: 3600}}}}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		return &server{kv: kv, sender: sender, signer: signer, g: &gateway.Gateway{Config: cfg, Mode: "retrieve", Fresh: fresh.New(nil),
			EAR: &ear.Verifier{Keys: []ear.TrustedKey{{Key: &earKey.PublicKey, Submods: []string{"SEVSNP"}}},
				MaxAge: 2 * time.Minute, Skew: 5 * time.Second}}}
	}
	request := func(s *server, cekPub []byte) *RetrieveRequest {
		r, err := s.g.Initiate(gateway.InitiateRequest{Target: target, CredentialType: "api-key"})
		if err != nil {
			t.Fatal(err)
		}
		bv := platform.BindingValue(r.Handle, rrpID, target, cekPub)
		jws, err := gateway.SignTestEAR(earKey, tmpl, bv[:], time.Now(), "")
		if err != nil {
			t.Fatal(err)
		}
		return &RetrieveRequest{SecondLeg: gateway.SecondLeg{FreshnessKind: fresh.PresentNonce, Target: target,
			CredentialType: "api-key", Handle: r.Handle, CredentialHint: hint, EAR: jws}, CEKPub: cekPub}
	}

	cek, cekPub, err := bundle.GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}
	s := newServer([]string{bundle.AcceptableSigned}, "bank")
	req := request(s, cekPub)
	b, err := s.retrieve(req)
	if err != nil {
		t.Fatalf("signed retrieval: %v", err)
	}
	if b.Container != bundle.ContainerSigned || len(b.Signature) == 0 {
		t.Fatalf("container %s, signature %d octets", b.Container, len(b.Signature))
	}
	got, err := bundle.OpenSigned(b, bundle.ExpectSigned{RRPID: rrpID, Target: target, Handle: req.Handle, CredentialHint: hint,
		CEK: cek, VaultKey: &signer.PublicKey})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.CredentialItems[0].Value != "the-secret" || bundle.CheckItems(got, false, 3600) != nil {
		t.Fatalf("released %+v", got)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := bundle.OpenSigned(b, bundle.ExpectSigned{RRPID: rrpID, Target: target, Handle: req.Handle, CredentialHint: hint,
		CEK: cek, VaultKey: &other.PublicKey}); !errors.Is(err, bundle.ErrSignature) {
		t.Fatalf("opened under another Vault key: %v", err)
	}

	// a Target that does not accept the signed container: 400
	s2 := newServer([]string{"DHKEM(X25519,HKDF-SHA256)+HKDF-SHA256+AES-256-GCM"}, "")
	if _, err := s2.retrieve(request(s2, cekPub)); status(err) != http.StatusBadRequest {
		t.Fatalf("signed container at a Target that does not accept it: %v", err)
	}
	// the bank profile: an X25519 CEK (hpke-auth) is refused, 400
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xSPKI, _ := x509.MarshalPKIXPublicKey(x.PublicKey())
	if _, err := s.retrieve(request(s, xSPKI)); status(err) != http.StatusBadRequest {
		t.Fatalf("hpke-auth under the bank profile: %v", err)
	}

	// the origin keys name the signature key
	srv := httptest.NewServer(s.routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/tacra/v1/origin-keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var keys map[string]bundle.B64
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		t.Fatal(err)
	}
	want, _ := x509.MarshalPKIXPublicKey(&signer.PublicKey)
	if !bytes.Equal(keys[bundle.SuiteSigned.Sig], want) {
		t.Fatal("origin-keys does not name the Vault's signature key")
	}
}
