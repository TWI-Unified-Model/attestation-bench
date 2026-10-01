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

// testVerifiers is the verifier the tests' Targets take: Veraison, for SEVSNP. The tests give the gateway its key
// directly (ear.Verifier); ear_key names the file a deployment would provision.
var testVerifiers = []gateway.VerifierConfig{{Name: "veraison", EARKey: "veraison.ear.jwk", Submods: []string{"SEVSNP"}}}

const (
	rrpID  = "https://vault1.tacra.example"
	target = "https://ledger.tacra.example"
	hint   = "payments.workload.tacra.example"
)

func benchKV(t *testing.T) *vaultKV {
	t.Helper()
	b := filepath.Join(os.Getenv("HOME"), "tacra-bench")
	kv, err := newVaultKV(vaultConfig{Addr: "https://127.0.0.1:8200", CA: filepath.Join(b, "tls/root.crt"),
		Mount: "secret", TokenFile: filepath.Join(b, "gateways/vault-gateway.token")},
		filepath.Join(b, "tls/clients/vault-gateway.crt"), filepath.Join(b, "tls/clients/vault-gateway.key"))
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
	cfg := &gateway.Config{RRPID: rrpID, Verifiers: testVerifiers, Targets: map[string]*gateway.Target{target: {
		Verifiers: []string{"veraison"}, CredentialTypes: []string{"api-key"}, FreshnessKind: fresh.PresentNonce, ExpiresInS: 300,
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
		EAR: &ear.Verifier{Keys: []ear.TrustedKey{{Name: "veraison", Key: &earKey.PublicKey, Submods: []string{"SEVSNP"}}},
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
		// the bank profile asks mutual TLS of the EST server's calls; these handlers are called directly
		cfg := &gateway.Config{RRPID: rrpID, Verifiers: testVerifiers, Profile: profile, ClientCA: "infra-root.crt",
			Clients: []string{"est-server.bench.tacra.example"}, Targets: map[string]*gateway.Target{target: {
				Verifiers: []string{"veraison"}, CredentialTypes: []string{"api-key"}, FreshnessKind: fresh.PresentNonce, ExpiresInS: 300, Acceptable: acceptable,
				Groups: map[string]*gateway.Group{hint: {SecretPath: "tacra/payments", Measurements: []string{strings.TrimSpace(string(measHex))},
					PolicyVersion: "1", Purpose: []string{"authenticate"}, Algorithm: "API-KEY", ValidityS: 3600}}}}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		return &server{kv: kv, sender: sender, signer: signer, g: &gateway.Gateway{Config: cfg, Mode: "retrieve", Fresh: fresh.New(nil),
			EAR: &ear.Verifier{Keys: []ear.TrustedKey{{Name: "veraison", Key: &earKey.PublicKey, Submods: []string{"SEVSNP"}}},
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
	// a Target that accepts only the signed container: an X25519 CEK (hpke-auth) is refused, 400, without the profile too
	s3 := newServer([]string{bundle.AcceptableSigned}, "")
	xk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xkSPKI, _ := x509.MarshalPKIXPublicKey(xk.PublicKey())
	if _, err := s3.retrieve(request(s3, xkSPKI)); status(err) != http.StatusBadRequest {
		t.Fatalf("hpke-auth at a Target that accepts only the signed container: %v", err)
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

// TestGroupPerTarget (tacra-est N2): the Target is part of the group. Two Targets with the same hint get two groups;
// each releases the secret its own policy names, so they share a secret only where both policies name it.
func TestGroupPerTarget(t *testing.T) {
	measHex, _ := os.ReadFile("../../internal/ear/testdata/measurement.hex")
	meas := strings.TrimSpace(string(measHex))
	tmplRaw, _ := os.ReadFile("../../internal/ear/testdata/ear-gcp-sevsnp.jws")
	tmpl := strings.TrimSpace(string(tmplRaw))
	earKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sender, _ := bundle.GenerateSenderKeys()
	kv := fakeSecrets{"tacra/ledger-a": {"type": "api-key", "format": "raw", "value": "secret-a"},
		"tacra/ledger-b": {"type": "api-key", "format": "raw", "value": "secret-b"},
		"tacra/shared":   {"type": "api-key", "format": "raw", "value": "shared"}}
	const ta, tb = "https://ledger-a.tacra.example", "https://ledger-b.tacra.example"
	newGW := func(pathA, pathB string) *server {
		group := func(path string) map[string]*gateway.Group {
			return map[string]*gateway.Group{hint: {SecretPath: path, Measurements: []string{meas}, PolicyVersion: "1",
				Purpose: []string{"authenticate"}, Algorithm: "opaque-bearer", ValidityS: 3600}}
		}
		target := func(path string) *gateway.Target {
			return &gateway.Target{Verifiers: []string{"veraison"}, CredentialTypes: []string{"api-key"}, FreshnessKind: fresh.PresentNonce,
				ExpiresInS: 300, Acceptable: []string{bundle.AcceptableSigned}, Groups: group(path)}
		}
		cfg := &gateway.Config{RRPID: rrpID, Verifiers: testVerifiers, Targets: map[string]*gateway.Target{ta: target(pathA), tb: target(pathB)}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		return &server{kv: kv, sender: sender, signer: signer, g: &gateway.Gateway{Config: cfg, Mode: "retrieve", Fresh: fresh.New(nil),
			EAR: &ear.Verifier{Keys: []ear.TrustedKey{{Name: "veraison", Key: &earKey.PublicKey, Submods: []string{"SEVSNP"}}},
				MaxAge: 2 * time.Minute, Skew: 5 * time.Second}}}
	}
	release := func(s *server, target string) (string, string) {
		cek, cekPub, err := bundle.GenerateCEK()
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.g.Initiate(gateway.InitiateRequest{Target: target, CredentialType: "api-key"})
		if err != nil {
			t.Fatal(err)
		}
		bv := platform.BindingValue(r.Handle, rrpID, target, cekPub)
		jws, _ := gateway.SignTestEAR(earKey, tmpl, bv[:], time.Now(), "")
		b, err := s.retrieve(&RetrieveRequest{SecondLeg: gateway.SecondLeg{FreshnessKind: fresh.PresentNonce, Target: target,
			CredentialType: "api-key", Handle: r.Handle, CredentialHint: hint, EAR: jws}, CEKPub: cekPub})
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		got, err := bundle.OpenSigned(b, bundle.ExpectSigned{RRPID: rrpID, Target: target, Handle: r.Handle, CredentialHint: hint,
			CEK: cek, VaultKey: &signer.PublicKey})
		if err != nil {
			t.Fatalf("%s: open: %v", target, err)
		}
		return b.AAD.GroupID, got.CredentialItems[0].Value
	}
	own := newGW("tacra/ledger-a", "tacra/ledger-b")
	ga, sa := release(own, ta)
	gb, sb := release(own, tb)
	if ga == gb || sa == sb || sa != "secret-a" || sb != "secret-b" {
		t.Fatalf("each Target its own secret: groups %s %s, secrets %q %q", ga[:16], gb[:16], sa, sb)
	}
	shared := newGW("tacra/shared", "tacra/shared")
	ga, sa = release(shared, ta)
	gb, sb = release(shared, tb)
	if ga == gb || sa != sb {
		t.Fatalf("both policies name one secret: groups %s %s (want two), secrets %q %q (want one)", ga[:16], gb[:16], sa, sb)
	}
}
