package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/fresh"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/gateway"
)

// testVerifiers is the verifier the tests' Targets take: Veraison, for SEVSNP. The tests give the gateway its key
// directly (ear.Verifier); ear_key names the file a deployment would provision.
var testVerifiers = []gateway.VerifierConfig{{Name: "veraison", EARKey: "veraison.ear.jwk", Submods: []string{"SEVSNP"}}}

const (
	rrpID  = "https://ca1.tacra.example"
	target = "https://db.tacra.example"
	hint   = "payments.workload.tacra.example"
)

// bench returns a step-ca client for the local test bench, or skips.
func bench(t *testing.T) *stepCA {
	t.Helper()
	b := filepath.Join(os.Getenv("HOME"), "tacra-bench")
	c, err := newStepCA(stepCAConfig{URL: "https://127.0.0.1:9000", Root: filepath.Join(b, "step/certs/root_ca.crt"),
		Provisioner: "tacra-ca-gateway", KeyFile: filepath.Join(b, "gateways/ca-provisioner.jwk")})
	if err != nil {
		t.Skipf("test bench not present: %v", err)
	}
	if resp, err := c.client.Get(c.url + "/health"); err != nil {
		t.Skipf("step-ca not running: %v", err)
	} else {
		resp.Body.Close()
	}
	return c
}

func testServer(t *testing.T, measurement string) (*server, *ecdsa.PrivateKey, string) {
	t.Helper()
	earKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl, err := os.ReadFile("../../internal/ear/testdata/ear-gcp-sevsnp.jws")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{RRPID: rrpID, Verifiers: testVerifiers, Targets: map[string]*gateway.Target{target: {
		Verifiers: []string{"veraison"}, CredentialTypes: []string{"x509"}, FreshnessKind: fresh.PresentNonce, ExpiresInS: 300,
		Acceptable: []string{"ecdsa-p256-sha256"},
		Identities: map[string]*gateway.Identity{
			hint:                            {SANs: []string{hint, "spiffe://tacra.example/payments"}, Measurements: []string{measurement}, Validity: "1h"},
			"ledger.workload.tacra.example": {SANs: []string{"ledger.workload.tacra.example"}, Measurements: []string{strings.Repeat("00", 48)}, Validity: "1h"},
		}}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	g := &gateway.Gateway{Config: cfg, Mode: "enroll", Fresh: fresh.New(nil),
		EAR: &ear.Verifier{Keys: []ear.TrustedKey{{Name: "veraison", Key: &earKey.PublicKey, Submods: []string{"SEVSNP"}}},
			MaxAge: 2 * time.Minute, Skew: 5 * time.Second}}
	return &server{g: g, ca: bench(t)}, earKey, strings.TrimSpace(string(tmpl))
}

func csrFor(t *testing.T, cn string, uris ...string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	for _, u := range uris {
		p, _ := url.Parse(u)
		tpl.URIs = append(tpl.URIs, p)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, k)
	if err != nil {
		t.Fatal(err)
	}
	return der, k
}

func status(err error) int {
	var e *gateway.Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func TestEnrollThroughStepCA(t *testing.T) {
	measHex, _ := os.ReadFile("../../internal/ear/testdata/measurement.hex")
	s, earKey, tmpl := testServer(t, strings.TrimSpace(string(measHex)))

	initiate := func() []byte {
		resp, err := s.g.Initiate(gateway.InitiateRequest{Target: target, CredentialType: "x509"})
		if err != nil || resp.RRPID != rrpID || resp.Mode != "enroll" || len(resp.Handle) != 32 {
			t.Fatalf("initiate: %+v %v", resp, err)
		}
		return resp.Handle
	}
	request := func(handle, csr []byte, h string, nonceTarget string, key *ecdsa.PrivateKey) *EnrollRequest {
		bv := platform.BindingValue(handle, rrpID, nonceTarget, csr)
		jws, err := gateway.SignTestEAR(key, tmpl, bv[:], time.Now(), "")
		if err != nil {
			t.Fatal(err)
		}
		return &EnrollRequest{SecondLeg: gateway.SecondLeg{FreshnessKind: fresh.PresentNonce, Target: target,
			CredentialType: "x509", Handle: handle, CredentialHint: h, EAR: jws}, CSR: csr}
	}

	handle := initiate()
	csr, key := csrFor(t, hint)
	out, err := s.enroll(request(handle, csr, hint, target, earKey))
	if err != nil {
		t.Fatalf("honest enrollment: %v", err)
	}
	leaf, err := x509.ParseCertificate(out.CertificateChain[0])
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("the certificate is not for the CSR's key")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != hint || len(leaf.URIs) != 1 ||
		leaf.URIs[0].String() != "spiffe://tacra.example/payments" {
		t.Fatalf("names %v %v, want the policy's", leaf.DNSNames, leaf.URIs)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d > 61*time.Minute {
		t.Fatalf("validity %s, want 1h", d)
	}
	t.Logf("issued serial %s to %s, valid %s, issuer %q", hex.EncodeToString(leaf.SerialNumber.Bytes()),
		leaf.DNSNames[0], leaf.NotAfter.Sub(leaf.NotBefore).Round(time.Second), leaf.Issuer.CommonName)

	// the same Handle again: refused, 409
	if _, err := s.enroll(request(handle, csr, hint, target, earKey)); status(err) != http.StatusConflict {
		t.Fatalf("replayed Handle: %v", err)
	}
	// Attestation Results for a binding over another Target: refused, 403
	if _, err := s.enroll(request(initiate(), csr, hint, "https://other.tacra.example", earKey)); status(err) != http.StatusForbidden {
		t.Fatalf("binding over another Target: %v", err)
	}
	// Attestation Results not signed by the verifier's key: refused, 403
	intruder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := s.enroll(request(initiate(), csr, hint, target, intruder)); status(err) != http.StatusForbidden {
		t.Fatalf("results under another key: %v", err)
	}
	// an identity the attested launch may not hold: refused, 403
	other, _ := csrFor(t, "ledger.workload.tacra.example")
	if _, err := s.enroll(request(initiate(), other, "ledger.workload.tacra.example", target, earKey)); status(err) != http.StatusForbidden {
		t.Fatalf("identity of another launch: %v", err)
	}
	// a CSR that asks for names itself: refused, 403 (the CA assigns them)
	named, _ := csrFor(t, hint, "spiffe://tacra.example/admin")
	if _, err := s.enroll(request(initiate(), named, hint, target, earKey)); status(err) != http.StatusForbidden {
		t.Fatalf("CSR with its own names: %v", err)
	}
	// a CSR whose signature does not verify: refused, 403
	bad := append([]byte(nil), csr...)
	bad[len(bad)-3] ^= 0xff
	if _, err := s.enroll(request(initiate(), bad, hint, target, earKey)); status(err) != http.StatusForbidden && status(err) != http.StatusBadRequest {
		t.Fatalf("broken CSR signature: %v", err)
	}
}

// TestNameFromBoundCSR needs no step-ca: every case is refused before the CA is asked. Two identities are allowed
// for the same attested launch, so that a conduit rewriting the Credential Hint could pick the other one.
func TestNameFromBoundCSR(t *testing.T) {
	measHex, _ := os.ReadFile("../../internal/ear/testdata/measurement.hex")
	meas := strings.TrimSpace(string(measHex))
	tmpl, err := os.ReadFile("../../internal/ear/testdata/ear-gcp-sevsnp.jws")
	if err != nil {
		t.Fatal(err)
	}
	earKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const batch = "batch.workload.tacra.example"
	cfg := &gateway.Config{RRPID: rrpID, Verifiers: testVerifiers, Targets: map[string]*gateway.Target{target: {
		Verifiers: []string{"veraison"}, CredentialTypes: []string{"x509"}, FreshnessKind: fresh.PresentNonce, ExpiresInS: 300,
		Acceptable: []string{"ecdsa-p256-sha256"},
		Identities: map[string]*gateway.Identity{
			hint:  {SANs: []string{hint}, Measurements: []string{meas}, Validity: "1h"},
			batch: {SANs: []string{batch}, Measurements: []string{meas}, Validity: "1h"},
		}}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := &server{g: &gateway.Gateway{Config: cfg, Mode: "enroll", Fresh: fresh.New(nil),
		EAR: &ear.Verifier{Keys: []ear.TrustedKey{{Name: "veraison", Key: &earKey.PublicKey, Submods: []string{"SEVSNP"}}},
			MaxAge: 2 * time.Minute, Skew: 5 * time.Second}}}
	request := func(csr []byte, h string) *EnrollRequest {
		resp, err := s.g.Initiate(gateway.InitiateRequest{Target: target, CredentialType: "x509"})
		if err != nil {
			t.Fatal(err)
		}
		bv := platform.BindingValue(resp.Handle, rrpID, target, csr)
		jws, err := gateway.SignTestEAR(earKey, strings.TrimSpace(string(tmpl)), bv[:], time.Now(), "")
		if err != nil {
			t.Fatal(err)
		}
		return &EnrollRequest{SecondLeg: gateway.SecondLeg{FreshnessKind: fresh.PresentNonce, Target: target,
			CredentialType: "x509", Handle: resp.Handle, CredentialHint: h, EAR: jws}, CSR: csr}
	}
	named, _ := csrFor(t, hint)
	unnamed, _ := csrFor(t, "")
	for _, c := range []struct {
		name string
		req  *EnrollRequest
		code string
	}{
		{"the conduit rewrites the hint to the other identity of the same launch", request(named, batch), "credential-hint"},
		{"a CSR without a name: the hint alone would choose", request(unnamed, hint), "csr-names"},
		{"a CSR subject with an attribute besides the name", request(csrWithOrg(t, hint), hint), "csr-names"},
	} {
		_, err := s.enroll(c.req)
		var e *gateway.Error
		if !errors.As(err, &e) || e.Status != http.StatusForbidden || e.Code != c.code {
			t.Errorf("%s: got %v, want 403 %s", c.name, err, c.code)
		}
	}
}

func csrWithOrg(t *testing.T, cn string) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn, Organization: []string{"Payments Operations"}}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestAssignIdentity is the name rule alone (tacra-est 14-DECISIONS-FROM-EVIDENCE.md, decision 1): the CA assigns
// an identity the attested launch may hold; the CSR needs no name when that is one identity and names one when it
// is several; a hint must be the identity assigned.
func TestAssignIdentity(t *testing.T) {
	const meas, other = "aa", "bb"
	const batch, ledger = "batch.workload.tacra.example", "ledger.workload.tacra.example"
	one := &gateway.Target{Identities: map[string]*gateway.Identity{
		hint:   {SANs: []string{hint}, Measurements: []string{meas}},
		ledger: {SANs: []string{ledger}, Measurements: []string{other}},
	}}
	two := &gateway.Target{Identities: map[string]*gateway.Identity{
		hint:   {SANs: []string{hint}, Measurements: []string{meas}},
		batch:  {SANs: []string{batch}, Measurements: []string{meas}},
		ledger: {SANs: []string{ledger}, Measurements: []string{other}},
	}}
	parse := func(der []byte) *x509.CertificateRequest {
		c, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	csr := func(cn string, uris ...string) *x509.CertificateRequest {
		der, _ := csrFor(t, cn, uris...)
		return parse(der)
	}
	m, _ := hex.DecodeString(meas)
	for _, c := range []struct {
		name   string
		t      *gateway.Target
		csr    *x509.CertificateRequest
		hint   string
		assign string // "" when refused
		code   string
	}{
		{"one identity, a CSR without a name, no hint", one, csr(""), "", hint, ""},
		{"one identity, a CSR without a name, the same hint", one, csr(""), hint, hint, ""},
		{"one identity, a CSR without a name, a hint for another", one, csr(""), batch, "", "credential-hint"},
		{"one identity, the CSR names it", one, csr(hint), "", hint, ""},
		{"one identity, the CSR names one of another launch", one, csr(ledger), "", "", "identity"},
		{"two identities, a CSR without a name", two, csr(""), hint, "", "csr-names"},
		{"two identities, the CSR names one, no hint", two, csr(batch), "", batch, ""},
		{"two identities, the CSR names one, the hint the other", two, csr(hint), batch, "", "credential-hint"},
		{"a CSR subject with an attribute besides the name", two, parse(csrWithOrg(t, hint)), "", "", "csr-names"},
		{"a CSR that asks for a URI of its own", one, csr("", "spiffe://tacra.example/admin"), "", "", "csr-names"},
	} {
		name, id, err := assignIdentity(c.t, m, c.csr, c.hint)
		if c.assign != "" {
			if err != nil || name != c.assign || id == nil || id.SANs[0] != c.assign {
				t.Errorf("%s: got %q %v, want %q", c.name, name, err, c.assign)
			}
			continue
		}
		var e *gateway.Error
		if !errors.As(err, &e) || e.Status != http.StatusForbidden || e.Code != c.code {
			t.Errorf("%s: got %q %v, want 403 %s", c.name, name, err, c.code)
		}
	}
}
