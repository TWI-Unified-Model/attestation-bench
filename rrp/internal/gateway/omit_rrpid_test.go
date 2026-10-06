package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/fresh"
)

// TestOmitRRPIDInBinding: with the #19/#20 experiment flag set, the gateway opens the verifier session with the
// binding value computed over an empty RRP identifier, not its own; so Evidence bound to the empty identifier is
// accepted and Evidence bound to this RRP's identifier is refused (nonce mismatch). The default (flag off) is the
// reverse, which TestBackgroundCheck covers.
func TestOmitRRPIDInBinding(t *testing.T) {
	tmplRaw, err := os.ReadFile("../ear/testdata/ear-gcp-sevsnp.jws")
	if err != nil {
		t.Fatal(err)
	}
	tmpl := strings.TrimSpace(string(tmplRaw))
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const rrpID, target = "https://ca1.tacra.example", "https://db.tacra.example"
	subject := []byte("the CSR's DER, as bound")

	v := newFakeVerifier(t, key, tmpl)
	cfg := &Config{RRPID: rrpID, OmitRRPIDInBinding: true, RATSModel: BackgroundCheck,
		Verifiers: []VerifierConfig{{Name: "veraison", EARKey: "veraison.ear.jwk", Submods: []string{"SEVSNP"},
			URL: v.srv.URL, CA: "root.crt", Provider: "sev_guest"}},
		Targets: map[string]*Target{target: {Verifiers: []string{"veraison"}, CredentialTypes: []string{"x509"},
			FreshnessKind: fresh.PresentNonce, ExpiresInS: 300}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	g := &Gateway{Config: cfg, Mode: "enroll", Fresh: fresh.New(nil),
		EAR:       &ear.Verifier{Keys: []ear.TrustedKey{{Name: "veraison", Key: &key.PublicKey, Submods: []string{"SEVSNP"}}}, MaxAge: time.Minute, Skew: 5 * time.Second},
		Appraiser: &Appraiser{Verifiers: []AppraisalVerifier{{Name: "veraison", Provider: "sev_guest", URL: v.srv.URL, Client: v.srv.Client()}}}}

	resp, err := g.Initiate(InitiateRequest{Target: target, CredentialType: "x509"})
	if err != nil {
		t.Fatal(err)
	}
	req := &SecondLeg{FreshnessKind: fresh.PresentNonce, Target: target, CredentialType: "x509", Handle: resp.Handle,
		Evidence: tsmEvidence(t, "sev_guest"), Profile: platform.TSMReportMediaTypeCBOR}
	if _, _, err := g.Check(req, subject); err != nil {
		t.Fatalf("exchange with the flag set: %v", err)
	}
	wantEmpty := platform.BindingValue(resp.Handle, target, "", subject)
	wantID := platform.BindingValue(resp.Handle, target, rrpID, subject)
	if len(v.nonces) != 1 || !bytes.Equal(v.nonces[0], wantEmpty[:]) {
		t.Fatalf("session nonce %x, want the empty-identifier binding %x (not the RRP-identifier one %x)", v.nonces, wantEmpty, wantID)
	}
}
