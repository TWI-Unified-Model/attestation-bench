package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/fresh"
)

// TestSimulatedTEE: results for the bench's software stand-in TEE (submodule SIM) are refused unless the RRP's
// configuration sets allow_simulated_tee, even when the Target's policy takes the verifier that signed them and a
// platform policy is configured; with the option they are accepted. A platform policy refuses a submodule it has
// no rule for.
func TestSimulatedTEE(t *testing.T) {
	const rrpID, target = "https://ca1.tacra.example", "https://db.tacra.example"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	claims, _ := json.Marshal(map[string]any{"eat_profile": "tag:github.com,2023:veraison/ear",
		"submods": map[string]any{"SIM": map[string]any{"ear.status": "affirming",
			"ear.veraison.annotated-evidence": map[string]string{"measurement": "4d", "debug": "false"}}}})
	tmpl := "x." + base64.RawURLEncoding.EncodeToString(claims) + ".x"
	subject := []byte("the CSR's DER, as bound")

	gw := func(allow bool, policy *PlatformPolicy) *Gateway {
		cfg := &Config{RRPID: rrpID, RATSModel: Passport, AllowSimulatedTEE: allow, Platform: policy,
			Verifiers: []VerifierConfig{{Name: "sim", EARKey: "sim.ear.jwk", Submods: []string{"SIM"}}},
			Targets: map[string]*Target{target: {Verifiers: []string{"sim"}, CredentialTypes: []string{"x509"},
				FreshnessKind: fresh.PresentNonce, ExpiresInS: 300}}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		return &Gateway{Config: cfg, Mode: "enroll", Fresh: fresh.New(nil),
			EAR: &ear.Verifier{Keys: []ear.TrustedKey{{Name: "sim", Key: &key.PublicKey, Submods: []string{"SIM"}}},
				MaxAge: time.Minute, Skew: 5 * time.Second}}
	}
	check := func(g *Gateway) error {
		resp, err := g.Initiate(InitiateRequest{Target: target, CredentialType: "x509"})
		if err != nil {
			t.Fatal(err)
		}
		bv := platform.BindingValue(resp.Handle, target, rrpID, subject)
		jws, err := SignTestEAR(key, tmpl, bv[:], time.Now(), "")
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = g.Check(&SecondLeg{FreshnessKind: fresh.PresentNonce, Target: target, CredentialType: "x509",
			Handle: resp.Handle, EAR: jws}, subject)
		return err
	}

	tdxOnly := &PlatformPolicy{TDX: &TDXPolicy{}}
	for _, policy := range []*PlatformPolicy{nil, tdxOnly} {
		err := check(gw(false, policy))
		if st, code := refusalStatus(err); st != http.StatusForbidden || code != "platform-policy" || !errors.Is(err, ErrPlatform) {
			t.Fatalf("without allow_simulated_tee (platform policy %v): %v, want 403 platform-policy", policy != nil, err)
		}
		if err := check(gw(true, policy)); err != nil {
			t.Fatalf("with allow_simulated_tee (platform policy %v): %v", policy != nil, err)
		}
	}

	if err := tdxOnly.Check(&ear.Result{Submod: "XYZ"}); !errors.Is(err, ErrPlatform) {
		t.Fatalf("a submodule without a rule: %v, want ErrPlatform", err)
	}
}
