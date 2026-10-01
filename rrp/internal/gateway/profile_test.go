package gateway

import (
	"strings"
	"testing"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/fresh"
)

// TestBankProfile: the bank profile's rules on a configuration, one fault at a time (tacra-est decisions 5 and 6).
func TestBankProfile(t *testing.T) {
	good := func() *Config {
		return &Config{RRPID: "https://ca1.tacra.example", Profile: "bank", ClientCA: "infra-root.crt",
			Clients:   []string{"est-server.bench.tacra.example"},
			Verifiers: []VerifierConfig{{Name: "veraison", EARKey: "veraison.ear.jwk", Submods: []string{"SEVSNP"}}},
			Targets: map[string]*Target{
				"https://db.tacra.example": {Verifiers: []string{"veraison"}, CredentialTypes: []string{"x509"}, FreshnessKind: fresh.PresentNonce, ExpiresInS: 300,
					Identities: map[string]*Identity{"workload.tacra.example": {SANs: []string{"workload.tacra.example"}, Validity: "1h"}},
					Groups: map[string]*Group{"payments": {SecretPath: "tacra/payments", Purpose: []string{"encrypt", "decrypt"},
						Algorithm: "AES-256-GCM", ValidityS: 3600}}}}}
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("a configuration that keeps the profile: %v", err)
	}
	for _, c := range []struct {
		name  string
		fault func(*Config)
		want  string
	}{
		{"a Target not present-nonce", func(c *Config) {
			c.Targets["https://db.tacra.example"].FreshnessKind = fresh.AbsentTimestamp
			c.Targets["https://db.tacra.example"].MaxAgeS = 60
		}, "every Target is present-nonce"},
		{"an identity valid for a day", func(c *Config) {
			c.Targets["https://db.tacra.example"].Identities["workload.tacra.example"].Validity = "24h"
		}, "at most 1h0m0s"},
		{"a group without key-block attributes", func(c *Config) {
			c.Targets["https://db.tacra.example"].Groups["payments"].Algorithm = ""
		}, "no purpose or algorithm"},
		{"a group valid for a day", func(c *Config) {
			c.Targets["https://db.tacra.example"].Groups["payments"].ValidityS = 86400
		}, "at most 3600"},
		{"an unknown profile", func(c *Config) { c.Profile = "retail" }, "unknown profile"},
		{"no client CA (no mutual TLS)", func(c *Config) { c.ClientCA = "" }, "client_ca and clients are required"},
		{"no protocol caller named", func(c *Config) { c.Clients = nil }, "client_ca and clients are required"},
		{"a Target that names no verifier", func(c *Config) { c.Targets["https://db.tacra.example"].Verifiers = nil }, "names no verifier"},
		{"a Target that names an unknown verifier", func(c *Config) {
			c.Targets["https://db.tacra.example"].Verifiers = []string{"veraison", "evidence-chosen"}
		}, `no verifier named "evidence-chosen"`},
		{"a verifier without a provisioned key", func(c *Config) { c.Verifiers[0].EARKey = "" }, "ear_key and submods are required"},
		{"two verifiers with one name", func(c *Config) { c.Verifiers = append(c.Verifiers, c.Verifiers[0]) }, "a name of its own"},
	} {
		cfg := good()
		c.fault(cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", c.name, err, c.want)
		}
	}
	// without the profile the same Target may use another Freshness Kind
	cfg := good()
	cfg.Profile = ""
	cfg.Targets["https://db.tacra.example"].FreshnessKind = fresh.AbsentTimestamp
	cfg.Targets["https://db.tacra.example"].MaxAgeS = 60
	if err := cfg.Validate(); err != nil {
		t.Fatalf("no profile: %v", err)
	}
}
