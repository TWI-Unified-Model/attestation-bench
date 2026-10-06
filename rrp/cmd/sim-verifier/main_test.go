package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/TWI-Unified-Model/tacra/platform"
)

// simEvidence makes Evidence with a SimTEE and returns it with the binding value its report carries.
func simEvidence(t *testing.T, key *ecdsa.PrivateKey, label string, debug bool) ([]byte, []byte) {
	t.Helper()
	sim, err := platform.NewSimTEE(platform.SimTEEConfig{Key: key, Measurement: platform.SimMeasurement(label), Debug: debug})
	if err != nil {
		t.Fatal(err)
	}
	csk, _ := sim.GenerateCSK(platform.SigningAlgorithmECDSAP256)
	signer, _ := csk.Signer()
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "w"}}, signer)
	req := platform.EvidenceRequest{FreshnessKind: platform.FreshnessKindPresentNonce, FreshnessHandle: bytes.Repeat([]byte{1}, 32),
		Target: "https://db.tacra.example", RelyingParty: "https://ca1.tacra.example", BoundKey: csk.Public(), CSR: csr,
		BoundKeyUse: platform.BoundKeyUseSign}
	ev, err := sim.GenerateEvidence(req)
	if err != nil {
		t.Fatal(err)
	}
	bv := platform.BindingValue(req.FreshnessHandle, req.Target, req.RelyingParty, csr)
	return ev.Token, bv[:]
}

// writePub writes a key's public JWK where the configuration names it.
func writePub(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	b, err := platform.SimPublicJWK(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ak.pub.jwk")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestAppraise: the honest report is affirming with its measurement annotated; another attestation key, another
// nonce, a debuggable instance and an unapproved measurement are contraindicated; a token that is not a SimTEE
// TSM report is malformed (no EAR).
func TestAppraise(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg := config{AttestationKeys: []string{writePub(t, key)},
		Measurements: []string{strings.ToUpper(hex.EncodeToString(platform.SimMeasurement("approved")))}}
	a, err := cfg.load()
	if err != nil {
		t.Fatal(err)
	}
	token, bv := simEvidence(t, key, "approved", false)
	st, ann, err := a.appraise(token, bv)
	if st != "affirming" || err != nil || ann["measurement"] != hex.EncodeToString(platform.SimMeasurement("approved")) {
		t.Fatalf("honest report: %s %v %v", st, ann, err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, c := range map[string]struct {
		token, nonce []byte
	}{
		"another attestation key": {func() []byte { tk, _ := simEvidence(t, other, "approved", false); return tk }(), bv},
		"another nonce":           {token, append([]byte{bv[0] ^ 1}, bv[1:]...)},
		"a debuggable instance":   {func() []byte { tk, _ := simEvidence(t, key, "approved", true); return tk }(), nil},
		"an unapproved launch":    {func() []byte { tk, _ := simEvidence(t, key, "unapproved", false); return tk }(), nil},
	} {
		nonce := c.nonce
		if nonce == nil { // the report's own binding value: only the debug flag or the measurement differs
			var tk struct {
				OutBlob []byte `cbor:"outblob"`
			}
			_ = cbor.Unmarshal(c.token, &tk)
			rep, err := platform.ParseSimReport(tk.OutBlob, a.keys)
			if err != nil {
				t.Fatal(err)
			}
			nonce = rep.ReportData
		}
		if st, _, err := a.appraise(c.token, nonce); st != "contraindicated" || err == nil {
			t.Errorf("%s: %s %v, want contraindicated", name, st, err)
		}
	}
	notSim, _ := cbor.Marshal(map[string]any{"provider": "sev_guest", "outblob": []byte{1, 2, 3}})
	if st, _, err := a.appraise(notSim, bv); st != "" || err == nil {
		t.Fatalf("a non-SimTEE token: %q %v, want malformed", st, err)
	}
}

// TestConfig: a configuration without attestation keys, or with a reference value that is not 48 octets, is refused.
func TestConfig(t *testing.T) {
	if _, err := (&config{}).load(); err == nil {
		t.Fatal("no attestation keys was accepted")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := (&config{AttestationKeys: []string{writePub(t, key)}, Measurements: []string{"abcd"}}).load(); err == nil {
		t.Fatal("a 2-octet reference value was accepted")
	}
}
