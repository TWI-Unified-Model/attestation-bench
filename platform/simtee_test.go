package platform

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func newSimForTest(t *testing.T, debug bool) (*SimTEE, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch := bytes.Repeat([]byte{0x5e}, 32)
	sim, err := NewSimTEE(SimTEEConfig{Key: key, Measurement: SimMeasurement("test workload"), Debug: debug},
		WithLocalEpoch(epoch))
	if err != nil {
		t.Fatal(err)
	}
	return sim, key, epoch
}

// simRequest builds an Evidence request the way the CAI and hwrun do, for one Freshness Kind and mode.
func simRequest(t *testing.T, sim *SimTEE, kind FreshnessKind, enroll bool, epoch []byte) EvidenceRequest {
	t.Helper()
	req := EvidenceRequest{FreshnessKind: kind, Target: "https://db.tacra.example"}
	switch kind {
	case FreshnessKindPresentNonce:
		req.FreshnessHandle = bytes.Repeat([]byte{0x11}, 32)
	case FreshnessKindPresentEpoch, FreshnessKindAbsentEpoch:
		req.FreshnessHandle = epoch
	}
	if enroll {
		req.RelyingParty = "https://ca1.tacra.example"
		csk, err := sim.GenerateCSK(SigningAlgorithmECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := csk.Signer()
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "w"}}, signer)
		if err != nil {
			t.Fatal(err)
		}
		req.BoundKey, req.CSR, req.BoundKeyUse = csk.Public(), csr, BoundKeyUseSign
	} else {
		req.RelyingParty = "https://vault1.tacra.example"
		cek, err := sim.GenerateCEK(EncryptionAlgorithmMLKEM768P256)
		if err != nil {
			t.Fatal(err)
		}
		req.BoundKey, req.BoundKeyUse = cek.Public(), BoundKeyUseEncrypt
	}
	return req
}

// Every Freshness Kind, Enrollment and Retrieval: the report signed by the SimTEE carries, as ReportData, the binding
// value an RRP recomputes from the Evidence's own claims and the subject, exactly as for REPORT_DATA on hardware.
func TestSimTEEBinding(t *testing.T) {
	sim, key, epoch := newSimForTest(t, false)
	kinds := []FreshnessKind{FreshnessKindPresentNonce, FreshnessKindPresentEpoch, FreshnessKindAbsentEpoch,
		FreshnessKindAbsentTimestamp, FreshnessKindAbsentNone}
	for _, kind := range kinds {
		for _, enroll := range []bool{true, false} {
			req := simRequest(t, sim, kind, enroll, epoch)
			ev, err := sim.GenerateEvidence(req)
			if err != nil {
				t.Fatalf("kind %d enroll %v: %v", kind, enroll, err)
			}
			if ev.MediaType != TSMReportMediaTypeCBOR {
				t.Fatalf("media type %q", ev.MediaType)
			}
			var tok tsmReport
			if err := cbor.Unmarshal(ev.Token, &tok); err != nil || tok.Provider != SimProvider {
				t.Fatalf("TSM token: provider %q, %v", tok.Provider, err)
			}
			rep, err := ParseSimReport(tok.OutBlob, []*ecdsa.PublicKey{&key.PublicKey})
			if err != nil {
				t.Fatal(err)
			}
			var claims map[string]any
			if err := cbor.Unmarshal(ev.Claims, &claims); err != nil {
				t.Fatal(err)
			}
			elem, _ := claims[TSMClaimFreshnessElement].([]byte)
			subject, err := Subject(req)
			if err != nil {
				t.Fatal(err)
			}
			want := BindingValue(elem, claims[TSMClaimTarget].(string), claims[TSMClaimRelyingParty].(string), subject)
			if !bytes.Equal(rep.ReportData, want[:]) {
				t.Fatalf("kind %d enroll %v: ReportData is not the recomputed binding value", kind, enroll)
			}
			if !bytes.Equal(rep.Measurement, SimMeasurement("test workload")) || rep.Debug {
				t.Fatalf("measurement or debug wrong: %x %v", rep.Measurement, rep.Debug)
			}
		}
	}
}

// A report checked against another key, or altered in one bit, is refused; a debug instance says so.
func TestSimTEERefusals(t *testing.T) {
	sim, key, epoch := newSimForTest(t, false)
	ev, err := sim.GenerateEvidence(simRequest(t, sim, FreshnessKindPresentNonce, true, epoch))
	if err != nil {
		t.Fatal(err)
	}
	var tok tsmReport
	if err := cbor.Unmarshal(ev.Token, &tok); err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := ParseSimReport(tok.OutBlob, []*ecdsa.PublicKey{&other.PublicKey}); !errors.Is(err, ErrSimReport) {
		t.Fatalf("another key: %v", err)
	}
	if _, err := ParseSimReport(tok.OutBlob, nil); !errors.Is(err, ErrSimReport) {
		t.Fatalf("no trusted key: %v", err)
	}
	changed := bytes.Clone(tok.OutBlob)
	changed[len(changed)-70] ^= 1 // inside the payload or the signature
	if _, err := ParseSimReport(changed, []*ecdsa.PublicKey{&key.PublicKey}); err == nil {
		t.Fatal("an altered report was accepted")
	}
	dbg, dkey, depoch := newSimForTest(t, true)
	ev, err = dbg.GenerateEvidence(simRequest(t, dbg, FreshnessKindAbsentNone, true, depoch))
	if err != nil {
		t.Fatal(err)
	}
	if err := cbor.Unmarshal(ev.Token, &tok); err != nil {
		t.Fatal(err)
	}
	rep, err := ParseSimReport(tok.OutBlob, []*ecdsa.PublicKey{&dkey.PublicKey})
	if err != nil || !rep.Debug {
		t.Fatalf("debug instance: %v %v", rep, err)
	}
}

func TestNewSimTEERefusesBadConfig(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := NewSimTEE(SimTEEConfig{Key: key, Measurement: make([]byte, 32)}); err == nil {
		t.Fatal("a 32-octet measurement was accepted")
	}
	if _, err := NewSimTEE(SimTEEConfig{Measurement: make([]byte, SimMeasurementSize)}); err == nil {
		t.Fatal("no key was accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewSimTEE(SimTEEConfig{Key: p384, Measurement: make([]byte, SimMeasurementSize)}); err == nil {
		t.Fatal("a P-384 key was accepted")
	}
}

func TestSimKeyFiles(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, err := SimPublicJWK(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var j map[string]string
	if err := json.Unmarshal(pub, &j); err != nil {
		t.Fatal(err)
	}
	j["d"] = encB64(key.D.FillBytes(make([]byte, 32)))
	priv, _ := json.Marshal(j)
	path := filepath.Join(t.TempDir(), "ak.jwk")
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSimKey(path)
	if err != nil || !got.Equal(key) {
		t.Fatalf("LoadSimKey: %v", err)
	}
	back, err := ParseSimPublicJWK(pub)
	if err != nil || !back.Equal(&key.PublicKey) {
		t.Fatalf("ParseSimPublicJWK: %v", err)
	}
	if _, err := ParseSimPublicJWK(priv); err == nil {
		t.Fatal("a private JWK was accepted as a Verifier's key")
	}
	j["x"] = j["y"] // not a point on the curve
	bad, _ := json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": j["x"], "y": j["y"]})
	if _, err := ParseSimPublicJWK(bad); err == nil {
		t.Fatal("a point off the curve was accepted")
	}
}

func encB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
