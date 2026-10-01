package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/fresh"
)

// fakeVerifier serves Veraison's challenge-response API and answers each session with an EAR for the session's
// nonce, re-signed from a real EAR's claims (SignTestEAR), and records what it was sent.
type fakeVerifier struct {
	srv    *httptest.Server
	key    *ecdsa.PrivateKey
	tmpl   string
	status string // "" keeps the template's (affirming)

	mu       sync.Mutex
	nonces   [][]byte
	evidence [][]byte
	types    []string
}

func newFakeVerifier(t *testing.T, key *ecdsa.PrivateKey, tmpl string) *fakeVerifier {
	f := &fakeVerifier{key: key, tmpl: tmpl}
	nonces := map[string][]byte{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /challenge-response/v1/newSession", func(w http.ResponseWriter, r *http.Request) {
		n, err := base64.URLEncoding.DecodeString(r.URL.Query().Get("nonce"))
		if err != nil {
			http.Error(w, "bad nonce", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		id := string(rune('a' + len(nonces)))
		nonces[id] = n
		f.nonces = append(f.nonces, n)
		f.mu.Unlock()
		w.Header().Set("Location", "session/"+id)
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("POST /challenge-response/v1/session/{id}", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		n := nonces[r.PathValue("id")]
		f.evidence = append(f.evidence, body)
		f.types = append(f.types, r.Header.Get("Content-Type"))
		f.mu.Unlock()
		jws, err := SignTestEAR(f.key, f.tmpl, n, time.Now(), f.status)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "complete", "result": jws})
	})
	mux.HandleFunc("DELETE /challenge-response/v1/session/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func tsmEvidence(t *testing.T, provider string) []byte {
	b, err := cbor.Marshal(map[string]any{"provider": provider, "outblob": bytes.Repeat([]byte{7}, 64)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func refusalStatus(err error) (int, string) {
	var e *Error
	if errors.As(err, &e) {
		return e.Status, e.Code
	}
	return 0, ""
}

// TestBackgroundCheck: an RRP in the Background Check model asks the verifier itself, with the binding value it
// recomputed as the session's nonce, and takes no Attestation Results from the request (TACRA Goal 6; TWI CAM C).
func TestBackgroundCheck(t *testing.T) {
	tmplRaw, err := os.ReadFile("../ear/testdata/ear-gcp-sevsnp.jws")
	if err != nil {
		t.Fatal(err)
	}
	tmpl := strings.TrimSpace(string(tmplRaw))
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const rrpID, target = "https://ca1.tacra.example", "https://db.tacra.example"
	gw := func(model string, verifiers ...AppraisalVerifier) *Gateway {
		cfg := &Config{RRPID: rrpID, RATSModel: model, Targets: map[string]*Target{target: {
			CredentialTypes: []string{"x509"}, FreshnessKind: fresh.PresentNonce, ExpiresInS: 300}}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		g := &Gateway{Config: cfg, Mode: "enroll", Fresh: fresh.New(nil),
			EAR: &ear.Verifier{Keys: []ear.TrustedKey{{Key: &key.PublicKey, Submods: []string{"SEVSNP"}}},
				MaxAge: time.Minute, Skew: 5 * time.Second}}
		if len(verifiers) > 0 {
			g.Appraiser = &Appraiser{Verifiers: verifiers}
		}
		return g
	}
	subject := []byte("the CSR's DER, as bound")
	leg := func(g *Gateway) (*SecondLeg, [64]byte) {
		resp, err := g.Initiate(InitiateRequest{Target: target, CredentialType: "x509"})
		if err != nil {
			t.Fatal(err)
		}
		return &SecondLeg{FreshnessKind: fresh.PresentNonce, Target: target, CredentialType: "x509", Handle: resp.Handle},
			platform.BindingValue(resp.Handle, rrpID, target, subject)
	}

	v := newFakeVerifier(t, key, tmpl)
	bc := gw(BackgroundCheck, AppraisalVerifier{URL: v.srv.URL, Client: v.srv.Client()})

	// the honest exchange: the RRP opens the session with its own binding value and accepts the verified EAR
	req, bv := leg(bc)
	req.Evidence, req.Profile = tsmEvidence(t, "sev_guest"), platform.TSMReportMediaTypeCBOR
	res, _, err := bc.Check(req, subject)
	if err != nil {
		t.Fatalf("honest exchange: %v", err)
	}
	if res.Submod != "SEVSNP" || len(v.nonces) != 1 || !bytes.Equal(v.nonces[0], bv[:]) {
		t.Fatalf("session nonce %x, want the RRP's binding value %x (submod %s)", v.nonces, bv, res.Submod)
	}
	if !bytes.Equal(v.evidence[0], req.Evidence) || v.types[0] != platform.TSMReportMediaTypeCBOR {
		t.Fatalf("the verifier received other Evidence or media type %q", v.types[0])
	}

	// Attestation Results that come with the request are not taken, with or without Evidence: 400
	forged, _ := SignTestEAR(key, tmpl, bv[:], time.Now(), "")
	for name, mod := range map[string]func(*SecondLeg){
		"an EAR instead of Evidence": func(l *SecondLeg) { l.EAR = forged },
		"an EAR beside the Evidence": func(l *SecondLeg) {
			l.EAR, l.Evidence, l.Profile = forged, tsmEvidence(t, "sev_guest"), platform.TSMReportMediaTypeCBOR
		},
	} {
		l, _ := leg(bc)
		mod(l)
		if st, _ := refusalStatus(func() error { _, _, err := bc.Check(l, subject); return err }()); st != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, st)
		}
	}

	// a Passport RRP takes no Evidence, alone or beside valid Attestation Results: 400
	pp := gw(Passport)
	l, _ := leg(pp)
	l.Evidence, l.Profile = tsmEvidence(t, "sev_guest"), platform.TSMReportMediaTypeCBOR
	if st, _ := refusalStatus(func() error { _, _, err := pp.Check(l, subject); return err }()); st != http.StatusBadRequest {
		t.Errorf("passport with Evidence: status %d, want 400", st)
	}
	l, lbv := leg(pp)
	l.EAR, _ = SignTestEAR(key, tmpl, lbv[:], time.Now(), "")
	l.Evidence, l.Profile = tsmEvidence(t, "sev_guest"), platform.TSMReportMediaTypeCBOR
	if st, _ := refusalStatus(func() error { _, _, err := pp.Check(l, subject); return err }()); st != http.StatusBadRequest {
		t.Errorf("passport with Evidence beside an EAR: status %d, want 400", st)
	}
	l, lbv = leg(pp)
	l.EAR, _ = SignTestEAR(key, tmpl, lbv[:], time.Now(), "")
	if _, _, err := pp.Check(l, subject); err != nil {
		t.Errorf("passport, the EAR alone: %v", err)
	}

	// the verifier answers contraindicated: 403
	v.status = "contraindicated"
	l, _ = leg(bc)
	l.Evidence, l.Profile = tsmEvidence(t, "sev_guest"), platform.TSMReportMediaTypeCBOR
	if st, code := refusalStatus(func() error { _, _, err := bc.Check(l, subject); return err }()); st != http.StatusForbidden || code != "attestation" {
		t.Errorf("contraindicated: %d %s, want 403 attestation", st, code)
	}
	v.status = ""

	// Evidence goes to the verifier named for its TSM provider; the rest to the one without a provider
	tdx := newFakeVerifier(t, key, tmpl)
	routed := gw(BackgroundCheck, AppraisalVerifier{URL: v.srv.URL, Client: v.srv.Client()},
		AppraisalVerifier{Provider: "tdx_guest", URL: tdx.srv.URL, Client: tdx.srv.Client()})
	before := len(v.nonces)
	l, _ = leg(routed)
	l.Evidence, l.Profile = tsmEvidence(t, "tdx_guest"), platform.TSMReportMediaTypeCBOR
	_, _, _ = routed.Check(l, subject) // the template's submodule is SEVSNP; what matters is where the Evidence went
	if len(tdx.nonces) != 1 || len(v.nonces) != before {
		t.Errorf("tdx_guest Evidence went to the TDX verifier %d times and to the default %d times; want 1 and 0",
			len(tdx.nonces), len(v.nonces)-before)
	}

	// the verifier cannot be reached: 503 verifier-unavailable
	down := newFakeVerifier(t, key, tmpl)
	dead := gw(BackgroundCheck, AppraisalVerifier{URL: down.srv.URL, Client: down.srv.Client()})
	down.srv.Close()
	l, _ = leg(dead)
	l.Evidence, l.Profile = tsmEvidence(t, "sev_guest"), platform.TSMReportMediaTypeCBOR
	if st, code := refusalStatus(func() error { _, _, err := dead.Check(l, subject); return err }()); st != http.StatusServiceUnavailable || code != "verifier-unavailable" {
		t.Errorf("verifier down: %d %s, want 503 verifier-unavailable", st, code)
	}

	// an unknown model is a configuration error
	if err := (&Config{RRPID: rrpID, RATSModel: "both", Targets: map[string]*Target{target: {
		CredentialTypes: []string{"x509"}, FreshnessKind: fresh.PresentNonce, ExpiresInS: 300}}}).Validate(); err == nil {
		t.Error("rats_model \"both\" was accepted")
	}
}
