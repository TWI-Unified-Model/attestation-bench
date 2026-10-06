package verifierapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
)

// fixed appraisal: "malformed" tokens give no EAR, "good" ones are affirming when the nonce is the session's
func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	key, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "ear.jwk"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Key: key, Submod: "SIM", PolicyID: "policy:test", Build: "test",
		Trust: map[string]int{"hardware": 2},
		Appraise: func(token, nonce []byte) (string, map[string]string, error) {
			switch string(token) {
			case "malformed":
				return "", nil, errors.New("not a TSM report")
			case "good":
				return "affirming", map[string]string{"measurement": strings.Repeat("4d", 48)}, nil
			}
			return "contraindicated", map[string]string{}, errors.New("no")
		}}
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return s, srv
}

func newSession(t *testing.T, srv *httptest.Server, nonce []byte) (string, int) {
	t.Helper()
	resp, err := http.Post(srv.URL+"/challenge-response/v1/newSession?nonce="+base64.URLEncoding.EncodeToString(nonce), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Header.Get("Location"), resp.StatusCode
}

func post(t *testing.T, srv *httptest.Server, loc, ctype, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(srv.URL+"/challenge-response/v1/"+loc, ctype, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestSessionToEAR: the EAR for a session carries the session's nonce and the appraisal, and an RRP's EAR verifier
// accepts it with the verifier's published key, for the verifier's submodule only.
func TestSessionToEAR(t *testing.T) {
	s, srv := testServer(t)
	nonce := bytes.Repeat([]byte{0xb1}, 64)
	loc, st := newSession(t, srv, nonce)
	if st != http.StatusCreated || !strings.HasPrefix(loc, "session/") {
		t.Fatalf("newSession: %d %q", st, loc)
	}
	st, out := post(t, srv, loc, MediaType, "good")
	if st != http.StatusOK || out["status"] != "complete" {
		t.Fatalf("Evidence: %d %v", st, out)
	}
	pub, err := ear.KeyFromJWK(func() []byte { b, _ := json.Marshal(PublicJWK(&s.Key.PublicKey)); return b }())
	if err != nil {
		t.Fatal(err)
	}
	v := &ear.Verifier{Keys: []ear.TrustedKey{{Name: "sim", Key: pub, Submods: []string{"SIM"}}}, MaxAge: time.Minute,
		Skew: 5 * time.Second}
	res, err := v.Verify(out["result"].(string), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if res.Submod != "SIM" || res.Status != "affirming" || len(res.Measurement) != 48 {
		t.Fatalf("result %s %s %x", res.Submod, res.Status, res.Measurement)
	}
	if _, err := v.Verify(out["result"].(string), append([]byte{nonce[0] ^ 1}, nonce[1:]...)); !errors.Is(err, ear.ErrNonce) {
		t.Fatalf("another nonce: %v", err)
	}
}

// TestRefusals: malformed Evidence gives 400 and no EAR; another media type 415; a bad nonce 400; an unknown or
// deleted session 404; Evidence that is not affirming gives an EAR that says so, which an RRP refuses.
func TestRefusals(t *testing.T) {
	s, srv := testServer(t)
	nonce := bytes.Repeat([]byte{7}, 32)
	if _, st := newSession(t, srv, []byte("short")); st != http.StatusBadRequest {
		t.Fatalf("a 5-octet nonce: %d", st)
	}
	loc, _ := newSession(t, srv, nonce)
	if st, _ := post(t, srv, loc, "application/json", "good"); st != http.StatusUnsupportedMediaType {
		t.Fatalf("other media type: %d", st)
	}
	if st, out := post(t, srv, loc, MediaType, "malformed"); st != http.StatusBadRequest || out["result"] != nil {
		t.Fatalf("malformed: %d %v", st, out)
	}
	st, out := post(t, srv, loc, MediaType, "bad")
	if st != http.StatusOK {
		t.Fatalf("not affirming: %d", st)
	}
	v := &ear.Verifier{Keys: []ear.TrustedKey{{Key: &s.Key.PublicKey, Submods: []string{"SIM"}}}, MaxAge: time.Minute,
		Skew: 5 * time.Second}
	if _, err := v.Verify(out["result"].(string), nonce); !errors.Is(err, ear.ErrNotAffirming) {
		t.Fatalf("contraindicated EAR: %v", err)
	}
	if st, _ := post(t, srv, "session/0000", MediaType, "good"); st != http.StatusNotFound {
		t.Fatalf("unknown session: %d", st)
	}
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/challenge-response/v1/"+loc, nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: %v", err)
	}
	if st, _ := post(t, srv, loc, MediaType, "good"); st != http.StatusNotFound {
		t.Fatalf("deleted session: %d", st)
	}
}

// TestKeyFile: the signing key is created once and read back the same.
func TestKeyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.jwk")
	k1, err := LoadOrCreateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateKey(p)
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("reloaded key differs: %v", err)
	}
}
