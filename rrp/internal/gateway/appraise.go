package gateway

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Appraiser sends Evidence to a verifier for an RRP in the Background Check model (TWI CAM C: the Credential
// Authority "handles the Credential Request by contacting the Verifier on the Workload's behalf, supplying the
// Evidence from the Credential Request"). It speaks Veraison's challenge-response API, as the EST backend does in
// Passport: a session opened with a nonce, here the binding value this RRP recomputed, and the Evidence posted to
// it. It routes Evidence by the TSM report's provider, as the EST backend does; that is not appraising it.
type Appraiser struct {
	Verifiers []AppraisalVerifier
}

// AppraisalVerifier is one verifier the Appraiser may send Evidence to.
type AppraisalVerifier struct {
	Provider string // TSM report provider ("tdx_guest", "sev_guest"); "" takes the rest
	URL      string
	Client   *http.Client
}

// NewAppraiser builds the Appraiser from the configured verifiers (their URLs and TLS CAs).
func NewAppraiser(c *Config) (*Appraiser, error) {
	a := &Appraiser{}
	for _, v := range c.Verifiers {
		pem, err := os.ReadFile(v.CA)
		if err != nil {
			return nil, fmt.Errorf("gateway: verifier %s: %w", v.URL, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("gateway: verifier %s: no CA certificate in %s", v.URL, v.CA)
		}
		a.Verifiers = append(a.Verifiers, AppraisalVerifier{Provider: v.Provider, URL: strings.TrimRight(v.URL, "/"),
			Client: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}})
	}
	if len(a.Verifiers) == 0 {
		return nil, errors.New("gateway: background-check needs a verifier")
	}
	return a, nil
}

// route picks the verifier for the Evidence: the one named for its TSM provider, otherwise the one without a provider.
func (a *Appraiser) route(evidence []byte) (*AppraisalVerifier, error) {
	var t struct {
		Provider string `cbor:"provider"`
	}
	provider := ""
	if cbor.Unmarshal(evidence, &t) == nil {
		provider = strings.TrimSpace(t.Provider)
	}
	var fallback *AppraisalVerifier
	for i := range a.Verifiers {
		v := &a.Verifiers[i]
		if v.Provider != "" && v.Provider == provider {
			return v, nil
		}
		if v.Provider == "" && fallback == nil {
			fallback = v
		}
	}
	if fallback == nil {
		return nil, refuse(http.StatusUnsupportedMediaType, "unsupported-evidence",
			fmt.Errorf("no verifier for Evidence of provider %q", provider))
	}
	return fallback, nil
}

// Appraise runs one challenge-response session and returns its Attestation Results, unverified: the RRP verifies
// them as it verifies those the EST server forwards in Passport (ear.Verifier).
func (a *Appraiser) Appraise(evidence []byte, mediaType string, nonce []byte) (string, error) {
	v, err := a.route(evidence)
	if err != nil {
		return "", err
	}
	unavailable := func(format string, args ...any) error {
		return refuse(http.StatusServiceUnavailable, "verifier-unavailable", fmt.Errorf(format, args...))
	}
	log.Printf("background-check: this RRP asks %s, %d octets of Evidence (%s)", v.URL, len(evidence), mediaType)
	q := url.Values{"nonce": {base64.URLEncoding.EncodeToString(nonce)}}
	resp, err := v.Client.Post(v.URL+"/challenge-response/v1/newSession?"+q.Encode(), "application/json", nil)
	if err != nil {
		return "", unavailable("verifier %s: %v", v.URL, err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusCreated || loc == "" {
		return "", unavailable("verifier %s refused a session: HTTP %d", v.URL, resp.StatusCode)
	}
	if !strings.HasPrefix(loc, "http") {
		loc = v.URL + "/challenge-response/v1/" + strings.TrimPrefix(loc, "/")
	}
	defer func() {
		if del, err := http.NewRequest(http.MethodDelete, loc, nil); err == nil {
			if r, err := v.Client.Do(del); err == nil {
				r.Body.Close()
			}
		}
	}()
	req, err := http.NewRequest(http.MethodPost, loc, bytes.NewReader(evidence))
	if err != nil {
		return "", unavailable("verifier %s: %v", v.URL, err)
	}
	req.Header.Set("Content-Type", mediaType)
	req.Header.Set("Accept", "application/vnd.veraison.challenge-response-session+json")
	resp, err = v.Client.Do(req)
	if err != nil {
		return "", unavailable("verifier %s: %v", v.URL, err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	var s struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Status != "complete" || s.Result == "" {
		return "", refuse(http.StatusForbidden, "attestation",
			fmt.Errorf("verifier %s produced no Attestation Results (HTTP %d)", v.URL, resp.StatusCode))
	}
	return s.Result, nil
}
