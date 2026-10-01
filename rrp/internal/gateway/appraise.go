package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/mtls"
)

// Appraiser sends Evidence to a verifier for an RRP in the Background Check model (TWI CAM C: the Credential
// Authority "handles the Credential Request by contacting the Verifier on the Workload's behalf, supplying the
// Evidence from the Credential Request"). It speaks Veraison's challenge-response API, as the EST backend does in
// Passport: a session opened with a nonce, here the binding value this RRP recomputed, and the Evidence posted to
// it, over mutual TLS with this RRP's own certificate (N23).
//
// Which verifier is the Target's policy's choice (N24; CVE-2026-92792): only the verifiers it names are asked. When it
// names more than one, one for each platform it takes, the TSM report's provider picks among them, and Evidence
// that none of them appraises is refused; there is no default verifier for the rest.
type Appraiser struct {
	Verifiers []AppraisalVerifier
}

// AppraisalVerifier is one verifier the Appraiser may send Evidence to.
type AppraisalVerifier struct {
	Name     string // its name in the configuration, which Targets' policies name
	Provider string // the TSM report provider of the Evidence it appraises ("sev_guest", "tdx_guest")
	URL      string
	Client   *http.Client
}

// NewAppraiser builds the Appraiser from the configured verifiers: their URLs, TLS CAs and this RRP's client
// certificate.
func NewAppraiser(c *Config) (*Appraiser, error) {
	a := &Appraiser{}
	for _, v := range c.Verifiers {
		tc, err := mtls.ClientTLS(v.CA, c.ClientCert, c.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("gateway: verifier %s: %w", v.Name, err)
		}
		a.Verifiers = append(a.Verifiers, AppraisalVerifier{Name: v.Name, Provider: v.Provider, URL: strings.TrimRight(v.URL, "/"),
			Client: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}})
	}
	if len(a.Verifiers) == 0 {
		return nil, errors.New("gateway: background-check needs a verifier")
	}
	return a, nil
}

// route picks, among the verifiers the Target's policy takes (accept), the one for the Evidence's TSM provider.
func (a *Appraiser) route(evidence []byte, accept []string) (*AppraisalVerifier, error) {
	var t struct {
		Provider string `cbor:"provider"`
	}
	provider := ""
	if cbor.Unmarshal(evidence, &t) == nil {
		provider = strings.TrimSpace(t.Provider)
	}
	for i := range a.Verifiers {
		v := &a.Verifiers[i]
		if slices.Contains(accept, v.Name) && v.Provider != "" && v.Provider == provider {
			return v, nil
		}
	}
	return nil, refuse(http.StatusForbidden, "verifier",
		fmt.Errorf("none of the verifiers this RRP takes for the Target (%s) appraises Evidence of provider %q",
			strings.Join(accept, ", "), provider))
}

// Appraise runs one challenge-response session with the verifier the Target's policy takes for this Evidence
// (accept: the policy's verifier names) and returns its Attestation Results, unverified: the RRP verifies them as it
// verifies those the EST server forwards in Passport (ear.Verifier).
func (a *Appraiser) Appraise(evidence []byte, mediaType string, nonce []byte, accept []string) (string, error) {
	v, err := a.route(evidence, accept)
	if err != nil {
		return "", err
	}
	unavailable := func(format string, args ...any) error {
		return refuse(http.StatusServiceUnavailable, "verifier-unavailable", fmt.Errorf(format, args...))
	}
	log.Printf("background-check: this RRP asks %s (%s), %d octets of Evidence (%s)", v.URL, v.Name, len(evidence), mediaType)
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
