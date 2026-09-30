// Package gateway is what the test bench's two RATS Relying Parties share: the per-Target policy, the answer to
// attest-initiate (Freshness Kind, Handle, rrp_id, mode, algorithms), and the checks a second-leg request passes
// before the Credential Authority issues or the Secret Vault releases: the Target's policy, freshness, and the
// binding value recomputed with this RRP's own identifier and reported by verified, affirming Attestation Results.
package gateway

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/tacra/bundle"
	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/fresh"
)

// Config is a gateway's configuration file.
type Config struct {
	RRPID   string `json:"rrp_id"` // the identifier Evidence binds for this RRP
	Listen  string `json:"listen"`
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// Verifiers whose Attestation Results this RRP accepts, each for its submodules (Veraison for SEVSNP, the
	// bench's TDX verifier for TDX); their EAR keys are read from their well-known endpoints at start.
	Verifiers []struct {
		URL     string   `json:"url"`
		CA      string   `json:"ca"`
		Submods []string `json:"submods"`
	} `json:"verifiers"`
	EAR struct {
		MaxAgeS int `json:"max_age"`
		SkewS   int `json:"skew"`
	} `json:"ear"`
	Targets map[string]*Target `json:"targets"`
	// EpochFile holds the deployment's current epoch marker (hex), shared by its RRPs; absent: a marker of this RRP.
	EpochFile string `json:"epoch_file,omitempty"`
	// Platform is this RRP's rule on the machine, product line, TCB and guest policy the Attestation Results report
	// (platform.go); absent: none beyond the verifier's "affirming".
	Platform *PlatformPolicy `json:"platform,omitempty"`
}

// LoadEpoch installs the epoch marker of EpochFile, if one is configured.
func (g *Gateway) LoadEpoch() error {
	if g.Config.EpochFile == "" {
		return nil
	}
	raw, err := os.ReadFile(g.Config.EpochFile)
	if err != nil {
		return err
	}
	m, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("gateway: %s: not hex", g.Config.EpochFile)
	}
	return g.Fresh.SetEpoch(m)
}

// Target is the policy for one Target.
type Target struct {
	CredentialTypes []string   `json:"credential_types"`
	FreshnessKind   fresh.Kind `json:"freshness_kind"`
	ExpiresInS      int        `json:"expires_in,omitempty"` // present-* Handle lifetime
	MaxAgeS         int        `json:"max_age,omitempty"`    // absent-timestamp
	SkewS           int        `json:"clock_skew,omitempty"` // absent-timestamp, future tolerance
	Acceptable      []string   `json:"acceptable"`           // acceptable_csk (CA) or acceptable_cek (Vault)
	// Identities (Credential Authority), keyed by the identity's name, which the bound CSR's common name or the
	// Credential Hint gives (ca-gateway assignIdentity); Groups (Secret Vault), keyed by Credential Hint.
	Identities map[string]*Identity `json:"identities,omitempty"`
	Groups     map[string]*Group    `json:"groups,omitempty"`
}

// Identity is what the Credential Authority may certify under one name, and for which launch measurements.
type Identity struct {
	SANs         []string `json:"sans"`
	Measurements []string `json:"measurements"` // hex; the attested launches allowed this identity
	Validity     string   `json:"validity"`     // e.g. "1h"
}

// Group is what the Secret Vault may release for a Credential Hint, and to which launch measurements.
type Group struct {
	SecretPath    string   `json:"secret_path"` // KV v2 path under the mount, e.g. "tacra/payments"
	Measurements  []string `json:"measurements"`
	PolicyVersion string   `json:"policy_version"`
}

// DecodeConfigFile reads a JSON configuration file into v, refusing fields v does not have.
func DecodeConfigFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("gateway: %s: %w", path, err)
	}
	return nil
}

// Validate checks the policy.
func (c *Config) Validate() error {
	if c.RRPID == "" || len(c.Targets) == 0 {
		return errors.New("gateway: rrp_id and at least one Target are required")
	}
	for name, t := range c.Targets {
		if !t.FreshnessKind.Valid() {
			return fmt.Errorf("gateway: Target %s: unknown Freshness Kind %q", name, t.FreshnessKind)
		}
		if (t.FreshnessKind == fresh.PresentNonce || t.FreshnessKind == fresh.PresentEpoch) && t.ExpiresInS < 60 {
			return fmt.Errorf("gateway: Target %s: expires_in below 60 s", name) // draft: Handle Lifetime
		}
		if t.FreshnessKind == fresh.AbsentTimestamp && t.MaxAgeS <= 0 {
			return fmt.Errorf("gateway: Target %s: absent-timestamp needs max_age", name)
		}
	}
	if c.Platform != nil {
		if err := c.Platform.Validate(); err != nil {
			return fmt.Errorf("gateway: %w", err)
		}
	}
	return nil
}

// TrustedKeys reads each configured verifier's EAR key.
func (c *Config) TrustedKeys() ([]ear.TrustedKey, error) {
	var keys []ear.TrustedKey
	for _, v := range c.Verifiers {
		k, err := ear.FetchVeraisonKey(v.URL, v.CA)
		if err != nil {
			return nil, fmt.Errorf("gateway: verifier %s: %w", v.URL, err)
		}
		keys = append(keys, ear.TrustedKey{Key: k, Submods: v.Submods})
	}
	if len(keys) == 0 {
		return nil, errors.New("gateway: no verifier configured")
	}
	return keys, nil
}

// Gateway holds a running RRP's state.
type Gateway struct {
	Config *Config
	Mode   string // "enroll" (Credential Authority) or "retrieve" (Secret Vault)
	Fresh  *fresh.Store
	EAR    *ear.Verifier
	Now    func() time.Time
}

// Error is a refusal with the HTTP status the draft's error handling gives it.
type Error struct {
	Status int
	Code   string
	Err    error
}

func (e *Error) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func refuse(status int, code string, err error) *Error { return &Error{status, code, err} }

// Errors a handler can wrap.
var (
	ErrPolicy = errors.New("not allowed by this RRP's policy for the Target")
	ErrPoP    = errors.New("the CSR is not signed by its own key")
)

// InitiateRequest is what the EST Server asks at attest-initiate.
type InitiateRequest struct {
	Target         string `json:"target"`
	CredentialType string `json:"credential_type"`
}

// InitiateResponse carries the fields of the AttestationInitiationResponse this RRP originates.
type InitiateResponse struct {
	FreshnessKind fresh.Kind `json:"freshness_kind"`
	Handle        bundle.B64 `json:"handle,omitempty"`
	RRPID         string     `json:"rrp_id"`
	ExpiresIn     int        `json:"expires_in,omitempty"`
	MaxAge        int        `json:"max_age,omitempty"`
	Mode          string     `json:"mode"`
	AcceptableCSK []string   `json:"acceptable_csk,omitempty"`
	AcceptableCEK []string   `json:"acceptable_cek,omitempty"`
}

// SecondLeg holds the fields both attest-enroll and attest-retrieve carry to the RRP, with the Attestation Results.
type SecondLeg struct {
	FreshnessKind  fresh.Kind `json:"freshness_kind"`
	Target         string     `json:"target"`
	CredentialType string     `json:"credential_type"`
	Handle         bundle.B64 `json:"handle,omitempty"` // the freshness element
	CredentialHint string     `json:"credential_hint,omitempty"`
	EAR            string     `json:"ear"` // Attestation Results from the Verifier
}

func (g *Gateway) target(name, credentialType string) (*Target, error) {
	t, ok := g.Config.Targets[name]
	if !ok {
		return nil, refuse(http.StatusForbidden, "unsupported-target", ErrPolicy)
	}
	if !slices.Contains(t.CredentialTypes, credentialType) {
		return nil, refuse(http.StatusForbidden, "unsupported-credential-type", ErrPolicy)
	}
	return t, nil
}

// Initiate answers attest-initiate for a Target: this RRP originates the Handle, never the conduit.
func (g *Gateway) Initiate(req InitiateRequest) (*InitiateResponse, error) {
	t, err := g.target(req.Target, req.CredentialType)
	if err != nil {
		return nil, err
	}
	resp := &InitiateResponse{FreshnessKind: t.FreshnessKind, RRPID: g.Config.RRPID, Mode: g.Mode}
	switch t.FreshnessKind {
	case fresh.PresentNonce:
		resp.Handle = g.Fresh.MintNonce(req.Target, req.CredentialType, time.Duration(t.ExpiresInS)*time.Second)
		resp.ExpiresIn = t.ExpiresInS
	case fresh.PresentEpoch:
		resp.Handle = g.Fresh.Epoch()
		resp.ExpiresIn = t.ExpiresInS
	case fresh.AbsentTimestamp:
		resp.MaxAge = t.MaxAgeS
	}
	if g.Mode == "enroll" {
		resp.AcceptableCSK = t.Acceptable
	} else {
		resp.AcceptableCEK = t.Acceptable
	}
	return resp, nil
}

// Check runs the checks common to both modes for a second leg whose binding subject is subject (the CSR DER, or
// CEKpub's SubjectPublicKeyInfo DER), and returns the verified Attestation Results and the Target's policy.
func (g *Gateway) Check(req *SecondLeg, subject []byte) (*ear.Result, *Target, error) {
	t, err := g.target(req.Target, req.CredentialType)
	if err != nil {
		return nil, nil, err
	}
	if req.FreshnessKind != t.FreshnessKind {
		return nil, nil, refuse(http.StatusForbidden, "freshness-kind-mismatch", ErrPolicy)
	}
	maxAge, skew := time.Duration(t.MaxAgeS)*time.Second, time.Duration(t.SkewS)*time.Second
	if err := g.Fresh.Accept(req.FreshnessKind, req.Handle, req.Target, req.CredentialType, maxAge, skew); err != nil {
		if errors.Is(err, fresh.ErrStale) {
			return nil, nil, refuse(http.StatusConflict, "freshness", err)
		}
		return nil, nil, refuse(http.StatusBadRequest, "freshness", err)
	}
	bv := platform.BindingValue(req.Handle, g.Config.RRPID, req.Target, subject)
	res, err := g.EAR.Verify(req.EAR, bv[:])
	if err != nil {
		return nil, nil, refuse(http.StatusForbidden, "attestation", err)
	}
	if g.Config.Platform != nil {
		if err := g.Config.Platform.Check(res); err != nil {
			return nil, nil, refuse(http.StatusForbidden, "platform-policy", err)
		}
	}
	return res, t, nil
}

// Allowed reports whether the launch measurement is one the policy names.
func Allowed(measurement []byte, allowed []string) bool {
	m := hex.EncodeToString(measurement)
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), m) {
			return true
		}
	}
	return false
}

// Platform names the TEE family of an accepted submodule, as the Vault's group derivation uses it.
func Platform(submod string) string {
	switch submod {
	case "SEVSNP":
		return "sev-snp"
	case "TDX":
		return "tdx"
	}
	return strings.ToLower(submod)
}

// DecodeJSON reads a request body into v, refusing unknown fields and bodies over 1 MiB.
func DecodeJSON(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return refuse(http.StatusBadRequest, "malformed", err)
	}
	return nil
}

// WriteJSON writes v with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes a refusal. The detail names the check that failed; it does not echo Evidence.
func WriteError(w http.ResponseWriter, err error) {
	var e *Error
	if !errors.As(err, &e) {
		e = refuse(http.StatusInternalServerError, "internal", err)
	}
	WriteJSON(w, e.Status, map[string]string{"error": e.Code, "detail": e.Err.Error()})
}
