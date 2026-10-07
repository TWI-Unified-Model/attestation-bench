// Package gateway is what the test bench's two RATS Relying Parties share: the per-Target policy, the answer to
// attest-initiate (Freshness Kind, Handle, rrp_id, mode, algorithms), and the checks a second-leg request passes
// before the Credential Authority issues or the Secret Vault releases: the Target's policy, freshness, and the
// binding value recomputed with this RRP's own identifier and reported by verified, affirming Attestation Results.
package gateway

import (
	"crypto/tls"
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
	"github.com/TWI-Unified-Model/tacra/rrp/internal/mtls"
)

// Config is a gateway's configuration file.
type Config struct {
	RRPID string `json:"rrp_id"` // the identifier Evidence binds for this RRP
	// OmitRRPIDInBinding, when set, makes this RRP recompute the binding value with an empty RRP identifier, as if
	// TACRA carried none (TheBankster/rats-tacra#19 and #20: whether the RRP identifier belongs in the binding). It
	// is an experiment to measure, on hardware, what the identifier prevents; the default (false) keeps the
	// identifier in the binding. RRPID is still reported at attest-initiate either way.
	OmitRRPIDInBinding bool   `json:"omit_rrp_id_in_binding,omitempty"`
	Listen             string `json:"listen"`
	TLSCert            string `json:"tls_cert"`
	TLSKey             string `json:"tls_key"`
	// Mutual TLS (N23). ClientCA certifies the callers this RRP takes; Clients are the identities among them (a DNS
	// name or URI of the certificate) that may run the protocol, the EST server's; any other caller of ClientCA may
	// read public material only (the Vault's origin keys). ClientCert and ClientKey are this RRP's own certificate
	// when it calls a verifier, step-ca or HashiCorp Vault.
	ClientCA   string   `json:"client_ca,omitempty"`
	Clients    []string `json:"clients,omitempty"`
	ClientCert string   `json:"client_cert,omitempty"`
	ClientKey  string   `json:"client_key,omitempty"`
	// Verifiers whose Attestation Results this RRP may take, each by name; a Target's policy names those it takes
	// (Target.Verifiers).
	Verifiers []VerifierConfig `json:"verifiers"`
	// RATSModel says how this RRP takes the Verifier's word (TACRA Goal 6): "passport" (the default), the
	// Attestation Results the EST server obtained and forwards; "background-check", the Attester's Evidence,
	// which this RRP sends to a verifier itself, with the binding value it recomputed as the session's nonce
	// (TWI CAM C; Mark Novak, TheBankster/rats-tacra#6: "the Verifier would be contacted by SV and CA in
	// Background Check mode").
	RATSModel string `json:"rats_model,omitempty"`
	EAR       struct {
		MaxAgeS int `json:"max_age"`
		SkewS   int `json:"skew"`
	} `json:"ear"`
	Targets map[string]*Target `json:"targets"`
	// EpochFile holds the deployment's current epoch marker (hex), shared by its RRPs; absent: a marker of this RRP.
	EpochFile string `json:"epoch_file,omitempty"`
	// Platform is this RRP's rule on the machine, product line, TCB and guest policy the Attestation Results report
	// (platform.go); absent: none beyond the verifier's "affirming".
	Platform *PlatformPolicy `json:"platform,omitempty"`
	// Profile "bank" adds the bank profile's rules (tacra-est BANK-PROFILE, decisions 5 and 6): every Target
	// present-nonce; certificates and released items for at most an hour; every group with its key-block attributes;
	// a shared private key only for a group declared a replicated service.
	Profile string `json:"profile,omitempty"`
}

// BankMaxValidity is the bank profile's longest lifetime of a certificate or a released item: one appraisal of 60
// minutes, the longest of PCI's attestation intervals for software on platforms it does not trust.
const BankMaxValidity = time.Hour

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

// VerifierConfig is one verifier this RRP may take Attestation Results from.
type VerifierConfig struct {
	Name string `json:"name"` // how Targets' policies name it
	// EARKey is the file of its EAR verification key, an EC P-256 public JWK or PEM key, as this RRP's operator
	// provisioned it (N24); the RRP never fetches the key from the verifier.
	EARKey  string   `json:"ear_key"`
	Submods []string `json:"submods"` // the submodules its results may speak for ("SEVSNP", "TDX")
	// Background Check: where this RRP asks it (URL, its TLS CA), and the TSM report provider of the Evidence it
	// appraises ("sev_guest", "tdx_guest"). The provider only picks among the verifiers the Target's policy takes.
	URL      string `json:"url,omitempty"`
	CA       string `json:"ca,omitempty"`
	Provider string `json:"provider,omitempty"`
}

// Target is the policy for one Target.
type Target struct {
	CredentialTypes []string   `json:"credential_types"`
	FreshnessKind   fresh.Kind `json:"freshness_kind"`
	// Verifiers names the verifiers whose Attestation Results this RRP takes for the Target (N24; CVE-2026-92792:
	// the appraisal path is chosen by the Relying Party's configuration, never by a field of the Evidence). A Target
	// that takes one platform names one verifier.
	Verifiers  []string `json:"verifiers"`
	ExpiresInS int      `json:"expires_in,omitempty"` // present-* Handle lifetime
	MaxAgeS    int      `json:"max_age,omitempty"`    // absent-timestamp
	SkewS      int      `json:"clock_skew,omitempty"` // absent-timestamp, future tolerance
	Acceptable []string `json:"acceptable"`           // acceptable_csk (CA) or acceptable_cek (Vault)
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

// Group is what the Secret Vault may release for a Credential Hint, and to which launch measurements, with the
// key-block attributes the released item carries (what it may be used for, with which algorithm and mode; it never
// leaves the TEE) and how long it counts as valid.
type Group struct {
	SecretPath    string   `json:"secret_path"` // KV v2 path under the mount, e.g. "tacra/payments"
	Measurements  []string `json:"measurements"`
	PolicyVersion string   `json:"policy_version"`
	Purpose       []string `json:"purpose,omitempty"`          // e.g. ["encrypt", "decrypt"]
	Algorithm     string   `json:"algorithm,omitempty"`        // e.g. "AES-256-GCM"
	Replicated    bool     `json:"replicated,omitempty"`       // a replicated service whose instances share a private key
	ValidityS     int      `json:"validity_seconds,omitempty"` // default 3600
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
	verifiers := map[string]*VerifierConfig{}
	for i := range c.Verifiers {
		v := &c.Verifiers[i]
		if v.Name == "" || verifiers[v.Name] != nil {
			return fmt.Errorf("gateway: verifier %d: a name of its own is required", i)
		}
		if v.EARKey == "" || len(v.Submods) == 0 {
			return fmt.Errorf("gateway: verifier %s: ear_key and submods are required", v.Name)
		}
		if c.RATSModel == BackgroundCheck && (v.URL == "" || v.CA == "" || v.Provider == "") {
			return fmt.Errorf("gateway: verifier %s: background-check asks it, and needs its url, ca and provider", v.Name)
		}
		verifiers[v.Name] = v
	}
	if (c.ClientCert == "") != (c.ClientKey == "") {
		return errors.New("gateway: client_cert and client_key go together")
	}
	for name, t := range c.Targets {
		if len(t.Verifiers) == 0 {
			return fmt.Errorf("gateway: Target %s names no verifier whose results it takes", name)
		}
		for _, v := range t.Verifiers {
			if verifiers[v] == nil {
				return fmt.Errorf("gateway: Target %s: no verifier named %q", name, v)
			}
		}
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
	switch c.RATSModel {
	case "", Passport, BackgroundCheck:
	default:
		return fmt.Errorf("gateway: unknown rats_model %q", c.RATSModel)
	}
	switch c.Profile {
	case "":
	case "bank":
		if c.ClientCA == "" || len(c.Clients) == 0 {
			return errors.New("gateway: bank profile: client_ca and clients are required (mutual TLS with the EST server)")
		}
		for name, t := range c.Targets {
			if t.FreshnessKind != fresh.PresentNonce {
				return fmt.Errorf("gateway: bank profile: every Target is present-nonce; %s is %s", name, t.FreshnessKind)
			}
			for n, id := range t.Identities {
				d, err := time.ParseDuration(id.Validity)
				if err != nil || d <= 0 || d > BankMaxValidity {
					return fmt.Errorf("gateway: bank profile: identity %s at %s valid for %q; at most %s", n, name, id.Validity, BankMaxValidity)
				}
			}
			for h, g := range t.Groups {
				if len(g.Purpose) == 0 || g.Algorithm == "" {
					return fmt.Errorf("gateway: bank profile: group %s at %s has no purpose or algorithm for its key block", h, name)
				}
				if g.ValidityS > int(BankMaxValidity/time.Second) {
					return fmt.Errorf("gateway: bank profile: group %s at %s valid for %d s; at most %d", h, name, g.ValidityS, int(BankMaxValidity/time.Second))
				}
			}
		}
	default:
		return fmt.Errorf("gateway: unknown profile %q", c.Profile)
	}
	return nil
}

// TrustedKeys reads each configured verifier's EAR key from the file its operator provisioned.
func (c *Config) TrustedKeys() ([]ear.TrustedKey, error) {
	var keys []ear.TrustedKey
	for _, v := range c.Verifiers {
		k, err := ear.LoadKey(v.EARKey)
		if err != nil {
			return nil, fmt.Errorf("gateway: verifier %s: %w", v.Name, err)
		}
		keys = append(keys, ear.TrustedKey{Name: v.Name, Key: k, Submods: v.Submods})
	}
	if len(keys) == 0 {
		return nil, errors.New("gateway: no verifier configured")
	}
	return keys, nil
}

// PublicPaths are the routes of public material, which any caller with a certificate of the client CA may read.
var PublicPaths = []string{"/tacra/v1/origin-keys"}

// ServerTLS is this RRP's listener TLS: 1.3, and with a client CA configured a client certificate required (N23).
func (c *Config) ServerTLS() (*tls.Config, error) { return mtls.ServerTLS(c.ClientCA) }

// Guard wraps the RRP's routes: with a client CA configured, the protocol (attest-initiate and the second legs)
// answers only the callers Clients names, and PublicPaths any caller of the client CA.
func (c *Config) Guard(h http.Handler) http.Handler {
	required := c.ClientCA != ""
	protocol, public := mtls.Authorize(required, c.Clients, h), mtls.Authorize(required, nil, h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slices.Contains(PublicPaths, r.URL.Path) {
			public.ServeHTTP(w, r)
			return
		}
		protocol.ServeHTTP(w, r)
	})
}

// The RATS models an RRP may run in (Config.RATSModel).
const (
	Passport        = "passport"
	BackgroundCheck = "background-check"
)

// Gateway holds a running RRP's state.
type Gateway struct {
	Config    *Config
	Mode      string // "enroll" (Credential Authority) or "retrieve" (Secret Vault)
	Fresh     *fresh.Store
	EAR       *ear.Verifier
	Appraiser *Appraiser // Background Check: how this RRP asks a verifier itself
	Now       func() time.Time
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

// SecondLeg holds the fields both attest-enroll and attest-retrieve carry to the RRP: in Passport the Attestation
// Results, in Background Check the Evidence and its media type.
type SecondLeg struct {
	FreshnessKind  fresh.Kind `json:"freshness_kind"`
	Target         string     `json:"target"`
	CredentialType string     `json:"credential_type"`
	Handle         bundle.B64 `json:"handle,omitempty"` // the freshness element
	CredentialHint string     `json:"credential_hint,omitempty"`
	EAR            string     `json:"ear,omitempty"`      // Passport: Attestation Results from the Verifier
	Evidence       bundle.B64 `json:"evidence,omitempty"` // Background Check: the Attester's Evidence, as it sent it
	Profile        string     `json:"profile,omitempty"`  // Background Check: the Evidence's media type
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
	bindRRPID := g.Config.RRPID
	if g.Config.OmitRRPIDInBinding {
		bindRRPID = "" // #19/#20 experiment: recompute as if TACRA carried no RRP identifier
	}
	bv := platform.BindingValue(req.Handle, req.Target, bindRRPID, subject)
	jws := req.EAR
	if g.Config.RATSModel == BackgroundCheck {
		// the RRP asks the verifier itself; Attestation Results that arrive with the request are not taken
		if req.EAR != "" || len(req.Evidence) == 0 {
			return nil, nil, refuse(http.StatusBadRequest, "malformed",
				errors.New("background-check: this RRP takes the Evidence, not Attestation Results"))
		}
		if g.Appraiser == nil {
			return nil, nil, refuse(http.StatusInternalServerError, "internal", errors.New("background-check: no verifier to ask"))
		}
		if jws, err = g.Appraiser.Appraise(req.Evidence, req.Profile, bv[:], t.Verifiers); err != nil {
			return nil, nil, err
		}
	} else if len(req.Evidence) > 0 || req.EAR == "" {
		return nil, nil, refuse(http.StatusBadRequest, "malformed",
			errors.New("passport: this RRP takes Attestation Results, not Evidence"))
	}
	// only the keys of the verifiers the Target's policy takes (N24): a result another verifier signed is refused,
	// whichever verifier the conduit chose to ask
	res, err := g.EAR.Only(t.Verifiers).Verify(jws, bv[:])
	if err != nil {
		if errors.Is(err, ear.ErrSignature) {
			err = fmt.Errorf("%w: none of the verifiers this RRP takes for the Target (%s) signed it", err,
				strings.Join(t.Verifiers, ", "))
		}
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
