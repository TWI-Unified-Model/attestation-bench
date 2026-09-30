package cai

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/veraison/eat"
	"google.golang.org/grpc"
)

// CredentialType, Mode, FreshnessKind, SigningAlgorithm, and
// EncryptionAlgorithm are the CAAPI enums, re-exported so the Attester
// can depend on cai alone.
type (
	CredentialType      = caapiv1.CredentialType
	Mode                = caapiv1.CredentialAcquisitionMode
	FreshnessKind       = caapiv1.FreshnessKind
	SigningAlgorithm    = caapiv1.SigningAlgorithm
	EncryptionAlgorithm = caapiv1.EncryptionAlgorithm
)

const (
	CredentialTypeUnspecified CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_UNSPECIFIED
	CredentialTypeJWT         CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_JWT
	CredentialTypePSK         CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_PSK
	CredentialTypeAPIKey      CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_API_KEY
	CredentialTypeX509        CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_X509
	CredentialTypeWIC         CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_WIC
	CredentialTypeWIT         CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_WIT

	ModeUnspecified Mode = caapiv1.CredentialAcquisitionMode_ACQUISITION_UNSPECIFIED
	ModeEnroll      Mode = caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL
	ModeRetrieve    Mode = caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE

	FreshnessUnspecified     FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_UNSPECIFIED
	FreshnessAbsentNone      FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_NONE
	FreshnessAbsentTimestamp FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_TIMESTAMP
	FreshnessAbsentEpoch     FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_EPOCH
	FreshnessPresentNonce    FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE
	FreshnessPresentEpoch    FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_EPOCH

	SigningAlgorithmUnspecified SigningAlgorithm = caapiv1.SigningAlgorithm_SIGNING_ALGORITHM_UNSPECIFIED
	SigningAlgorithmECDSAP256   SigningAlgorithm = caapiv1.SigningAlgorithm_SIGNING_ALGORITHM_ECDSA_P256
	SigningAlgorithmRSA2048     SigningAlgorithm = caapiv1.SigningAlgorithm_SIGNING_ALGORITHM_RSA_2048

	EncryptionAlgorithmUnspecified EncryptionAlgorithm = caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_UNSPECIFIED
	EncryptionAlgorithmECDHP256    EncryptionAlgorithm = caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_ECDH_P256
	EncryptionAlgorithmRSA2048     EncryptionAlgorithm = caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_RSA_2048
)

// Credential is the document returned to the Attester.
type Credential struct {
	Type CredentialType
	// Document is the credential bytes (certificate, JWT, API key, …).
	Document []byte
	// PrivateKey is the CSK for Enrollment of proof-of-possession
	// credentials. Nil for Retrieval. *ecdsa.PrivateKey or
	// *rsa.PrivateKey (both are crypto.Signer). The algorithm is a
	// property of the key, not a sibling field.
	PrivateKey crypto.Signer
}

// AcquisitionRequest is the CAS-chosen context for one enroll or retrieve
// exchange. Further fields (cipher suites, etc.) will be added here.
type AcquisitionRequest struct {
	Target              string
	Type                CredentialType
	Hint                string
	Kind                FreshnessKind
	Handle              []byte
	SigningAlgorithm    SigningAlgorithm
	EncryptionAlgorithm EncryptionAlgorithm
	// RelyingParty is the RRP identifier the Evidence binds: the one the CAI
	// holds for the Target and mode (TACRA Section 4.5: "The Credential
	// Acquisition Interface holds this identifier in its configuration for each
	// Target and Credential Acquisition Mode; it does not take it from the CAS").
	RelyingParty string
}

// Client is the CAI implementation: one AcquireCredential call that drives
// CAAPI and the platform plug-in.
type Client struct {
	plugin platform.Plugin
	caapi  caapiv1.CredentialAcquisitionServiceClient

	// relyingParties holds, per Target and mode, the identifier of the RRP
	// the deployment intends; Evidence binds it, and nothing else.
	relyingParties map[rpKey]string
	// vaultOrigins holds, per RRP identifier and DHKEM, the Secret Vault's
	// static KEM key (SubjectPublicKeyInfo DER) the hpke-auth container must
	// be sealed with.
	vaultOrigins map[string]map[string][]byte
	// csrNamesHint makes the CSR name the Credential Hint instead of the
	// Target, leaving the certificate's names to the CA's policy.
	csrNamesHint bool
}

// WithCSRNamingHint makes the CSR carry only the Credential Hint as its
// common name, for a Credential Authority that assigns the certificate's
// names by policy (the test bench's CA gateway does).
func WithCSRNamingHint() Option { return func(c *Client) { c.csrNamesHint = true } }

// Option configures a Client.
type Option func(*Client)

type rpKey struct {
	target string
	mode   Mode
}

// WithRelyingParty makes the CAI bind rrpID for target when the CAS selects
// mode: the Credential Authority's identifier for Enrollment, the Secret
// Vault's for Retrieval. Whatever the Initiate response names is not used, and
// a Target and mode for which none is held get no Evidence.
func WithRelyingParty(target string, mode Mode, rrpID string) Option {
	return func(c *Client) { c.relyingParties[rpKey{target, mode}] = rrpID }
}

// RelyingParties turns a configuration of the form Target -> mode ("enroll" or "retrieve") -> RRP identifier
// into the options that hold those identifiers.
func RelyingParties(cfg map[string]map[string]string) ([]Option, error) {
	var opts []Option
	for target, byMode := range cfg {
		for name, rrpID := range byMode {
			var mode Mode
			switch name {
			case "enroll":
				mode = ModeEnroll
			case "retrieve":
				mode = ModeRetrieve
			default:
				return nil, fmt.Errorf("cai: relying party for %s: mode %q is neither enroll nor retrieve", target, name)
			}
			if target == "" || rrpID == "" {
				return nil, fmt.Errorf("cai: relying party: empty Target or identifier (%q, %q)", target, rrpID)
			}
			opts = append(opts, WithRelyingParty(target, mode, rrpID))
		}
	}
	return opts, nil
}

// WithVaultOrigin provisions the Secret Vault's origin key for rrpID and the
// named DHKEM (for example "DHKEM(X25519, HKDF-SHA256)").
func WithVaultOrigin(rrpID, kem string, spki []byte) Option {
	return func(c *Client) {
		if c.vaultOrigins[rrpID] == nil {
			c.vaultOrigins[rrpID] = map[string][]byte{}
		}
		c.vaultOrigins[rrpID][kem] = append([]byte(nil), spki...)
	}
}

// New constructs a CAI client. plugin must run in the Attester TEE; caapi is
// the CAAPI gRPC client (CAS Client side).
func New(plugin platform.Plugin, caapi caapiv1.CredentialAcquisitionServiceClient, opts ...Option) (*Client, error) {
	if plugin == nil {
		return nil, ErrNilPlugin
	}
	if caapi == nil {
		return nil, ErrNilCAAPI
	}
	c := &Client{plugin: plugin, caapi: caapi, relyingParties: map[rpKey]string{},
		vaultOrigins: map[string]map[string][]byte{}}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Dial opens a gRPC connection to addr and returns a CAI client. The caller
// closes conn. opts must include transport credentials.
func Dial(addr string, plugin platform.Plugin, opts ...grpc.DialOption) (*Client, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("cai: dial %s: %w", addr, err)
	}
	c, err := New(plugin, caapiv1.NewCredentialAcquisitionServiceClient(conn))
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return c, conn, nil
}

// AcquireCredential obtains a credential for target of the requested type.
// The CAS selects Enrollment or Retrieval; the Attester does not.
func (c *Client) AcquireCredential(ctx context.Context, target string, credType CredentialType, credHint string) (*Credential, error) {
	if c == nil {
		return nil, ErrNilClient
	}
	if target == "" {
		return nil, ErrInvalidTarget
	}
	if credType == CredentialTypeUnspecified {
		return nil, ErrInvalidCredentialType
	}

	initResp, err := c.caapi.InitiateRemoteAttestation(ctx, &caapiv1.InitiateCredentialAcquistionRequest{
		Target:         target,
		CredentialType: credType,
	})
	if err != nil {
		return nil, rpcError("InitiateRemoteAttestation", err)
	}

	handle, err := c.freshnessHandle(initResp)
	if err != nil {
		return nil, err
	}

	req := AcquisitionRequest{
		Target:              target,
		Type:                credType,
		Hint:                credHint,
		Kind:                initResp.GetFreshnessKind(),
		Handle:              handle,
		SigningAlgorithm:    initResp.GetSigningAlgorithm(),
		EncryptionAlgorithm: initResp.GetEncryptionAlgorithm(),
	}
	switch initResp.GetMode() {
	case ModeRetrieve:
		if req.SigningAlgorithm != SigningAlgorithmUnspecified {
			return nil, fmt.Errorf("%w: %s", ErrUnexpectedSigningAlgorithm, req.SigningAlgorithm)
		}
		if req.EncryptionAlgorithm == EncryptionAlgorithmUnspecified {
			return nil, ErrMissingEncryptionAlgorithm
		}
		if req.RelyingParty, err = c.heldRelyingParty(target, ModeRetrieve); err != nil {
			return nil, err
		}
		return c.retrieve(ctx, req)
	case ModeEnroll:
		if req.EncryptionAlgorithm != EncryptionAlgorithmUnspecified {
			return nil, fmt.Errorf("%w: %s", ErrUnexpectedEncryptionAlgorithm, req.EncryptionAlgorithm)
		}
		if req.SigningAlgorithm == SigningAlgorithmUnspecified {
			return nil, ErrMissingSigningAlgorithm
		}
		if req.RelyingParty, err = c.heldRelyingParty(target, ModeEnroll); err != nil {
			return nil, err
		}
		return c.enroll(ctx, req)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMode, initResp.GetMode())
	}
}

// heldRelyingParty is the identifier the CAI holds for target and mode; the Initiate response's is never used.
func (c *Client) heldRelyingParty(target string, mode Mode) (string, error) {
	held, ok := c.relyingParties[rpKey{target, mode}]
	if !ok || held == "" {
		return "", fmt.Errorf("%w: %s, %s", ErrNoRelyingParty, target, mode)
	}
	return held, nil
}

func (c *Client) retrieve(ctx context.Context, req AcquisitionRequest) (*Credential, error) {
	cek, err := c.plugin.GenerateCEK(platform.EncryptionAlgorithm(req.EncryptionAlgorithm))
	if err != nil {
		return nil, fmt.Errorf("cai: generate CEK: %w", err)
	}
	ev, err := c.plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKind(req.Kind),
		FreshnessHandle: req.Handle,
		BoundKey:        cek.Public(),
		BoundKeyUse:     platform.BoundKeyUseEncrypt,
		Target:          req.Target,
		RelyingParty:    req.RelyingParty,
	})
	if err != nil {
		return nil, fmt.Errorf("cai: generate evidence: %w", err)
	}
	cekPub, err := x509.MarshalPKIXPublicKey(cek.Public())
	if err != nil {
		return nil, fmt.Errorf("cai: CEKpub: %w", err)
	}
	element := freshnessElement(ev, req.Handle)
	resp, err := c.caapi.RetrieveCredential(ctx, &caapiv1.RetrieveCredentialRequest{
		Target:              req.Target,
		CredentialType:      req.Type,
		CredentialHint:      optionalHint(req.Hint),
		Evidence:            ev.Token,
		EncryptionAlgorithm: new(req.EncryptionAlgorithm),
		FreshnessKind:       req.Kind,
		FreshnessElement:    element,
		EvidenceProfile:     optionalHint(ev.MediaType),
		CekPub:              cekPub,
	})
	if err != nil {
		return nil, rpcError("RetrieveCredential", err)
	}
	if len(resp.GetWrappedCredential()) == 0 {
		return nil, ErrEmptyCredential
	}
	var doc []byte
	if isHPKEAuth(resp.GetWrappedCredential()) {
		doc, err = c.openHPKEAuth(resp.GetWrappedCredential(), cek.Private, req, element)
	} else {
		doc, err = UnwrapCredential(cek.Private, resp.GetWrappedCredential())
	}
	if err != nil {
		return nil, err
	}
	return &Credential{
		Type:     req.Type,
		Document: doc,
	}, nil
}

func (c *Client) enroll(ctx context.Context, req AcquisitionRequest) (*Credential, error) {
	csk, err := c.plugin.GenerateCSK(platform.SigningAlgorithm(req.SigningAlgorithm))
	if err != nil {
		return nil, fmt.Errorf("cai: generate CSK: %w", err)
	}
	signer, err := csk.Signer()
	if err != nil {
		return nil, fmt.Errorf("cai: CSK: %w", err)
	}
	name := ""
	if c.csrNamesHint {
		name = req.Hint
	}
	csr, err := createCSR(csk, req.Target, name)
	if err != nil {
		return nil, err
	}
	ev, err := c.plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKind(req.Kind),
		FreshnessHandle: req.Handle,
		BoundKey:        csk.Public(),
		CSR:             csr,
		BoundKeyUse:     platform.BoundKeyUseSign,
		Target:          req.Target,
		RelyingParty:    req.RelyingParty,
	})
	if err != nil {
		return nil, fmt.Errorf("cai: generate evidence: %w", err)
	}
	resp, err := c.caapi.EnrollCredential(ctx, &caapiv1.EnrollCredentialRequest{
		Target:           req.Target,
		CredentialType:   req.Type,
		CredentialHint:   optionalHint(req.Hint),
		Evidence:         ev.Token,
		Csr:              csr,
		SigningAlgorithm: new(req.SigningAlgorithm),
		FreshnessKind:    req.Kind,
		FreshnessElement: freshnessElement(ev, req.Handle),
		EvidenceProfile:  optionalHint(ev.MediaType),
	})
	if err != nil {
		return nil, rpcError("EnrollCredential", err)
	}
	if len(resp.GetPlaintextCredential()) == 0 {
		return nil, ErrEmptyCredential
	}
	return &Credential{
		Type:       req.Type,
		Document:   resp.GetPlaintextCredential(),
		PrivateKey: signer,
	}, nil
}

func optionalHint(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// freshnessHandle applies draft-novak-rats-tacra Freshness Kind rules.
// present-* kinds require a Handle that is embedded in Evidence.
// absent-* kinds return no Handle: absent-none and absent-timestamp omit
// eat_nonce (iat is the timestamp); absent-epoch uses a locally held epoch.
func (c *Client) freshnessHandle(resp *caapiv1.InitiateCredentialAcquisitionResponse) ([]byte, error) {
	kind := resp.GetFreshnessKind()
	handle := resp.GetFreshnessHandle()
	switch kind {
	case FreshnessPresentNonce, FreshnessPresentEpoch:
		if err := validatePresentHandle(handle); err != nil {
			return nil, err
		}
		return handle, nil
	case FreshnessAbsentNone, FreshnessAbsentTimestamp:
		if len(handle) != 0 {
			return nil, fmt.Errorf("%w: %s", ErrUnexpectedFreshnessHandle, kind)
		}
		return nil, nil
	case FreshnessAbsentEpoch:
		if len(handle) != 0 {
			return nil, fmt.Errorf("%w: %s", ErrUnexpectedFreshnessHandle, kind)
		}
		epoch := c.plugin.LocalEpoch()
		if len(epoch) == 0 {
			return nil, ErrNoLocalEpoch
		}
		if err := validatePresentHandle(epoch); err != nil {
			return nil, err
		}
		return epoch, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedFreshnessKind, kind)
	}
}

func validatePresentHandle(h []byte) error {
	n := len(h)
	if n < eat.MinNonceSize || n > eat.MaxNonceSize {
		return fmt.Errorf("%w: got %d", ErrInvalidFreshnessHandle, n)
	}
	return nil
}
