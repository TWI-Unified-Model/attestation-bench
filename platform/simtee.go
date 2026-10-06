package platform

// SimTEE is the test bench's software stand-in for a confidential-computing platform, for runs on a laptop with no
// TEE. IT PROVIDES NO ISOLATION AND NO SECURITY: its "attestation key" is an ordinary file, and anyone who holds it
// can produce any report. Its only purpose is to let the protocol around the TEE run unchanged.
//
// It is built so that everything the protocol does is the code the hardware back-ends run: SimTEE embeds the same
// tsmConfig as SEVSNP and TDX (CEK and CSK generation, the local epoch, FreshnessElement), binds the report with the
// same BindingValue(freshness element, Target, RelyingParty, Subject(req)), and encodes Evidence with the same
// tsmEvidence, as a Veraison TSM report. Only the report differs: a COSE_Sign1 (ES256) over SimReport, signed with
// the key the operator gives it, under the TSM provider "sim_guest". A Verifier for it (the bench's sim-verifier)
// is configured with that key's public half, and an RRP accepts its results only when its configuration says so
// explicitly (gateway option allow_simulated_tee).
//
// The group's Simulated plug-in (sim.go) is a different thing: it puts the Freshness Handle itself in its EAT nonce,
// without the Target or the RRP identifier.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const (
	// SimProvider is the TSM provider name of SimTEE Evidence: the Verifier is chosen by it, as for sev_guest and
	// tdx_guest.
	SimProvider = "sim_guest"
	// SimReportContentType is the COSE content type of a SimReport.
	SimReportContentType = "application/vnd.attestation-bench.sim-report+cbor"
	// SimMeasurementSize is the size of a SimTEE launch measurement, SHA-384 as for SEV-SNP and TDX.
	SimMeasurementSize = 48
	// SimInstanceIDSize is the size of a SimTEE instance identifier (a stand-in for a machine's identity).
	SimInstanceIDSize = 16
)

// SimReport is what a SimTEE signs.
type SimReport struct {
	// ReportData is BindingValue(freshness element, Target, RelyingParty, subject), as REPORT_DATA and REPORTDATA.
	ReportData []byte `cbor:"report_data"`
	// Measurement is the launch measurement the instance was configured with.
	Measurement []byte `cbor:"measurement"`
	// InstanceID names this instance; it is random per SimTEE.
	InstanceID []byte `cbor:"instance_id"`
	// Debug says the instance is debuggable, so its report must not be trusted (a Verifier refuses it).
	Debug bool `cbor:"debug"`
}

// SimTEEConfig is what a SimTEE is given.
type SimTEEConfig struct {
	Key         *ecdsa.PrivateKey // the stand-in attestation key, P-256
	Measurement []byte            // 48 octets
	Debug       bool              // report a debuggable instance (for the bench's refusal scenarios)
}

// SimTEE is the software stand-in back-end; see the file comment.
type SimTEE struct {
	tsmConfig
	key         *ecdsa.PrivateKey
	measurement []byte
	instance    []byte
	debug       bool
}

// ErrSimReport is wrapped by every refusal of ParseSimReport.
var ErrSimReport = errors.New("platform: not a valid SimTEE report")

// simEncMode encodes SimReport deterministically (RFC 8949 core deterministic encoding).
var simEncMode, _ = cbor.CoreDetEncOptions().EncMode()

// NewSimTEE returns the software stand-in back-end. TSMOption values set the clock and the local epoch, as for the
// hardware back-ends; it has no configfs-tsm client.
func NewSimTEE(cfg SimTEEConfig, opts ...TSMOption) (*SimTEE, error) {
	if cfg.Key == nil || cfg.Key.Curve != elliptic.P256() {
		return nil, errors.New("platform: SimTEE needs a P-256 attestation key")
	}
	if len(cfg.Measurement) != SimMeasurementSize {
		return nil, fmt.Errorf("platform: SimTEE measurement is %d octets, want %d", len(cfg.Measurement), SimMeasurementSize)
	}
	c := tsmConfig{clock: time.Now}
	for _, o := range opts {
		o(&c)
	}
	instance := make([]byte, SimInstanceIDSize)
	if _, err := rand.Read(instance); err != nil {
		return nil, err
	}
	return &SimTEE{tsmConfig: c, key: cfg.Key, measurement: append([]byte(nil), cfg.Measurement...), instance: instance,
		debug: cfg.Debug}, nil
}

// Name implements Plugin.
func (p *SimTEE) Name() string {
	return "sim"
}

// AttestationPublicKey implements Plugin.
func (p *SimTEE) AttestationPublicKey() *ecdsa.PublicKey {
	return &p.key.PublicKey
}

// GenerateEvidence implements Plugin, exactly as the hardware back-ends do up to the report itself.
func (p *SimTEE) GenerateEvidence(req EvidenceRequest) (*Evidence, error) {
	elem, err := p.FreshnessElement(req)
	if err != nil {
		return nil, err
	}
	subject, err := Subject(req)
	if err != nil {
		return nil, err
	}
	bv := BindingValue(elem, req.Target, req.RelyingParty, subject)
	payload, err := simEncMode.Marshal(SimReport{ReportData: bv[:], Measurement: p.measurement, InstanceID: p.instance,
		Debug: p.debug})
	if err != nil {
		return nil, fmt.Errorf("platform: SimTEE report: %w", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, p.key)
	if err != nil {
		return nil, fmt.Errorf("platform: SimTEE signer: %w", err)
	}
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
			cose.HeaderLabelContentType: SimReportContentType,
		},
		Unprotected: cose.UnprotectedHeader{cose.HeaderLabelKeyID: kidFromPublic(&p.key.PublicKey)},
	}
	signed, err := cose.Sign1(rand.Reader, signer, headers, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("platform: SimTEE COSE_Sign1: %w", err)
	}
	return tsmEvidence(req, elem, bv, tsmReport{OutBlob: signed, Provider: SimProvider}, map[string]any{"simulated": true})
}

// ParseSimReport verifies a SimTEE report (a TSM report's outblob) against the trusted attestation keys and returns
// what it reports. It checks the signature, the content type and the field sizes; the caller compares ReportData
// with the binding value and applies its own rules to the rest.
func ParseSimReport(outblob []byte, trusted []*ecdsa.PublicKey) (*SimReport, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(outblob); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSimReport, err)
	}
	if ct, _ := msg.Headers.Protected[cose.HeaderLabelContentType].(string); ct != SimReportContentType {
		return nil, fmt.Errorf("%w: content type %q", ErrSimReport, ct)
	}
	verified := false
	for _, k := range trusted {
		v, err := cose.NewVerifier(cose.AlgorithmES256, k)
		if err != nil {
			continue
		}
		if msg.Verify(nil, v) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("%w: not signed by a trusted attestation key", ErrSimReport)
	}
	var r SimReport
	if err := cbor.Unmarshal(msg.Payload, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSimReport, err)
	}
	if len(r.ReportData) != sha512.Size || len(r.Measurement) != SimMeasurementSize || len(r.InstanceID) != SimInstanceIDSize {
		return nil, fmt.Errorf("%w: field sizes %d/%d/%d", ErrSimReport, len(r.ReportData), len(r.Measurement), len(r.InstanceID))
	}
	return &r, nil
}

// SimMeasurement is the launch measurement the bench gives a SimTEE for a workload label: SHA-384 of the label.
func SimMeasurement(label string) []byte {
	m := sha512.Sum384([]byte(label))
	return m[:]
}

// simJWK is an EC P-256 key as a JWK (d only in a private key).
type simJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d,omitempty"`
}

// LoadSimKey reads a SimTEE attestation key: an EC P-256 private JWK.
func LoadSimKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var j simJWK
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("platform: %s: %w", path, err)
	}
	pub, err := simPublic(j)
	if err != nil {
		return nil, fmt.Errorf("platform: %s: %w", path, err)
	}
	d, err := base64.RawURLEncoding.DecodeString(j.D)
	if err != nil || len(d) != 32 {
		return nil, fmt.Errorf("platform: %s holds no private P-256 key (d: 32 octets of base64url)", path)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return nil, fmt.Errorf("platform: %s: %w", path, err)
	}
	if !priv.PublicKey.Equal(pub) {
		return nil, fmt.Errorf("platform: %s: x and y are not the public key of d", path)
	}
	return priv, nil
}

// ParseSimPublicJWK parses a SimTEE attestation key's public half, as a Verifier is given it.
func ParseSimPublicJWK(raw []byte) (*ecdsa.PublicKey, error) {
	var j simJWK
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, err
	}
	if j.D != "" {
		return nil, errors.New("platform: a Verifier is given the public key alone")
	}
	return simPublic(j)
}

// SimPublicJWK encodes a public key as the JWK ParseSimPublicJWK reads.
func SimPublicJWK(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, errors.New("platform: want a P-256 public key")
	}
	point, err := pub.Bytes() // 0x04 || x || y, 32 octets each
	if err != nil {
		return nil, fmt.Errorf("platform: %w", err)
	}
	enc := base64.RawURLEncoding
	return json.Marshal(simJWK{Kty: "EC", Crv: "P-256", X: enc.EncodeToString(point[1:33]), Y: enc.EncodeToString(point[33:])})
}

func simPublic(j simJWK) (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, fmt.Errorf("key %s/%s, want EC/P-256", j.Kty, j.Crv)
	}
	x, err1 := base64.RawURLEncoding.DecodeString(j.X)
	y, err2 := base64.RawURLEncoding.DecodeString(j.Y)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("key coordinates are not 32 octets of base64url each")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, fmt.Errorf("key is not a P-256 point: %w", err)
	}
	return pub, nil
}
