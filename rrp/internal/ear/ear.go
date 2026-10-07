// Package ear verifies, for a RATS Relying Party, the Attestation Results a Veraison verifier returns: an EAR (a JWT
// signed ES256) that must be signed by the key the RRP was given for a verifier its policy takes for the Target, be
// recent, report the binding value the RRP recomputed as its eat_nonce, and be affirming for the scheme's submodule. It also reads the launch measurement the verifier
// annotated, which the Secret Vault uses to choose a credential group.
package ear

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/jwk"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/corim/comid"
)

// Refusals, all answered 403 by the RRP.
var (
	ErrSignature    = errors.New("ear: not signed by the verifier's key")
	ErrStale        = errors.New("ear: issued too long ago or in the future")
	ErrNonce        = errors.New("ear: eat_nonce is not the binding value")
	ErrNotAffirming = errors.New("ear: not affirming")
	ErrMalformed    = errors.New("ear: malformed")
)

// mKeyMeasurement is the SEV-SNP launch MEASUREMENT in the AMD CoRIM profile.
const mKeyMeasurement = 641

// TrustedKey is a verifier's EAR signing key, as the RRP's configuration provisions it, and the submodules it may
// speak for.
type TrustedKey struct {
	Name    string // the verifier's name in the RRP's configuration, which a Target's policy names
	Key     *ecdsa.PublicKey
	Submods []string // "SEVSNP" for Veraison, "TDX" for the bench's TDX verifier
}

// Verifier holds the verifiers' EAR signing keys and the RRP's acceptance rules.
type Verifier struct {
	Keys   []TrustedKey
	MaxAge time.Duration // how old an EAR may be
	Skew   time.Duration // how far in the future its iat may be
	Now    func() time.Time
}

// Only is this Verifier with the keys of the named verifiers alone: those a Target's policy takes (N24, "the Verifier
// is chosen by the RP's configuration for the Target"). A result signed by any other key it holds is then refused.
func (v *Verifier) Only(names []string) *Verifier {
	o := *v
	o.Keys = nil
	for _, k := range v.Keys {
		if slices.Contains(names, k.Name) {
			o.Keys = append(o.Keys, k)
		}
	}
	return &o
}

// Result is what the RRP takes from a verified EAR.
type Result struct {
	Submod      string
	Status      string
	IssuedAt    time.Time
	Measurement []byte // launch measurement annotated by the verifier, if any
	Raw         string // the EAR as received, for the issuance record
	// SNP holds the SEV-SNP report fields the verifier annotated (submodule SEVSNP), or nil with SNPErr saying why;
	// TDX the bench TDX verifier's annotations (submodule TDX).
	SNP    *SNPClaims
	SNPErr error
	TDX    map[string]string
	// Waived is what the RRP's platform rule admitted these results without, one line per named waiver it applied
	// (gateway.PlatformPolicy.Check), for the RRP's record of the issuance or release.
	Waived []string
}

// KeyFromJWK parses an EC P-256 public JWK (strictly: internal/jwk).
func KeyFromJWK(b []byte) (*ecdsa.PublicKey, error) {
	pub, err := jwk.ParsePublic(b)
	if err != nil {
		return nil, fmt.Errorf("ear: %w", err)
	}
	return pub, nil
}

// LoadKey reads a verifier's EAR verification key from the file the RRP's operator provisioned: an EC P-256 public
// JWK, or a PEM public key. The RRP never fetches the key from the verifier (N24: the key is provisioned; fetched at
// start it is only as good as the channel and the verifier's answer at that moment).
func LoadKey(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if b, _ := pem.Decode(raw); b != nil {
		k, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ear: %s: %w", path, err)
		}
		pub, ok := k.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, fmt.Errorf("ear: %s is not an EC P-256 public key", path)
		}
		return pub, nil
	}
	var j struct {
		D string `json:"d"`
	}
	if json.Unmarshal(raw, &j) == nil && j.D != "" {
		return nil, fmt.Errorf("ear: %s holds a private key; the RRP is given the public key alone", path)
	}
	return KeyFromJWK(raw)
}

// Verify checks the EAR and that it reports wantNonce, and returns what the RRP needs from it.
func (v *Verifier) Verify(jws string, wantNonce []byte) (*Result, error) {
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a compact JWS", ErrMalformed)
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header", ErrMalformed)
	}
	var h struct{ Alg string }
	if json.Unmarshal(hdr, &h) != nil || h.Alg != "ES256" {
		return nil, fmt.Errorf("%w: alg %q, want ES256", ErrMalformed, h.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, fmt.Errorf("%w: signature is not 64 octets", ErrMalformed)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	var submods []string // the submodules the key that signed may speak for
	for _, k := range v.Keys {
		if ecdsa.Verify(k.Key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			submods = k.Submods
			break
		}
	}
	if submods == nil {
		return nil, ErrSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload", ErrMalformed)
	}
	var claims struct {
		Nonce   string `json:"eat_nonce"`
		IAT     int64  `json:"iat"`
		Submods map[string]struct {
			Status   string          `json:"ear.status"`
			Evidence json.RawMessage `json:"ear.veraison.annotated-evidence"`
		} `json:"submods"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims", ErrMalformed)
	}
	iat := time.Unix(claims.IAT, 0)
	if claims.IAT == 0 || iat.Before(now().Add(-v.MaxAge)) || iat.After(now().Add(v.Skew)) {
		return nil, fmt.Errorf("%w: iat %s", ErrStale, iat.UTC().Format(time.RFC3339))
	}
	nonce, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(claims.Nonce, "="))
	if err != nil || !bytes.Equal(nonce, wantNonce) {
		return nil, ErrNonce
	}
	for _, name := range submods {
		sub, ok := claims.Submods[name]
		if !ok {
			continue
		}
		if sub.Status != "affirming" {
			return nil, fmt.Errorf("%w: %s is %q", ErrNotAffirming, name, sub.Status)
		}
		res := &Result{Submod: name, Status: sub.Status, IssuedAt: iat, Raw: jws,
			Measurement: annotatedMeasurement(name, sub.Evidence)}
		switch name {
		case "SEVSNP":
			res.SNP, res.SNPErr = snpClaims(sub.Evidence)
		case "TDX":
			_ = json.Unmarshal(sub.Evidence, &res.TDX)
		}
		return res, nil
	}
	return nil, fmt.Errorf("%w: no submodule the signing verifier may speak for (%v)", ErrNotAffirming, submods)
}

// annotatedMeasurement reads the launch measurement the verifier annotated: SEV-SNP's MEASUREMENT from Veraison's
// CoMID, TDX's MRTD from the bench TDX verifier's annotation.
func annotatedMeasurement(submod string, raw json.RawMessage) []byte {
	switch submod {
	case "SEVSNP":
		var a struct {
			Tags []string `json:"tags"`
		}
		if json.Unmarshal(raw, &a) == nil && len(a.Tags) > 0 {
			return measurement(a.Tags[0])
		}
	case "TDX":
		var a struct {
			MRTD string `json:"mrtd"`
		}
		if json.Unmarshal(raw, &a) == nil {
			if m, err := hex.DecodeString(a.MRTD); err == nil && len(m) == 48 {
				return m
			}
		}
	}
	return nil
}

// measurement reads MKey 641 from the annotated CoMID (base64 of a CBOR-tagged CoMID), or nil.
func measurement(tag string) []byte {
	raw, err := base64.StdEncoding.DecodeString(tag)
	if err != nil {
		return nil
	}
	// Veraison annotates the CoMID as tag 506 around a byte string that holds the CoMID map.
	var t cbor.RawTag
	if cbor.Unmarshal(raw, &t) == nil && t.Number == 506 {
		raw = t.Content
		var wrapped []byte
		if cbor.Unmarshal(raw, &wrapped) == nil {
			raw = wrapped
		}
	}
	var c comid.Comid
	if err := c.FromCBOR(raw); err != nil || c.Triples.ReferenceValues == nil {
		return nil
	}
	for _, vt := range c.Triples.ReferenceValues.Values {
		for _, m := range vt.Measurements.Values {
			if k, err := m.Key.GetKeyUint(); err == nil && k == mKeyMeasurement && m.Val.Digests != nil && len(*m.Val.Digests) > 0 {
				return append([]byte(nil), (*m.Val.Digests)[0].HashValue...)
			}
		}
	}
	return nil
}
