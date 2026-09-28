// Package ear verifies, for a RATS Relying Party, the Attestation Results a Veraison verifier returns: an EAR (a JWT
// signed ES256) that must be signed by the verifier's key, be recent, report the binding value the RRP recomputed as
// its eat_nonce, and be affirming for the scheme's submodule. It also reads the launch measurement the verifier
// annotated, which the Secret Vault uses to choose a credential group.
package ear

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

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

// TrustedKey is a verifier's EAR signing key and the submodules it may speak for.
type TrustedKey struct {
	Key     *ecdsa.PublicKey
	Submods []string // e.g. "SEVSNP" for Veraison, "TDX" for the bench's TDX verifier
}

// Verifier holds the verifiers' EAR signing keys and the RRP's acceptance rules.
type Verifier struct {
	Keys   []TrustedKey
	MaxAge time.Duration // how old an EAR may be
	Skew   time.Duration // how far in the future its iat may be
	Now    func() time.Time
}

// Result is what the RRP takes from a verified EAR.
type Result struct {
	Submod      string
	Status      string
	IssuedAt    time.Time
	Measurement []byte // launch measurement annotated by the verifier, if any
	Raw         string // the EAR as received, for the issuance record
}

// KeyFromJWK parses an EC P-256 public JWK.
func KeyFromJWK(b []byte) (*ecdsa.PublicKey, error) {
	var k struct{ Kty, Crv, X, Y string }
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, err
	}
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("ear: key %s/%s, want EC/P-256", k.Kty, k.Crv)
	}
	x, err1 := base64.RawURLEncoding.DecodeString(k.X)
	y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
	if err1 != nil || err2 != nil {
		return nil, errors.New("ear: key coordinates are not base64url")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("ear: key is not on P-256")
	}
	return pub, nil
}

// FetchVeraisonKey reads the EAR verification key a Veraison verification service publishes, over TLS trusting caPath.
func FetchVeraisonKey(baseURL, caPath string) (*ecdsa.PublicKey, error) {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("ear: no CA certificate in " + caPath)
	}
	c := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	resp, err := c.Get(strings.TrimRight(baseURL, "/") + "/.well-known/veraison/verification")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var wk struct {
		Key json.RawMessage `json:"ear-verification-key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wk); err != nil {
		return nil, err
	}
	return KeyFromJWK(wk.Key)
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
		return &Result{Submod: name, Status: sub.Status, IssuedAt: iat, Raw: jws,
			Measurement: annotatedMeasurement(name, sub.Evidence)}, nil
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
