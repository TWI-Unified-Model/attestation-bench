// Package bundle is the EncryptedCredentialBundle of draft-novak-lamps-tacra-est (the mandatory "hpke-auth"
// container): the Secret Vault seals a credential bundle to the Attester's CEKpub with HPKE in mode_auth (RFC 9180,
// Section 5.1.3) under its static KEM key, with the freshness element in info and the associated data
// {group_id, target, handle, credential_hint} authenticated; the Attester opens it only under the Vault key it trusts
// and only if the associated data names what its Evidence bound. No identifier of the Vault is in it since 11 October
// 2026 (rats-tacra#20): the Vault's key, which the Attester holds, is its identity.
//
// The encoding: info = len32(handle) || handle; the associated data and the plaintext are the JSON Canonicalization
// Scheme (RFC 8785) of their objects; byte strings in JSON are unpadded base64url. The DHKEM follows the key type of CEKpub: X25519 (mandatory to implement) or P-256.
package bundle

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// Container is the only container this package produces.
const Container = "hpke-auth"

// Suite names as they appear in the bundle.
const (
	KEMX25519 = "DHKEM(X25519, HKDF-SHA256)"
	KEMP256   = "DHKEM(P-256, HKDF-SHA256)"
	KDF       = "HKDF-SHA256"
	AEAD      = "AES-256-GCM"
)

// B64 is a byte string carried in JSON as unpadded base64url.
type B64 []byte

// MarshalJSON implements json.Marshaler.
func (b B64) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *B64) UnmarshalJSON(d []byte) error {
	var s string
	if err := json.Unmarshal(d, &s); err != nil {
		return err
	}
	v, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// AAD is the associated data of the bundle.
type AAD struct {
	GroupID        string `json:"group_id"`
	Target         string `json:"target"`
	Handle         B64    `json:"handle,omitempty"`
	CredentialHint string `json:"credential_hint,omitempty"`
}

// Bundle is the EncryptedCredentialBundle.
type Bundle struct {
	Container  string  `json:"container"`
	Suite      Suite   `json:"suite"`
	Enc        B64     `json:"enc"`
	Ciphertext B64     `json:"ciphertext"`
	AAD        AAD     `json:"aad"`
	SenderPub  B64     `json:"sender_pub,omitempty"` // hpke-auth: SubjectPublicKeyInfo of the Vault's KEM key
	Origin     *Origin `json:"origin,omitempty"`     // hpke-base: the Vault's origin authentication (signed.go)
}

// Suite names the HPKE algorithms.
type Suite struct {
	KEM  string `json:"kem"`
	KDF  string `json:"kdf"`
	AEAD string `json:"aead"`
}

// Origin is the Secret Vault's authentication of itself as the origin of an hpke-base container: the name of the
// signature algorithm (OriginAlg) and the signature (signed.go).
type Origin struct {
	Alg       string `json:"alg"`
	Signature B64    `json:"signature"`
}

// Item is one credential inside the bundle, with its key-block attributes: what it may be used for, with which
// algorithm and mode, whether it may leave the TEE, and whether it is a private key shared by a replicated
// service's instances.
type Item struct {
	Type       string   `json:"type"`
	Format     string   `json:"format,omitempty"`
	Value      string   `json:"value"`
	Kid        string   `json:"kid,omitempty"`
	Purpose    []string `json:"purpose,omitempty"`
	Algorithm  string   `json:"algorithm,omitempty"`
	Exportable *bool    `json:"exportable,omitempty"`
	Shared     bool     `json:"shared,omitempty"`
}

// Content is the plaintext of the bundle.
type Content struct {
	CredentialItems []Item         `json:"credential_items"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

// Info is the HPKE info parameter: the freshness element, length-prefixed.
func Info(handle []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(handle)))
	return append(b, handle...)
}

// Canonical returns the JSON Canonicalization Scheme serialization (RFC 8785) of v, for the values a bundle carries:
// object keys sorted, no insignificant space, strings escaped as Section 3.2.2.2 says, integers as they are.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&tree); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, tree); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case string:
		return writeString(buf, t)
	case json.Number:
		buf.WriteString(t.String())
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		buf.WriteString("null")
	default:
		return fmt.Errorf("bundle: cannot encode %T", v)
	}
	return nil
}

// writeString writes s as the JSON Canonicalization Scheme does (RFC 8785, Section 3.2.2.2): only the quotation mark,
// the reverse solidus and the control characters are escaped, the latter as \b \t \n \f \r or \u00xx in lowercase
// hex, and everything else, U+007F and the characters above it included, is written as it is.
func writeString(buf *bytes.Buffer, s string) error {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r < 0x20:
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
	return nil
}

// KEM key handling: CEKpub and the Vault's key are carried as SubjectPublicKeyInfo DER.

func kemFor(spki []byte) (hpke.KEM, string, []byte, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return 0, "", nil, err
	}
	switch k := pub.(type) {
	case *ecdh.PublicKey:
		if k.Curve() != ecdh.X25519() {
			return 0, "", nil, errors.New("bundle: unsupported ECDH curve")
		}
		return hpke.KEM_X25519_HKDF_SHA256, KEMX25519, k.Bytes(), nil
	case *ecdsa.PublicKey:
		e, err := k.ECDH()
		if err != nil || e.Curve() != ecdh.P256() {
			return 0, "", nil, errors.New("bundle: CEK must be X25519 or P-256")
		}
		return hpke.KEM_P256_HKDF_SHA256, KEMP256, e.Bytes(), nil
	}
	return 0, "", nil, fmt.Errorf("bundle: unsupported key type %T", pub)
}

// SenderKeys are the Vault's static KEM keys, one per DHKEM it supports.
type SenderKeys struct {
	X25519 *ecdh.PrivateKey
	P256   *ecdh.PrivateKey
}

// GenerateSenderKeys makes a new pair of static keys.
func GenerateSenderKeys() (*SenderKeys, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	p, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SenderKeys{X25519: x, P256: p}, nil
}

// PublicSPKI returns the SubjectPublicKeyInfo of the sender key used with CEKs of the given DHKEM.
func (s *SenderKeys) PublicSPKI(kemName string) ([]byte, error) {
	switch kemName {
	case KEMX25519:
		return x509.MarshalPKIXPublicKey(s.X25519.PublicKey())
	case KEMP256:
		pub, err := p256ECDSA(s.P256.PublicKey())
		if err != nil {
			return nil, err
		}
		return x509.MarshalPKIXPublicKey(pub)
	}
	return nil, fmt.Errorf("bundle: no sender key for %s", kemName)
}

func p256ECDSA(pub *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	if e, ok := k.(*ecdsa.PublicKey); ok {
		return e, nil
	}
	return nil, errors.New("bundle: P-256 key did not parse as ECDSA")
}

func (s *SenderKeys) private(kemName string, scheme kem.Scheme) (kem.PrivateKey, error) {
	var k *ecdh.PrivateKey
	switch kemName {
	case KEMX25519:
		k = s.X25519
	case KEMP256:
		k = s.P256
	}
	if k == nil {
		return nil, fmt.Errorf("bundle: no sender key for %s", kemName)
	}
	return scheme.UnmarshalBinaryPrivateKey(k.Bytes())
}

// Seal encrypts content to cekSPKI (X25519 or P-256) under the sender's static key, in mode_auth.
func Seal(sender *SenderKeys, cekSPKI []byte, aad AAD, content Content) (*Bundle, error) {
	kemID, kemName, pkRaw, err := kemFor(cekSPKI)
	if err != nil {
		return nil, err
	}
	scheme := kemID.Scheme()
	pkR, err := scheme.UnmarshalBinaryPublicKey(pkRaw)
	if err != nil {
		return nil, err
	}
	skS, err := sender.private(kemName, scheme)
	if err != nil {
		return nil, err
	}
	senderSPKI, err := sender.PublicSPKI(kemName)
	if err != nil {
		return nil, err
	}
	suite := hpke.NewSuite(kemID, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	s, err := suite.NewSender(pkR, Info(aad.Handle))
	if err != nil {
		return nil, err
	}
	enc, sealer, err := s.SetupAuth(rand.Reader, skS)
	if err != nil {
		return nil, err
	}
	aadBytes, err := Canonical(aad)
	if err != nil {
		return nil, err
	}
	pt, err := Canonical(content)
	if err != nil {
		return nil, err
	}
	ct, err := sealer.Seal(pt, aadBytes)
	if err != nil {
		return nil, err
	}
	return &Bundle{Container: Container, Suite: Suite{KEM: kemName, KDF: KDF, AEAD: AEAD}, Enc: enc, Ciphertext: ct,
		AAD: aad, SenderPub: senderSPKI}, nil
}

// Expect is what the Attester bound into its Evidence, and the Vault key it trusts.
type Expect struct {
	Target         string
	Handle         []byte
	CredentialHint string
	VaultSPKI      []byte // the Vault's KEM key for this DHKEM, provisioned as a trust anchor
}

// Refusals of Open.
var (
	ErrContainer = errors.New("bundle: not an hpke-auth container")
	ErrAAD       = errors.New("bundle: associated data does not name what the Evidence bound")
	ErrOrigin    = errors.New("bundle: not sealed by the trusted Vault key")
)

// Open checks the container against exp and decrypts it with the CEK private key (X25519 or P-256).
func Open(b *Bundle, cek *ecdh.PrivateKey, exp Expect) (*Content, error) {
	if b.Container != Container || b.Suite.KDF != KDF || b.Suite.AEAD != AEAD {
		return nil, ErrContainer
	}
	if b.AAD.Target != exp.Target || !bytes.Equal(b.AAD.Handle, exp.Handle) || b.AAD.CredentialHint != exp.CredentialHint {
		return nil, ErrAAD
	}
	var kemID hpke.KEM
	switch {
	case b.Suite.KEM == KEMX25519 && cek.Curve() == ecdh.X25519():
		kemID = hpke.KEM_X25519_HKDF_SHA256
	case b.Suite.KEM == KEMP256 && cek.Curve() == ecdh.P256():
		kemID = hpke.KEM_P256_HKDF_SHA256
	default:
		return nil, ErrContainer
	}
	_, trustedKEM, trustedRaw, err := kemFor(exp.VaultSPKI)
	if err != nil || trustedKEM != b.Suite.KEM {
		return nil, ErrOrigin
	}
	scheme := kemID.Scheme()
	pkS, err := scheme.UnmarshalBinaryPublicKey(trustedRaw)
	if err != nil {
		return nil, ErrOrigin
	}
	skR, err := scheme.UnmarshalBinaryPrivateKey(cek.Bytes())
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewSuite(kemID, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM).NewReceiver(skR, Info(exp.Handle))
	if err != nil {
		return nil, err
	}
	opener, err := r.SetupAuth(b.Enc, pkS)
	if err != nil {
		return nil, ErrOrigin
	}
	aadBytes, err := Canonical(b.AAD)
	if err != nil {
		return nil, err
	}
	pt, err := opener.Open(b.Ciphertext, aadBytes)
	if err != nil {
		return nil, ErrOrigin // mode_auth: only the holder of the trusted sender key could have produced it
	}
	var c Content
	if err := json.Unmarshal(pt, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
