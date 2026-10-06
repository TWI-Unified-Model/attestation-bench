// Package jwk reads and writes the EC P-256 keys of the RRPs and the bench's verifiers as JSON Web Keys (RFC 7517,
// RFC 7518 section 6.2), strictly: each coordinate and the private scalar are exactly 32 octets of base64url (RFC 7518
// requires the full length), the point is on P-256, and a private key's x and y are its own public key.
package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Key is an EC P-256 JWK. Alg and Kid are kept when present; D is set for a private key only.
type Key struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d,omitempty"`
}

var b64 = base64.RawURLEncoding

// Parse decodes a JWK. Its Public and Private methods check it.
func Parse(raw []byte) (Key, error) {
	var k Key
	if err := json.Unmarshal(raw, &k); err != nil {
		return Key{}, fmt.Errorf("jwk: %w", err)
	}
	return k, nil
}

// ParsePublic returns the public key of an EC P-256 JWK. A private JWK's d is not read.
func ParsePublic(raw []byte) (*ecdsa.PublicKey, error) {
	k, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return k.Public()
}

// ParsePrivate returns the private key of an EC P-256 private JWK, and the JWK itself (for its kid).
func ParsePrivate(raw []byte) (*ecdsa.PrivateKey, Key, error) {
	k, err := Parse(raw)
	if err != nil {
		return nil, Key{}, err
	}
	priv, err := k.Private()
	return priv, k, err
}

// Public is the key's public half.
func (k Key) Public() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("jwk: key %s/%s, want EC/P-256", k.Kty, k.Crv)
	}
	x, errX := b64.DecodeString(k.X)
	y, errY := b64.DecodeString(k.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("jwk: x and y must each be 32 octets of base64url")
	}
	point := append(append([]byte{4}, x...), y...) // SEC 1 uncompressed point
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("jwk: x and y are not a point on P-256: %w", err)
	}
	return pub, nil
}

// Private is the private key, which must match the key's x and y.
func (k Key) Private() (*ecdsa.PrivateKey, error) {
	pub, err := k.Public()
	if err != nil {
		return nil, err
	}
	d, err := b64.DecodeString(k.D)
	if err != nil || len(d) != 32 {
		return nil, errors.New("jwk: d must be 32 octets of base64url")
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return nil, fmt.Errorf("jwk: d: %w", err)
	}
	if !priv.PublicKey.Equal(pub) {
		return nil, errors.New("jwk: x and y are not the public key of d")
	}
	return priv, nil
}

// FromPublic encodes a P-256 public key as a JWK.
func FromPublic(pub *ecdsa.PublicKey) (Key, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return Key{}, errors.New("jwk: want a P-256 public key")
	}
	point, err := pub.Bytes() // 0x04 || x || y, 32 octets each
	if err != nil {
		return Key{}, fmt.Errorf("jwk: %w", err)
	}
	return Key{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(point[1:33]), Y: b64.EncodeToString(point[33:])}, nil
}

// FromPrivate encodes a P-256 private key as a JWK.
func FromPrivate(priv *ecdsa.PrivateKey) (Key, error) {
	if priv == nil {
		return Key{}, errors.New("jwk: want a P-256 private key")
	}
	k, err := FromPublic(&priv.PublicKey)
	if err != nil {
		return Key{}, err
	}
	d, err := priv.Bytes()
	if err != nil {
		return Key{}, fmt.Errorf("jwk: %w", err)
	}
	k.D = b64.EncodeToString(d)
	return k, nil
}
