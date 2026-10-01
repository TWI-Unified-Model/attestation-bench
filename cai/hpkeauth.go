package cai

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TWI-Unified-Model/tacra/bundle"
	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/fxamacker/cbor/v2"
)

// freshnessElement is the value the Evidence binds as its freshness element: what a hardware plug-in reports in its
// unsigned claims (for absent-timestamp the plug-in reads its own clock), else the handle the CAI passed.
func freshnessElement(ev *platform.Evidence, handle []byte) []byte {
	if ev != nil && len(ev.Claims) > 0 {
		var claims map[string]any
		if cbor.Unmarshal(ev.Claims, &claims) == nil {
			if e, ok := claims["freshness-element"].([]byte); ok {
				return e
			}
		}
	}
	return handle
}

// containerOf names the container of a wrapped credential: bundle.ContainerSigned (hpke-base-signed),
// bundle.Container (hpke-auth), or "" for the earlier wrapping that is not a JSON container.
func containerOf(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' {
		return ""
	}
	var head struct {
		Container string `json:"container"`
	}
	if json.Unmarshal(b, &head) != nil {
		return ""
	}
	return head.Container
}

// ErrNoVaultOrigin is returned when the CAI holds no trust anchor for the Secret Vault that sealed a container.
var ErrNoVaultOrigin = errors.New("cai: no trust anchor for the Secret Vault's origin key")

// openHPKEAuth checks and opens an hpke-auth container: it must be sealed under the origin key the CAI holds for the
// RRP its Evidence bound, name that RRP, the Target, the freshness element and the hint, and decrypt with CEKpri.
// The document returned is the first credential item's value.
func (c *Client) openHPKEAuth(raw []byte, cekPriv crypto.PrivateKey, req AcquisitionRequest, element []byte) ([]byte, error) {
	var b bundle.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	origin := c.vaultOrigins[req.RelyingParty][b.Suite.KEM]
	if origin == nil {
		return nil, ErrNoVaultOrigin
	}
	var cek *ecdh.PrivateKey
	switch k := cekPriv.(type) {
	case *ecdsa.PrivateKey:
		var err error
		if cek, err = k.ECDH(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
		}
	case *ecdh.PrivateKey:
		cek = k
	default:
		return nil, fmt.Errorf("%w: CEK type %T", ErrUnwrap, cekPriv)
	}
	content, err := bundle.Open(&b, cek, bundle.Expect{RRPID: req.RelyingParty, Target: req.Target, Handle: element,
		CredentialHint: req.Hint, VaultSPKI: origin})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	if len(content.CredentialItems) == 0 {
		return nil, ErrEmptyCredential
	}
	return []byte(content.CredentialItems[0].Value), nil
}

// ErrNoVaultSigner is returned when the CAI holds no signature key for the Secret Vault that sealed a signed container.
var ErrNoVaultSigner = errors.New("cai: no trust anchor for the Secret Vault's signature key")

// SignedItemPolicy is what the CAI takes from a signed container (the bank profile; tacra-est decisions 5 and 6):
// every item with its key-block attributes and not exportable, no private key shared among instances, and a
// validity of at most 3600 s.
var SignedItemPolicy = struct {
	AcceptShared       bool
	MaxValiditySeconds int
}{false, 3600}

// openSigned checks and opens an hpke-base-signed container: it must be signed by the key the CAI holds for the RRP
// its Evidence bound, name that RRP, the Target, the freshness element and the hint, be sealed to this request's
// MLKEM768-P256 CEK, and carry only items SignedItemPolicy takes. The document returned is the first item's value.
func (c *Client) openSigned(raw []byte, cekPriv crypto.PrivateKey, req AcquisitionRequest, element []byte) ([]byte, error) {
	var b bundle.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	spki := c.vaultSigners[req.RelyingParty]
	if spki == nil {
		return nil, ErrNoVaultSigner
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	vaultKey, ok := pub.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return nil, fmt.Errorf("%w: the key held for %s is not an ECDSA public key", ErrNoVaultSigner, req.RelyingParty)
	}
	cek, ok := cekPriv.(hpke.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: a signed container needs an MLKEM768-P256 CEK, not %T", ErrUnwrap, cekPriv)
	}
	content, err := bundle.OpenSigned(&b, bundle.ExpectSigned{RRPID: req.RelyingParty, Target: req.Target, Handle: element,
		CredentialHint: req.Hint, CEK: cek, VaultKey: vaultKey})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	if err := bundle.CheckItems(content, SignedItemPolicy.AcceptShared, SignedItemPolicy.MaxValiditySeconds); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	if len(content.CredentialItems) == 0 {
		return nil, ErrEmptyCredential
	}
	return []byte(content.CredentialItems[0].Value), nil
}
