package cai

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/x509"
	"encoding/base64"
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

// containerOf names the container of a wrapped credential: bundle.ContainerBase (hpke-base),
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
	content, err := bundle.Open(&b, cek, bundle.Expect{Target: req.Target, Handle: element,
		CredentialHint: req.Hint, VaultSPKI: origin})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	if len(content.CredentialItems) == 0 {
		return nil, ErrEmptyCredential
	}
	return itemOctets(content.CredentialItems[0])
}

// ErrNoVaultSigner is returned when the key the CAI holds for the Secret Vault's signatures is not an ECDSA key.
var ErrNoVaultSigner = errors.New("cai: no trust anchor for the Secret Vault's signature key")

// ItemPolicy is what the CAI takes from an hpke-base container (the bank profile; tacra-est decisions 5 and 6):
// every item with its key-block attributes and not exportable, no private key shared among instances, and a
// validity of at most 3600 s.
var ItemPolicy = struct {
	AcceptShared       bool
	MaxValiditySeconds int
}{false, 3600}

// openBase checks and opens an hpke-base container: it must name the Target, the freshness element and the hint the
// Evidence bound, be sealed to this request's CEK (MLKEM768-P256 or P-256, cekPub being CEKpub as the request carried
// it), and carry only items ItemPolicy takes. The Target's policy on origin authentication is the key the CAI holds
// for the RRP its Evidence bound: with a key, the container must carry the Secret Vault's signature under it; without
// one, the container opens as it is, which is the EST draft's accepted risk (docs/attacks.md, section 6). The document
// returned is the first item's value.
func (c *Client) openBase(raw []byte, cekPriv crypto.PrivateKey, cekPub []byte, req AcquisitionRequest, element []byte) ([]byte, error) {
	var b bundle.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	var vaultKey *ecdsa.PublicKey
	if spki := c.vaultSigners[req.RelyingParty]; spki != nil {
		pub, err := x509.ParsePKIXPublicKey(spki)
		k, ok := pub.(*ecdsa.PublicKey)
		if err != nil || !ok {
			return nil, fmt.Errorf("%w: the key held for %s is not an ECDSA public key", ErrNoVaultSigner, req.RelyingParty)
		}
		vaultKey = k
	}
	cek, ok := cekPriv.(hpke.PrivateKey)
	if !ok {
		var err error
		if cek, err = bundle.DHKEMPrivateKey(cekPriv); err != nil {
			return nil, fmt.Errorf("%w: an hpke-base container needs an MLKEM768-P256 or a P-256 CEK: %v", ErrUnwrap, err)
		}
	}
	content, err := bundle.OpenBase(&b, bundle.ExpectBase{Target: req.Target, Handle: element,
		CredentialHint: req.Hint, CEK: cek, CEKPub: cekPub, VaultKey: vaultKey, RequireOrigin: vaultKey != nil})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	if err := bundle.CheckItems(content, ItemPolicy.AcceptShared, ItemPolicy.MaxValiditySeconds); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	if len(content.CredentialItems) == 0 {
		return nil, ErrEmptyCredential
	}
	return itemOctets(content.CredentialItems[0])
}

// itemOctets is the credential an item carries: its value is the unpadded base64url of the credential's octets, a DER
// certificate, a DER PrivateKeyInfo, the key octets or the UTF-8 of a token (the EST draft, Response:
// EncryptedCredentialBundle, 30 October 2026).
func itemOctets(it bundle.Item) ([]byte, error) {
	octets, err := base64.RawURLEncoding.DecodeString(it.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: the item's value is not unpadded base64url: %v", ErrUnwrap, err)
	}
	return octets, nil
}
