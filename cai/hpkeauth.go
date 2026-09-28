package cai

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
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

// isHPKEAuth reports whether a wrapped credential is the hpke-auth container of the revised EST profile.
func isHPKEAuth(b []byte) bool {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' {
		return false
	}
	var head struct {
		Container string `json:"container"`
	}
	return json.Unmarshal(b, &head) == nil && head.Container == bundle.Container
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
