package bundle

// The hpke-base-signed container of the revised profile (tacra-est impl/bundle.py): HPKE base mode with
// MLKEM768-P256 (0x0050), HKDF-SHA256 and AES-256-GCM, from the standard crypto/hpke, and the Secret Vault's ECDSA
// P-256 signature over the sealed bundle. HPKE's replacement for RFC 9180 (draft-ietf-hpke-hpke-05) removes the Auth
// modes, and the post-quantum KEMs have no AuthEncap (draft-ietf-hpke-pq-05, Section 7.2), so the origin of the
// bundle is the Vault's signature, under a key the CAI holds for the Target and Retrieval. One suite, not negotiated.
//
//	info          len32-prefixed: "tacra-est bundle v1", the Target, the freshness element
//	aad           Canonical({group_id, target, handle?, credential_hint?})
//	to be signed  len32-prefixed: "tacra-est bundle signature v1", the HPKE suite_id, "ecdsa-p256-sha256",
//	              CEKpub, info, aad, enc, ciphertext
//
// CEKpub is the 1249-octet MLKEM768-P256 encapsulation key, the subject of the binding input for Retrieval.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// ContainerSigned is the container of the revised profile.
const ContainerSigned = "hpke-base-signed"

// SuiteSigned is the one suite of ContainerSigned.
var SuiteSigned = Suite{KEM: "MLKEM768-P256", KDF: "HKDF-SHA256", AEAD: "AES-256-GCM", Sig: "ECDSA-P256-SHA256"}

// AcceptableSigned is how attest-initiate names ContainerSigned's suite among the acceptable CEKs, as the reference
// implementation does (tacra-est impl/bundle.py ACCEPTABLE_CEK).
const AcceptableSigned = "MLKEM768-P256+HKDF-SHA256+AES-256-GCM"

// IsSignedCEK reports whether cekPub is an MLKEM768-P256 encapsulation key, the CEKpub of ContainerSigned.
func IsSignedCEK(cekPub []byte) bool {
	kem, _, _ := suiteParts()
	_, err := kem.NewPublicKey(cekPub)
	return err == nil
}

const (
	infoLabel = "tacra-est bundle v1"
	sigLabel  = "tacra-est bundle signature v1"
	sigAlg    = "ecdsa-p256-sha256"
)

// suiteID is the HPKE suite_id of RFC 9180 Section 5.1: "HPKE" || kem_id || kdf_id || aead_id.
var suiteID = []byte{'H', 'P', 'K', 'E', 0x00, 0x50, 0x00, 0x01, 0x00, 0x02}

func lp(b []byte, parts ...[]byte) []byte {
	for _, p := range parts {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p)))
		b = append(b, p...)
	}
	return b
}

// InfoSigned is the HPKE info of ContainerSigned.
func InfoSigned(target string, freshness []byte) []byte {
	return lp(nil, []byte(infoLabel), []byte(target), freshness)
}

// ToBeSigned is what the Vault signs.
func ToBeSigned(cekPub, info, aad, enc, ct []byte) []byte {
	return lp(nil, []byte(sigLabel), suiteID, []byte(sigAlg), cekPub, info, aad, enc, ct)
}

func suiteParts() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.MLKEM768P256(), hpke.HKDFSHA256(), hpke.AES256GCM()
}

// GenerateCEK makes a fresh MLKEM768-P256 key pair for one request: the private key, and CEKpub as it is bound.
func GenerateCEK() (hpke.PrivateKey, []byte, error) {
	kem, _, _ := suiteParts()
	sk, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return sk, sk.PublicKey().Bytes(), nil
}

// SealSigned seals content to cekPub in base mode and signs the result with the Vault's key. The freshness element
// is aad.Handle.
func SealSigned(signKey *ecdsa.PrivateKey, cekPub []byte, aad AAD, content Content) (*Bundle, error) {
	kem, kdf, aead := suiteParts()
	pk, err := kem.NewPublicKey(cekPub)
	if err != nil {
		return nil, fmt.Errorf("bundle: CEKpub is not an MLKEM768-P256 encapsulation key: %w", err)
	}
	info := InfoSigned(aad.Target, aad.Handle)
	enc, s, err := hpke.NewSender(pk, kdf, aead, info)
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
	ct, err := s.Seal(aadBytes, pt)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(ToBeSigned(cekPub, info, aadBytes, enc, ct))
	sig, err := ecdsa.SignASN1(rand.Reader, signKey, digest[:])
	if err != nil {
		return nil, err
	}
	return &Bundle{Container: ContainerSigned, Suite: SuiteSigned, Enc: enc, Ciphertext: ct, AAD: aad, Signature: sig}, nil
}

// ExpectSigned is what the Attester bound into its Evidence, its CEK, and the Vault key it holds for the Target.
type ExpectSigned struct {
	Target         string
	Handle         []byte // the freshness element
	CredentialHint string
	CEK            hpke.PrivateKey
	VaultKey       *ecdsa.PublicKey
}

// ErrSignature is returned when the signature is missing or not the trusted Vault's over this request's bundle.
var ErrSignature = errors.New("bundle: not signed by the trusted Vault key over this request's bundle")

// OpenSigned checks the container, the suite, the associated data and the Vault's signature, then decrypts.
func OpenSigned(b *Bundle, exp ExpectSigned) (*Content, error) {
	if b.Container != ContainerSigned || b.Suite != SuiteSigned {
		return nil, ErrContainer
	}
	if b.AAD.Target != exp.Target || !bytes.Equal(b.AAD.Handle, exp.Handle) || b.AAD.CredentialHint != exp.CredentialHint {
		return nil, ErrAAD
	}
	if exp.VaultKey == nil || len(b.Signature) == 0 {
		return nil, ErrSignature
	}
	cekPub := exp.CEK.PublicKey().Bytes()
	info := InfoSigned(exp.Target, exp.Handle)
	aadBytes, err := Canonical(b.AAD)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(ToBeSigned(cekPub, info, aadBytes, b.Enc, b.Ciphertext))
	if !ecdsa.VerifyASN1(exp.VaultKey, digest[:], b.Signature) {
		return nil, ErrSignature
	}
	_, kdf, aead := suiteParts()
	r, err := hpke.NewRecipient(b.Enc, exp.CEK, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	pt, err := r.Open(aadBytes, b.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	var c Content
	if err := json.Unmarshal(pt, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Refusals of CheckItems.
var (
	ErrAttributes = errors.New("bundle: an item has no key-block attributes (purpose, algorithm, exportable)")
	ErrExportable = errors.New("bundle: an item may leave the TEE")
	ErrShared     = errors.New("bundle: an item is a private key shared among instances, which this CAI takes none of")
	ErrValidity   = errors.New("bundle: validity_seconds is missing or longer than this CAI accepts")
)

// CheckItems is the CAI's policy on what it takes: every item with its key-block attributes, nothing exportable, a
// shared private key only if acceptShared, and a validity of at most maxValiditySeconds (0: not checked).
func CheckItems(c *Content, acceptShared bool, maxValiditySeconds int) error {
	for _, it := range c.CredentialItems {
		if len(it.Purpose) == 0 || it.Algorithm == "" || it.Exportable == nil {
			return fmt.Errorf("%w: %s", ErrAttributes, it.Kid)
		}
		if *it.Exportable {
			return fmt.Errorf("%w: %s", ErrExportable, it.Kid)
		}
		if it.Shared && !acceptShared {
			return fmt.Errorf("%w: %s", ErrShared, it.Kid)
		}
	}
	if maxValiditySeconds > 0 {
		v, ok := c.Metadata["validity_seconds"].(float64)
		if !ok || v > float64(maxValiditySeconds) || v != float64(int(v)) {
			return fmt.Errorf("%w: %v", ErrValidity, c.Metadata["validity_seconds"])
		}
	}
	return nil
}
