package bundle

// The hpke-base-signed container of the revised profile (tacra-est impl/bundle.py): HPKE base mode, from the standard
// crypto/hpke, with one of two suites, and the Secret Vault's ECDSA P-256 signature over the sealed bundle. HPKE's
// replacement for RFC 9180 (draft-ietf-hpke-hpke-05) removes the Auth modes, and the post-quantum KEMs have no AuthEncap
// (draft-ietf-hpke-pq-05, Section 7.2), so the origin of the bundle is the Vault's signature, under a key the CAI holds
// for the Target and Retrieval.
//
//	suites        MLKEM768-P256 (0x0050), the bank profile's, or DHKEM(P-256, HKDF-SHA256) (0x0010), each with
//	              HKDF-SHA256 (0x0001) and AES-256-GCM (0x0002); a Target names in acceptable_cek the ones it takes
//	info          len32-prefixed: "tacra-est bundle v1", the Target, the freshness element
//	aad           Canonical({group_id, target, handle?, credential_hint?}), the JCS of RFC 8785
//	to be signed  len32-prefixed: "tacra-est bundle signature v1", the HPKE suite_id of the suite in use,
//	              "ecdsa-p256-sha256", CEKpub as the request carried it, info, aad, enc, ciphertext
//
// CEKpub is carried in the encoding of its KEM: the 1249-octet MLKEM768-P256 encapsulation key, or the DER
// SubjectPublicKeyInfo of a P-256 key. Those octets are the subject of the binding input for Retrieval.

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// ContainerSigned is the container of the revised profile.
const ContainerSigned = "hpke-base-signed"

// The two suites of ContainerSigned.
var (
	// SuiteSigned is the suite of the bank profile: the ML-KEM-768 and P-256 hybrid KEM.
	SuiteSigned = Suite{KEM: "MLKEM768-P256", KDF: "HKDF-SHA256", AEAD: "AES-256-GCM", Sig: "ECDSA-P256-SHA256"}
	// SuiteSignedP256 is the suite with the DHKEM of RFC 9180 on P-256.
	SuiteSignedP256 = Suite{KEM: "DHKEM(P-256, HKDF-SHA256)", KDF: "HKDF-SHA256", AEAD: "AES-256-GCM", Sig: "ECDSA-P256-SHA256"}
)

// How attest-initiate names the suites of ContainerSigned among the acceptable CEKs: the KEM, the KDF and the AEAD
// by their HPKE registry names, joined with "+", as the reference implementation does (tacra-est impl/bundle.py).
const (
	AcceptableSigned     = "MLKEM768-P256+HKDF-SHA256+AES-256-GCM"
	AcceptableSignedP256 = "DHKEM(P-256, HKDF-SHA256)+HKDF-SHA256+AES-256-GCM"
)

const (
	infoLabel = "tacra-est bundle v1"
	sigLabel  = "tacra-est bundle signature v1"
	sigAlg    = "ecdsa-p256-sha256"
)

// signedSuite is one suite of ContainerSigned: its names, its KEM and its HPKE suite_id.
type signedSuite struct {
	suite Suite
	kem   hpke.KEM
	id    []byte
}

// suiteID is the HPKE suite_id of RFC 9180 Section 5.1: "HPKE" || kem_id || kdf_id || aead_id, with HKDF-SHA256 and
// AES-256-GCM.
func suiteID(kemID uint16) []byte {
	return []byte{'H', 'P', 'K', 'E', byte(kemID >> 8), byte(kemID), 0x00, 0x01, 0x00, 0x02}
}

var signedSuites = []signedSuite{
	{suite: SuiteSigned, kem: hpke.MLKEM768P256(), id: suiteID(0x0050)},
	{suite: SuiteSignedP256, kem: hpke.DHKEM(ecdh.P256()), id: suiteID(0x0010)},
}

func kdfAEAD() (hpke.KDF, hpke.AEAD) {
	return hpke.HKDFSHA256(), hpke.AES256GCM()
}

// SuiteID returns the HPKE suite_id of a suite of ContainerSigned, and false for any other suite.
func SuiteID(s Suite) ([]byte, bool) {
	for _, c := range signedSuites {
		if c.suite == s {
			return c.id, true
		}
	}
	return nil, false
}

// publicKeyOf reads CEKpub as the request carries it: an MLKEM768-P256 encapsulation key, else the DER
// SubjectPublicKeyInfo of a P-256 key.
func publicKeyOf(cekPub []byte) (signedSuite, hpke.PublicKey, error) {
	if pk, err := signedSuites[0].kem.NewPublicKey(cekPub); err == nil {
		return signedSuites[0], pk, nil
	}
	if pub, err := x509.ParsePKIXPublicKey(cekPub); err == nil {
		var e *ecdh.PublicKey
		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			if k.Curve == elliptic.P256() {
				e, _ = k.ECDH()
			}
		case *ecdh.PublicKey:
			if k.Curve() == ecdh.P256() {
				e = k
			}
		}
		if e != nil {
			if pk, err := hpke.NewDHKEMPublicKey(e); err == nil {
				return signedSuites[1], pk, nil
			}
		}
	}
	return signedSuite{}, nil, errors.New("bundle: CEKpub is neither an MLKEM768-P256 encapsulation key nor a P-256 SubjectPublicKeyInfo")
}

// IsSignedCEK reports whether cekPub is an MLKEM768-P256 encapsulation key, the CEKpub of SuiteSigned.
func IsSignedCEK(cekPub []byte) bool {
	_, err := signedSuites[0].kem.NewPublicKey(cekPub)
	return err == nil
}

// IsSignedCEKP256 reports whether cekPub is the SubjectPublicKeyInfo of a P-256 key, the CEKpub of SuiteSignedP256.
// Such a key also opens the hpke-auth container, so the Secret Vault chooses by what the Target accepts.
func IsSignedCEKP256(cekPub []byte) bool {
	s, _, err := publicKeyOf(cekPub)
	return err == nil && s.suite == SuiteSignedP256
}

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

// ToBeSigned is what the Vault signs: the suite in use names the HPKE suite_id among the signed octets.
func ToBeSigned(s Suite, cekPub, info, aad, enc, ct []byte) []byte {
	id, _ := SuiteID(s)
	return lp(nil, []byte(sigLabel), id, []byte(sigAlg), cekPub, info, aad, enc, ct)
}

// GenerateCEK makes a fresh MLKEM768-P256 key pair for one request: the private key, and CEKpub as it is bound.
func GenerateCEK() (hpke.PrivateKey, []byte, error) {
	sk, err := signedSuites[0].kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return sk, sk.PublicKey().Bytes(), nil
}

// GenerateCEKP256 makes a fresh P-256 key pair for one request: the private key, and CEKpub as it is bound, the DER
// SubjectPublicKeyInfo.
func GenerateCEKP256() (*ecdh.PrivateKey, []byte, error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(k.PublicKey())
	if err != nil {
		return nil, nil, err
	}
	return k, spki, nil
}

// DHKEMPrivateKey is a P-256 CEK as the HPKE recipient takes it: from the ECDSA or ECDH private key the platform
// plug-in generated.
func DHKEMPrivateKey(k crypto.PrivateKey) (hpke.PrivateKey, error) {
	switch p := k.(type) {
	case *ecdh.PrivateKey:
		if p.Curve() != ecdh.P256() {
			return nil, errors.New("bundle: the CEK is not a P-256 key")
		}
		return hpke.NewDHKEMPrivateKey(p)
	case *ecdsa.PrivateKey:
		e, err := p.ECDH()
		if err != nil {
			return nil, err
		}
		if e.Curve() != ecdh.P256() {
			return nil, errors.New("bundle: the CEK is not a P-256 key")
		}
		return hpke.NewDHKEMPrivateKey(e)
	}
	return nil, fmt.Errorf("bundle: a CEK of type %T opens no signed container", k)
}

// SealSigned seals content to cekPub in base mode under the suite cekPub's encoding names and signs the result with
// the Vault's key. The freshness element is aad.Handle.
func SealSigned(signKey *ecdsa.PrivateKey, cekPub []byte, aad AAD, content Content) (*Bundle, error) {
	s, pk, err := publicKeyOf(cekPub)
	if err != nil {
		return nil, err
	}
	kdf, aead := kdfAEAD()
	info := InfoSigned(aad.Target, aad.Handle)
	enc, snd, err := hpke.NewSender(pk, kdf, aead, info)
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
	ct, err := snd.Seal(aadBytes, pt)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(ToBeSigned(s.suite, cekPub, info, aadBytes, enc, ct))
	sig, err := ecdsa.SignASN1(rand.Reader, signKey, digest[:])
	if err != nil {
		return nil, err
	}
	return &Bundle{Container: ContainerSigned, Suite: s.suite, Enc: enc, Ciphertext: ct, AAD: aad, Signature: sig}, nil
}

// ExpectSigned is what the Attester bound into its Evidence, its CEK, and the Vault key it holds for the Target.
type ExpectSigned struct {
	Target         string
	Handle         []byte // the freshness element
	CredentialHint string
	CEK            hpke.PrivateKey
	// CEKPub is CEKpub as the request carried it, the octets the signature covers. When nil, the KEM's own encoding
	// of CEK's public key, which is CEKpub of SuiteSigned.
	CEKPub   []byte
	VaultKey *ecdsa.PublicKey
}

// ErrSignature is returned when the signature is missing or not the trusted Vault's over this request's bundle.
var ErrSignature = errors.New("bundle: not signed by the trusted Vault key over this request's bundle")

// OpenSigned checks the container, the suite, the associated data and the Vault's signature, then decrypts.
func OpenSigned(b *Bundle, exp ExpectSigned) (*Content, error) {
	if b.Container != ContainerSigned {
		return nil, ErrContainer
	}
	if _, ok := SuiteID(b.Suite); !ok {
		return nil, ErrContainer
	}
	if b.AAD.Target != exp.Target || !bytes.Equal(b.AAD.Handle, exp.Handle) || b.AAD.CredentialHint != exp.CredentialHint {
		return nil, ErrAAD
	}
	if exp.VaultKey == nil || len(b.Signature) == 0 {
		return nil, ErrSignature
	}
	cekPub := exp.CEKPub
	if cekPub == nil {
		cekPub = exp.CEK.PublicKey().Bytes()
	}
	info := InfoSigned(exp.Target, exp.Handle)
	aadBytes, err := Canonical(b.AAD)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(ToBeSigned(b.Suite, cekPub, info, aadBytes, b.Enc, b.Ciphertext))
	if !ecdsa.VerifyASN1(exp.VaultKey, digest[:], b.Signature) {
		return nil, ErrSignature
	}
	kdf, aead := kdfAEAD()
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
