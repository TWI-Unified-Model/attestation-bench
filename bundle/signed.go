package bundle

// The hpke-base container of the EST profile (draft-novak-lamps-tacra-est, Response: EncryptedCredentialBundle; issue
// #15 of the draft, 28 October 2026), as TACRA's "Sealing the Released Credential" constructs it: HPKE in base mode,
// from the standard crypto/hpke, under one of two suites, and, where the Target requires origin authentication, the
// Secret Vault's ECDSA P-256 signature over the sealed container, in the container's origin member. HPKE's replacement
// for RFC 9180 (draft-ietf-hpke-hpke-05) removes the Auth modes, and the post-quantum KEMs have no AuthEncap
// (draft-ietf-hpke-pq-05, Section 7.2), so where a deployment wants the origin authenticated it is the Vault's
// signature, under a key the CAI holds for the Target and Retrieval. Without it, a container anyone sealed to CEKpub
// opens: the profile's accepted risk, which the CAI takes for a Target it holds no key for.
//
//	suites        MLKEM768-P256 (0x0050), the bank profile's, or DHKEM(P-256, HKDF-SHA256) (0x0010), each with
//	              HKDF-SHA256 (0x0001) and AES-256-GCM (0x0002); a Target names in acceptable_cek the ones it takes
//	info          len32-prefixed: "tacra hpke-base v1", the Target, the freshness element
//	aad           Canonical({group_id, target, handle?, credential_hint?}), the JCS of RFC 8785
//	origin        {alg: "ECDSA-P256-SHA256", signature}: ECDSA P-256 over the SHA-256 of the len32-prefixed
//	              "tacra-est bundle signature v1", the HPKE suite_id of the suite in use, "ECDSA-P256-SHA256", CEKpub
//	              as the request carried it, info, aad, enc, ciphertext; the signature DER-encoded (ECDSA-Sig-Value)
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

// ContainerBase is the container of the EST profile.
const ContainerBase = "hpke-base"

// OriginAlg is the name of the origin member's signature algorithm, in the member and among the signed octets alike.
const OriginAlg = "ECDSA-P256-SHA256"

// The two suites of ContainerBase.
var (
	// SuiteMLKEM768P256 is the suite of the bank profile: the ML-KEM-768 and P-256 hybrid KEM, the profile's
	// recommended one.
	SuiteMLKEM768P256 = Suite{KEM: "MLKEM768-P256", KDF: "HKDF-SHA256", AEAD: "AES-256-GCM"}
	// SuiteDHKEMP256 is the suite with the DHKEM of RFC 9180 on P-256, the profile's mandatory one.
	SuiteDHKEMP256 = Suite{KEM: "DHKEM(P-256, HKDF-SHA256)", KDF: "HKDF-SHA256", AEAD: "AES-256-GCM"}
)

// How attest-initiate names the suites of ContainerBase among the acceptable CEKs: the KEM, the KDF and the AEAD by
// their HPKE registry names, joined with "+", as the reference implementation does (tacra-est impl/bundle.py).
const (
	AcceptableMLKEM768P256 = "MLKEM768-P256+HKDF-SHA256+AES-256-GCM"
	AcceptableDHKEMP256    = "DHKEM(P-256, HKDF-SHA256)+HKDF-SHA256+AES-256-GCM"
)

const (
	infoLabel = "tacra hpke-base v1"
	sigLabel  = "tacra-est bundle signature v1"
)

// baseSuite is one suite of ContainerBase: its names, its KEM and its HPKE suite_id.
type baseSuite struct {
	suite Suite
	kem   hpke.KEM
	id    []byte
}

// suiteID is the HPKE suite_id of RFC 9180 Section 5.1: "HPKE" || kem_id || kdf_id || aead_id, with HKDF-SHA256 and
// AES-256-GCM.
func suiteID(kemID uint16) []byte {
	return []byte{'H', 'P', 'K', 'E', byte(kemID >> 8), byte(kemID), 0x00, 0x01, 0x00, 0x02}
}

var baseSuites = []baseSuite{
	{suite: SuiteMLKEM768P256, kem: hpke.MLKEM768P256(), id: suiteID(0x0050)},
	{suite: SuiteDHKEMP256, kem: hpke.DHKEM(ecdh.P256()), id: suiteID(0x0010)},
}

func kdfAEAD() (hpke.KDF, hpke.AEAD) {
	return hpke.HKDFSHA256(), hpke.AES256GCM()
}

// SuiteID returns the HPKE suite_id of a suite of ContainerBase, and false for any other suite.
func SuiteID(s Suite) ([]byte, bool) {
	for _, c := range baseSuites {
		if c.suite == s {
			return c.id, true
		}
	}
	return nil, false
}

// publicKeyOf reads CEKpub as the request carries it: an MLKEM768-P256 encapsulation key, else the DER
// SubjectPublicKeyInfo of a P-256 key.
func publicKeyOf(cekPub []byte) (baseSuite, hpke.PublicKey, error) {
	if pk, err := baseSuites[0].kem.NewPublicKey(cekPub); err == nil {
		return baseSuites[0], pk, nil
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
				return baseSuites[1], pk, nil
			}
		}
	}
	return baseSuite{}, nil, errors.New("bundle: CEKpub is neither an MLKEM768-P256 encapsulation key nor a P-256 SubjectPublicKeyInfo")
}

// IsMLKEM768P256CEK reports whether cekPub is an MLKEM768-P256 encapsulation key, the CEKpub of SuiteMLKEM768P256.
func IsMLKEM768P256CEK(cekPub []byte) bool {
	_, err := baseSuites[0].kem.NewPublicKey(cekPub)
	return err == nil
}

// IsP256CEK reports whether cekPub is the SubjectPublicKeyInfo of a P-256 key, the CEKpub of SuiteDHKEMP256. Such a
// key also opens the hpke-auth container, so the Secret Vault chooses by what the Target accepts.
func IsP256CEK(cekPub []byte) bool {
	s, _, err := publicKeyOf(cekPub)
	return err == nil && s.suite == SuiteDHKEMP256
}

func lp(b []byte, parts ...[]byte) []byte {
	for _, p := range parts {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p)))
		b = append(b, p...)
	}
	return b
}

// InfoBase is the HPKE info of ContainerBase.
func InfoBase(target string, freshness []byte) []byte {
	return lp(nil, []byte(infoLabel), []byte(target), freshness)
}

// ToBeSigned is what the Vault signs for the origin member: the suite in use names the HPKE suite_id among the signed
// octets, and the algorithm's name is OriginAlg, the one the member carries.
func ToBeSigned(s Suite, cekPub, info, aad, enc, ct []byte) []byte {
	id, _ := SuiteID(s)
	return lp(nil, []byte(sigLabel), id, []byte(OriginAlg), cekPub, info, aad, enc, ct)
}

// GenerateCEK makes a fresh MLKEM768-P256 key pair for one request: the private key, and CEKpub as it is bound.
func GenerateCEK() (hpke.PrivateKey, []byte, error) {
	sk, err := baseSuites[0].kem.GenerateKey()
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
	return nil, fmt.Errorf("bundle: a CEK of type %T opens no hpke-base container", k)
}

// SealBase seals content to cekPub in base mode under the suite cekPub's encoding names, and, with signKey, signs the
// result into the origin member. Without signKey the container carries no origin member: the Target's policy accepts
// the risk. The freshness element is aad.Handle.
func SealBase(signKey *ecdsa.PrivateKey, cekPub []byte, aad AAD, content Content) (*Bundle, error) {
	s, pk, err := publicKeyOf(cekPub)
	if err != nil {
		return nil, err
	}
	kdf, aead := kdfAEAD()
	info := InfoBase(aad.Target, aad.Handle)
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
	b := &Bundle{Container: ContainerBase, Suite: s.suite, Enc: enc, Ciphertext: ct, AAD: aad}
	if signKey != nil {
		digest := sha256.Sum256(ToBeSigned(s.suite, cekPub, info, aadBytes, enc, ct))
		sig, err := ecdsa.SignASN1(rand.Reader, signKey, digest[:])
		if err != nil {
			return nil, err
		}
		b.Origin = &Origin{Alg: OriginAlg, Signature: sig}
	}
	return b, nil
}

// ExpectBase is what the Attester bound into its Evidence, its CEK, and its policy for the Target on origin
// authentication: the Vault key it holds, and whether the container must carry a signature under it.
type ExpectBase struct {
	Target         string
	Handle         []byte // the freshness element
	CredentialHint string
	CEK            hpke.PrivateKey
	// CEKPub is CEKpub as the request carried it, the octets the signature covers. When nil, the KEM's own encoding
	// of CEK's public key, which is CEKpub of SuiteMLKEM768P256.
	CEKPub []byte
	// VaultKey is the Secret Vault's signature key the Attester holds for the Target; an origin member the container
	// carries is verified under it. RequireOrigin refuses a container without one. The CAI holds both or neither.
	VaultKey      *ecdsa.PublicKey
	RequireOrigin bool
}

// Refusals of OpenBase on the origin member.
var (
	// ErrSignature is returned when the origin member is not the trusted Vault's signature over this request's bundle.
	ErrSignature = errors.New("bundle: not signed by the trusted Vault key over this request's bundle")
	// ErrOriginRequired is returned when the Target requires origin authentication and the container carries none.
	ErrOriginRequired = errors.New("bundle: origin authentication required, and the container carries none")
)

// OpenBase checks the container, the suite, the associated data and, as the Attester's policy says, the origin
// member, then decrypts. With VaultKey, an origin member the container carries must verify under it; with
// RequireOrigin, the container must carry one. With neither, the container opens as it is.
func OpenBase(b *Bundle, exp ExpectBase) (*Content, error) {
	if b.Container != ContainerBase {
		return nil, ErrContainer
	}
	if _, ok := SuiteID(b.Suite); !ok {
		return nil, ErrContainer
	}
	if b.AAD.Target != exp.Target || !bytes.Equal(b.AAD.Handle, exp.Handle) || b.AAD.CredentialHint != exp.CredentialHint {
		return nil, ErrAAD
	}
	info := InfoBase(exp.Target, exp.Handle)
	aadBytes, err := Canonical(b.AAD)
	if err != nil {
		return nil, err
	}
	switch {
	case b.Origin != nil && exp.VaultKey != nil:
		cekPub := exp.CEKPub
		if cekPub == nil {
			cekPub = exp.CEK.PublicKey().Bytes()
		}
		digest := sha256.Sum256(ToBeSigned(b.Suite, cekPub, info, aadBytes, b.Enc, b.Ciphertext))
		if b.Origin.Alg != OriginAlg || !ecdsa.VerifyASN1(exp.VaultKey, digest[:], b.Origin.Signature) {
			return nil, ErrSignature
		}
	case b.Origin != nil && exp.RequireOrigin:
		return nil, ErrSignature // required, and no key to verify it under
	case b.Origin == nil && exp.RequireOrigin:
		return nil, ErrOriginRequired
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
