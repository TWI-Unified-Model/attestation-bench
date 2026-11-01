package bundle

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
)

// What keeps a conduit from giving the Attester the container the Vault made for another Retrieval, and which of the
// container's checks it rests on (docs/attacks.md, section 6). The Vault seals for two Targets under the same RRP
// identifier and the same epoch (a present-epoch or absent-epoch Handle, which every Target shares). With a new CEK
// for each Retrieval, as the CAI makes, the other container does not open whatever the associated data says. With one
// CEK kept across Retrievals, the hpke-auth container's HPKE info carries the RRP identifier and the freshness element
// but not the Target, so only the associated data's Target check refuses the other Target's container; the
// hpke-base container's origin signature covers the Target, in its HPKE info, and refuses it without that check.

const (
	keptLedger = "https://ledger.tacra.example"
	keptDB     = "https://db.tacra.example"
)

var keptEpoch = []byte("an epoch every Target of the deployment shares")

func keptContent(secret string) Content {
	no := false
	return Content{CredentialItems: []Item{{Type: "api-key", Value: secret, Purpose: []string{"authenticate"},
		Algorithm: "opaque-bearer", Exportable: &no}}, Metadata: map[string]any{"validity_seconds": 3600}}
}

func keptAAD(target string) AAD {
	return AAD{GroupID: "g", Target: B64(target), Handle: keptEpoch}
}

func TestAuthContainerNewCEKForEachRetrieval(t *testing.T) {
	vault, err := GenerateSenderKeys()
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := vault.PublicSPKI(KEMX25519)
	if err != nil {
		t.Fatal(err)
	}
	cekA, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cekB, _ := ecdh.X25519().GenerateKey(rand.Reader)
	spkiA, _ := x509.MarshalPKIXPublicKey(cekA.PublicKey())
	a, err := Seal(vault, spkiA, keptAAD(keptLedger), keptContent("the ledger's key"))
	if err != nil {
		t.Fatal(err)
	}
	// B's CAI, comparing nothing: it takes the RRP identifier, Target and Handle the container itself names
	_, err = Open(a, cekB, Expect{Target: string(a.AAD.Target), Handle: a.AAD.Handle, VaultSPKI: anchor})
	if !errors.Is(err, ErrOrigin) {
		t.Fatalf("A's container opened with B's CEK: %v, want %v", err, ErrOrigin)
	}
}

func TestAuthContainerKeptCEKOnlyTheTargetCheck(t *testing.T) {
	vault, err := GenerateSenderKeys()
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := vault.PublicSPKI(KEMX25519)
	if err != nil {
		t.Fatal(err)
	}
	cek, _ := ecdh.X25519().GenerateKey(rand.Reader) // kept: the same CEK for the two Retrievals
	spki, _ := x509.MarshalPKIXPublicKey(cek.PublicKey())
	a, err := Seal(vault, spki, keptAAD(keptLedger), keptContent("the ledger's key"))
	if err != nil {
		t.Fatal(err)
	}
	expectDB := Expect{Target: keptDB, Handle: keptEpoch, VaultSPKI: anchor}
	if _, err := Open(a, cek, expectDB); !errors.Is(err, ErrAAD) {
		t.Fatalf("the ledger's container given for db: %v, want %v", err, ErrAAD)
	}
	// without the Target check, the HPKE info (RRP identifier and Handle, the same for both) lets it open
	noTarget := expectDB
	noTarget.Target = string(a.AAD.Target)
	c, err := Open(a, cek, noTarget)
	if err != nil || c.CredentialItems[0].Value != "the ledger's key" {
		t.Fatalf("without the Target check: %v; this test shows that the Target check is the one that refuses", err)
	}
}

func TestOriginSignatureCoversTheTarget(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sk, cekPub, err := GenerateCEK() // kept: the same CEK for the two Retrievals
	if err != nil {
		t.Fatal(err)
	}
	a, err := SealBase(signer, cekPub, keptAAD(keptLedger), keptContent("the ledger's key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBase(a, ExpectBase{Target: keptDB, Handle: keptEpoch, CEK: sk,
		VaultKey: &signer.PublicKey, RequireOrigin: true}); !errors.Is(err, ErrAAD) {
		t.Fatalf("the ledger's container given for db: %v, want %v", err, ErrAAD)
	}
	// without the associated data's check, what db's CAI verifies is signed over db's info, not the ledger's
	aadBytes, err := Canonical(a.AAD)
	if err != nil {
		t.Fatal(err)
	}
	verifies := func(target string) bool {
		d := sha256.Sum256(ToBeSigned(SuiteMLKEM768P256, cekPub, InfoBase(target, keptEpoch), aadBytes, a.Enc, a.Ciphertext))
		return ecdsa.VerifyASN1(&signer.PublicKey, d[:], a.Origin.Signature)
	}
	if !verifies(keptLedger) {
		t.Fatal("the Vault's signature does not verify for the Target it was made for")
	}
	if verifies(keptDB) {
		t.Fatal("the Vault's signature verifies for another Target")
	}
	// and with a new CEK for each Retrieval it does not verify either: the signature covers CEKpub
	_, otherPub, err := GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(ToBeSigned(SuiteMLKEM768P256, otherPub, InfoBase(keptLedger, keptEpoch), aadBytes, a.Enc, a.Ciphertext))
	if ecdsa.VerifyASN1(&signer.PublicKey, d[:], a.Origin.Signature) {
		t.Fatal("the Vault's signature verifies for another CEK")
	}
}
