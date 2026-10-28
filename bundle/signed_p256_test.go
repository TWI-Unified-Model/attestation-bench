package bundle

import (
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// The DHKEM(P-256, HKDF-SHA256) suite of the signed container: CEKpub is a SubjectPublicKeyInfo, and the signature
// covers those octets and the suite's own suite_id.
func TestSignedP256RoundTripAndRefusals(t *testing.T) {
	vault := testVault(t)
	k, cekPub, err := GenerateCEKP256()
	if err != nil {
		t.Fatal(err)
	}
	if pub, err := x509.ParsePKIXPublicKey(cekPub); err != nil {
		t.Fatalf("CEKpub is not a SubjectPublicKeyInfo: %v", err)
	} else if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("CEKpub parses as %T, want an EC key", pub)
	}
	if !IsSignedCEKP256(cekPub) || IsSignedCEK(cekPub) {
		t.Fatal("CEKpub is not read as the P-256 CEK of the signed container")
	}
	cek, err := DHKEMPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	aad := AAD{GroupID: "g1", Target: "https://ledger.tacra.example",
		Handle: []byte("0123456789abcdef0123456789abcdef"), CredentialHint: "workload.tacra.example"}
	b, err := SealSigned(vault, cekPub, aad, testContent())
	if err != nil {
		t.Fatal(err)
	}
	if b.Suite != SuiteSignedP256 {
		t.Fatalf("suite %+v, want %+v", b.Suite, SuiteSignedP256)
	}
	if len(b.Enc) != 65 {
		t.Fatalf("enc is %d octets, want the 65 of an uncompressed P-256 point", len(b.Enc))
	}
	exp := ExpectSigned{Target: aad.Target, Handle: aad.Handle, CredentialHint: aad.CredentialHint,
		CEK: cek, CEKPub: cekPub, VaultKey: &vault.PublicKey}
	c, err := OpenSigned(b, exp)
	if err != nil {
		t.Fatalf("honest bundle: %v", err)
	}
	if err := CheckItems(c, false, 3600); err != nil {
		t.Fatalf("honest items: %v", err)
	}
	other := testVault(t)
	_, cekPub2, _ := GenerateCEKP256()
	b2, _ := SealSigned(vault, cekPub2, aad, testContent())
	forged, _ := SealSigned(other, cekPub, aad, testContent())
	hybrid, hybridPub, _ := GenerateCEK()
	hb, _ := SealSigned(vault, hybridPub, aad, testContent())
	for _, c := range []struct {
		name string
		b    Bundle
		exp  ExpectSigned
		want error
	}{
		{"signed by another key", *forged, exp, ErrSignature},
		{"unsigned", func() Bundle { x := *b; x.Signature = nil; return x }(), exp, ErrSignature},
		{"suite relabelled as the hybrid", func() Bundle { x := *b; x.Suite = SuiteSigned; return x }(), exp, ErrSignature},
		{"suite relabelled as hpke-auth's", func() Bundle { x := *b; x.Suite.KEM = "DHKEM(X25519, HKDF-SHA256)"; return x }(), exp, ErrContainer},
		{"another request's enc, ciphertext and signature", func() Bundle {
			x := *b
			x.Enc, x.Ciphertext, x.Signature = b2.Enc, b2.Ciphertext, b2.Signature
			return x
		}(), exp, ErrSignature},
		{"CEKpub as the raw point, not as carried", *b, func() ExpectSigned { e := exp; e.CEKPub = cek.PublicKey().Bytes(); return e }(), ErrSignature},
		{"another handle", *b, func() ExpectSigned { e := exp; e.Handle = []byte("other"); return e }(), ErrAAD},
		{"the hybrid's bundle under the P-256 CEK", *hb, exp, ErrSignature},
	} {
		if _, err := OpenSigned(&c.b, c.exp); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	// the hybrid still works beside it
	if _, err := OpenSigned(hb, ExpectSigned{Target: aad.Target, Handle: aad.Handle, CredentialHint: aad.CredentialHint,
		CEK: hybrid, VaultKey: &vault.PublicKey}); err != nil {
		t.Fatalf("hybrid bundle: %v", err)
	}
}

// vectorP256 is the test vector of the P-256 suite (testdata/go-hpke-base-signed-p256.json, TestWriteVectorP256).
type vectorP256 struct {
	CEKPKCS8       string          `json:"cek_pkcs8"`
	CEKPub         string          `json:"cek_pub"`
	VaultSPKI      string          `json:"vault_signing_spki"`
	VaultPKCS8     string          `json:"vault_signing_key_pkcs8"`
	Target         string          `json:"target"`
	Freshness      string          `json:"freshness"`
	CredentialHint string          `json:"credential_hint"`
	Info           string          `json:"info"`
	AAD            string          `json:"aad"`
	ToBeSigned     string          `json:"to_be_signed"`
	Bundle         json.RawMessage `json:"bundle"`
	Plaintext      string          `json:"plaintext"`
	Suite          Suite           `json:"suite"`
	Description    string          `json:"description"`
}

const vectorP256Path = "testdata/go-hpke-base-signed-p256.json"

func TestOpenVectorP256(t *testing.T) {
	raw, err := os.ReadFile(vectorP256Path)
	if err != nil {
		t.Skipf("no vector yet: %v", err)
	}
	var v vectorP256
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var b Bundle
	if err := json.Unmarshal(v.Bundle, &b); err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(unhex(t, v.CEKPKCS8))
	if err != nil {
		t.Fatal(err)
	}
	cek, err := DHKEMPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	cekPub := unhex(t, v.CEKPub)
	pub, err := x509.ParsePKIXPublicKey(unhex(t, v.VaultSPKI))
	if err != nil {
		t.Fatal(err)
	}
	fresh := unhex(t, v.Freshness)
	info := InfoSigned(v.Target, fresh)
	if hex.EncodeToString(info) != v.Info {
		t.Fatal("info differs")
	}
	aad, _ := Canonical(b.AAD)
	if string(aad) != v.AAD {
		t.Fatalf("associated data differs:\n%s\n%s", aad, v.AAD)
	}
	if hex.EncodeToString(ToBeSigned(v.Suite, cekPub, info, aad, b.Enc, b.Ciphertext)) != v.ToBeSigned {
		t.Fatal("to-be-signed octets differ")
	}
	c, err := OpenSigned(&b, ExpectSigned{Target: v.Target, Handle: fresh, CredentialHint: v.CredentialHint,
		CEK: cek, CEKPub: cekPub, VaultKey: pub.(*ecdsa.PublicKey)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pt, _ := Canonical(c)
	if string(pt) != v.Plaintext {
		t.Fatalf("plaintext differs:\n%s\n%s", pt, v.Plaintext)
	}
}

// TestWriteVectorP256 writes the vector TestOpenVectorP256 reads: TACRA_WRITE_VECTOR_P256=1 go test -run TestWriteVectorP256.
func TestWriteVectorP256(t *testing.T) {
	if os.Getenv("TACRA_WRITE_VECTOR_P256") == "" {
		t.Skip("TACRA_WRITE_VECTOR_P256 not set")
	}
	vault := testVault(t)
	k, cekPub, err := GenerateCEKP256()
	if err != nil {
		t.Fatal(err)
	}
	cek, err := DHKEMPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	aad := AAD{GroupID: "a0f1c2d3e4f50617a0f1c2d3e4f50617a0f1c2d3e4f50617", Target: "https://ledger.tacra.example",
		Handle: []byte("0123456789abcdef0123456789abcdef"), CredentialHint: "workload.tacra.example"}
	b, err := SealSigned(vault, cekPub, aad, testContent())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSigned(b, ExpectSigned{Target: aad.Target, Handle: aad.Handle, CredentialHint: aad.CredentialHint,
		CEK: cek, CEKPub: cekPub, VaultKey: &vault.PublicKey}); err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(k)
	spki, _ := x509.MarshalPKIXPublicKey(&vault.PublicKey)
	vpkcs8, _ := x509.MarshalPKCS8PrivateKey(vault)
	info := InfoSigned(aad.Target, aad.Handle)
	aadBytes, _ := Canonical(aad)
	pt, _ := Canonical(testContent())
	braw, _ := json.Marshal(b)
	v := vectorP256{CEKPKCS8: hex.EncodeToString(pkcs8), CEKPub: hex.EncodeToString(cekPub), VaultSPKI: hex.EncodeToString(spki),
		VaultPKCS8: hex.EncodeToString(vpkcs8), Target: aad.Target, Freshness: hex.EncodeToString(aad.Handle),
		CredentialHint: aad.CredentialHint, Info: hex.EncodeToString(info), AAD: string(aadBytes),
		ToBeSigned: hex.EncodeToString(ToBeSigned(b.Suite, cekPub, info, aadBytes, b.Enc, b.Ciphertext)), Bundle: braw,
		Plaintext: string(pt), Suite: b.Suite,
		Description: "hpke-base-signed with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM: sealed and signed by this package on 28 October 2026"}
	out, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(vectorP256Path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = hpke.AES256GCM
}
