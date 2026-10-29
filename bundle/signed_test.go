package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func testVault(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testContent() Content {
	no := false
	return Content{CredentialItems: []Item{{Type: "symmetric-key", Format: "raw", Value: "c2VjcmV0", Kid: "g1",
		Purpose: []string{"encrypt", "decrypt"}, Algorithm: "AES-256-GCM", Exportable: &no}},
		Metadata: map[string]any{"validity_seconds": 3600, "rotation_epoch": 1}}
}

// The hybrid suite of the hpke-base container: with the Vault's origin authentication required, what opens and what is
// refused; without the requirement, what the Attester accepts.
func TestBaseRoundTripAndRefusals(t *testing.T) {
	vault := testVault(t)
	cek, cekPub, err := GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}
	if len(cekPub) != 1249 {
		t.Fatalf("CEKpub is %d octets, want 1249", len(cekPub))
	}
	aad := AAD{GroupID: "g1", Target: "https://ledger.tacra.example",
		Handle: []byte("0123456789abcdef0123456789abcdef"), CredentialHint: "workload.tacra.example"}
	b, err := SealBase(vault, cekPub, aad, testContent())
	if err != nil {
		t.Fatal(err)
	}
	if b.Container != ContainerBase || b.Origin == nil || b.Origin.Alg != OriginAlg {
		t.Fatalf("the Vault's container: %s, origin %+v", b.Container, b.Origin)
	}
	exp := ExpectBase{Target: aad.Target, Handle: aad.Handle, CredentialHint: aad.CredentialHint,
		CEK: cek, VaultKey: &vault.PublicKey, RequireOrigin: true}
	c, err := OpenBase(b, exp)
	if err != nil {
		t.Fatalf("honest bundle: %v", err)
	}
	if err := CheckItems(c, false, 3600); err != nil {
		t.Fatalf("honest items: %v", err)
	}
	other := testVault(t)
	_, cekPub2, _ := GenerateCEK()
	b2, _ := SealBase(vault, cekPub2, aad, testContent())
	forged, _ := SealBase(other, cekPub, aad, testContent())
	unsigned, err := SealBase(nil, cekPub, aad, testContent())
	if err != nil || unsigned.Origin != nil {
		t.Fatalf("sealed without a key: %v, origin %+v", err, unsigned.Origin)
	}
	for _, c := range []struct {
		name string
		b    Bundle
		exp  ExpectBase
		want error
	}{
		{"signed by another key", *forged, exp, ErrSignature},
		{"origin stripped", func() Bundle { x := *b; x.Origin = nil; return x }(), exp, ErrOriginRequired},
		{"unsigned by the Vault, origin required", *unsigned, exp, ErrOriginRequired},
		{"origin of another algorithm", func() Bundle {
			x, o := *b, *b.Origin
			o.Alg = "ECDSA-P384-SHA384"
			x.Origin = &o
			return x
		}(), exp, ErrSignature},
		{"suite relabelled", func() Bundle { x := *b; x.Suite.KEM = "DHKEM(X25519, HKDF-SHA256)"; return x }(), exp, ErrContainer},
		{"container relabelled", func() Bundle { x := *b; x.Container = Container; return x }(), exp, ErrContainer},
		{"another request's enc, ciphertext and origin", func() Bundle {
			x := *b
			x.Enc, x.Ciphertext, x.Origin = b2.Enc, b2.Ciphertext, b2.Origin
			return x
		}(), exp, ErrSignature},
		{"another handle", *b, func() ExpectBase { e := exp; e.Handle = []byte("other"); return e }(), ErrAAD},
		{"origin required, no key held", *b, func() ExpectBase { e := exp; e.VaultKey = nil; return e }(), ErrSignature},
	} {
		if _, err := OpenBase(&c.b, c.exp); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	// the accepted risk: an Attester that holds no Vault key for the Target, and so requires no origin, opens a
	// container as it is, whoever sealed it
	relaxed := ExpectBase{Target: aad.Target, Handle: aad.Handle, CredentialHint: aad.CredentialHint, CEK: cek}
	for name, x := range map[string]*Bundle{"the Vault's unsigned container": unsigned, "the Vault's signed container": b,
		"a container signed by another key": forged} {
		if _, err := OpenBase(x, relaxed); err != nil {
			t.Errorf("no key held: %s: %v", name, err)
		}
	}
	// a key held is used on every origin member, whether or not one is required
	held := ExpectBase{Target: aad.Target, Handle: aad.Handle, CredentialHint: aad.CredentialHint, CEK: cek, VaultKey: &vault.PublicKey}
	if _, err := OpenBase(forged, held); !errors.Is(err, ErrSignature) {
		t.Errorf("key held, not required, signed by another key: %v, want %v", err, ErrSignature)
	}
	if _, err := OpenBase(unsigned, held); err != nil {
		t.Errorf("key held, not required, unsigned: %v", err)
	}
}

func TestCheckItems(t *testing.T) {
	yes, no := true, false
	for _, c := range []struct {
		name   string
		item   Item
		shared bool
		valid  any
		want   error
	}{
		{"with attributes", Item{Kid: "a", Purpose: []string{"encrypt"}, Algorithm: "AES-256-GCM", Exportable: &no}, false, 3600, nil},
		{"no attributes", Item{Kid: "b"}, false, 3600, ErrAttributes},
		{"exportable", Item{Kid: "c", Purpose: []string{"encrypt"}, Algorithm: "AES-256-GCM", Exportable: &yes}, false, 3600, ErrExportable},
		{"shared, not taken", Item{Kid: "d", Purpose: []string{"sign"}, Algorithm: "ECDSA-P256-SHA256", Exportable: &no, Shared: true}, false, 3600, ErrShared},
		{"shared, taken", Item{Kid: "e", Purpose: []string{"sign"}, Algorithm: "ECDSA-P256-SHA256", Exportable: &no, Shared: true}, true, 3600, nil},
		{"a day", Item{Kid: "f", Purpose: []string{"encrypt"}, Algorithm: "AES-256-GCM", Exportable: &no}, false, 86400, ErrValidity},
	} {
		raw, _ := json.Marshal(Content{CredentialItems: []Item{c.item}, Metadata: map[string]any{"validity_seconds": c.valid}})
		var content Content
		if err := json.Unmarshal(raw, &content); err != nil {
			t.Fatal(err)
		}
		if err := CheckItems(&content, c.shared, 3600); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

// vector is a test vector of the container (testdata/go-hpke-base.json, written by TestWriteVector).
type vector struct {
	CEKSeed        string          `json:"cek_seed"`
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

const vectorPath = "testdata/go-hpke-base.json"

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestOpenVector opens the committed vector (sealed and signed by this package on 29 October 2026, the origin member
// by the Target's policy) and checks info, the associated data and the to-be-signed octets byte for byte.
func TestOpenVector(t *testing.T) {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var b Bundle
	if err := json.Unmarshal(v.Bundle, &b); err != nil {
		t.Fatal(err)
	}
	cek, err := hpke.MLKEM768P256().NewPrivateKey(unhex(t, v.CEKSeed))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(cek.PublicKey().Bytes()) != v.CEKPub {
		t.Fatal("CEKpub from the seed differs from the vector's")
	}
	pub, err := x509.ParsePKIXPublicKey(unhex(t, v.VaultSPKI))
	if err != nil {
		t.Fatal(err)
	}
	fresh := unhex(t, v.Freshness)
	info := InfoBase(v.Target, fresh)
	if hex.EncodeToString(info) != v.Info {
		t.Fatal("info differs")
	}
	aad, _ := Canonical(b.AAD)
	if string(aad) != v.AAD {
		t.Fatalf("associated data differs:\n%s\n%s", aad, v.AAD)
	}
	if hex.EncodeToString(ToBeSigned(v.Suite, unhex(t, v.CEKPub), info, aad, b.Enc, b.Ciphertext)) != v.ToBeSigned {
		t.Fatal("to-be-signed octets differ")
	}
	c, err := OpenBase(&b, ExpectBase{Target: v.Target, Handle: fresh, CredentialHint: v.CredentialHint,
		CEK: cek, VaultKey: pub.(*ecdsa.PublicKey), RequireOrigin: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pt, _ := Canonical(c)
	if string(pt) != v.Plaintext {
		t.Fatalf("plaintext differs:\n%s\n%s", pt, v.Plaintext)
	}
	if err := CheckItems(c, false, 3600); err != nil {
		t.Fatal(err)
	}
}

// TestWriteVector writes the vector TestOpenVector reads: TACRA_WRITE_VECTOR=1 go test -run TestWriteVector.
func TestWriteVector(t *testing.T) {
	if os.Getenv("TACRA_WRITE_VECTOR") == "" {
		t.Skip("TACRA_WRITE_VECTOR not set")
	}
	vault := testVault(t)
	cek, cekPub, err := GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}
	fresh := make([]byte, 32)
	rand.Read(fresh)
	aad := AAD{GroupID: "1111111111111111111111111111111111111111111111111111111111111111", Target: "https://ledger.tacra.example", Handle: fresh, CredentialHint: "workload.tacra.example"}
	content := testContent()
	b, err := SealBase(vault, cekPub, aad, content)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := cek.Bytes()
	spki, _ := x509.MarshalPKIXPublicKey(&vault.PublicKey)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(vault)
	info := InfoBase(aad.Target, fresh)
	aadBytes, _ := Canonical(aad)
	pt, _ := Canonical(content)
	braw, _ := json.Marshal(b)
	out, _ := json.MarshalIndent(vector{Description: "hpke-base container with MLKEM768-P256, HKDF-SHA256 and AES-256-GCM, its origin member signed by the test Vault key: sealed by TWI bundle.SealBase (Go crypto/hpke) on 29 October 2026; test keys",
		Suite: SuiteMLKEM768P256, CEKSeed: hex.EncodeToString(seed), CEKPub: hex.EncodeToString(cekPub), VaultSPKI: hex.EncodeToString(spki),
		VaultPKCS8: hex.EncodeToString(pkcs8), Target: aad.Target, Freshness: hex.EncodeToString(fresh),
		CredentialHint: aad.CredentialHint, Info: hex.EncodeToString(info), AAD: string(aadBytes),
		ToBeSigned: hex.EncodeToString(ToBeSigned(SuiteMLKEM768P256, cekPub, info, aadBytes, b.Enc, b.Ciphertext)), Bundle: braw,
		Plaintext: string(pt)}, "", " ")
	if err := os.WriteFile(vectorPath, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
