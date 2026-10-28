package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
)

func TestP256RoundTrip(t *testing.T) {
	sender, _ := GenerateSenderKeys()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cekSPKI, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	cek, _ := k.ECDH()
	vaultSPKI, _ := sender.PublicSPKI(KEMP256)
	aad := AAD{GroupID: "g", Target: "https://ledger.tacra.example"}
	b, err := Seal(sender, cekSPKI, aad, Content{CredentialItems: []Item{{Type: "psk", Value: "s"}}})
	if err != nil {
		t.Fatal(err)
	}
	if b.Suite.KEM != KEMP256 {
		t.Fatalf("suite %s", b.Suite.KEM)
	}
	c, err := Open(b, cek, Expect{Target: aad.Target, VaultSPKI: vaultSPKI})
	if err != nil || c.CredentialItems[0].Value != "s" {
		t.Fatalf("%v %+v", err, c)
	}
	// a container sealed by someone else who saw CEKpub is refused
	intruder, _ := GenerateSenderKeys()
	forged, _ := Seal(intruder, cekSPKI, aad, Content{CredentialItems: []Item{{Type: "psk", Value: "x"}}})
	if _, err := Open(forged, cek, Expect{Target: aad.Target, VaultSPKI: vaultSPKI}); !errors.Is(err, ErrOrigin) {
		t.Fatalf("container from another sender: %v", err)
	}
}

// Canonical matches Python's json.dumps(sort_keys=True, separators=(",", ":")).
func TestCanonicalMatchesReference(t *testing.T) {
	got, err := Canonical(map[string]any{"b": "Ω\u007f✓\U0001F600<&>", "a": []any{1, true, nil}})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":[1,true,null],\"b\":\"Ω\u007f✓\U0001F600<&>\"}" // RFC 8785: nothing above U+001F is escaped
	if string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
