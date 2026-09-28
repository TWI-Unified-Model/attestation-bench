package bundle

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fixture struct {
	CEK            string          `json:"cek_x25519"`
	VaultSPKI      string          `json:"vault_spki"`
	RRPID          string          `json:"rrp_id"`
	Target         string          `json:"target"`
	Handle         string          `json:"handle"`
	CredentialHint string          `json:"credential_hint"`
	Bundle         json.RawMessage `json:"bundle"`
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The reference implementation's Secret Vault (tacra-est, Python) sealed testdata/reference-bundle*.json, with and
// without a Credential Hint.
func TestOpensReferenceBundle(t *testing.T) {
	for _, name := range []string{"reference-bundle.json", "reference-bundle-nohint.json"} {
		t.Run(name, func(t *testing.T) { opensReference(t, name) })
	}
}

func opensReference(t *testing.T, name string) {
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	var b Bundle
	if err := json.Unmarshal(f.Bundle, &b); err != nil {
		t.Fatal(err)
	}
	cek, err := ecdh.X25519().NewPrivateKey(b64(t, f.CEK))
	if err != nil {
		t.Fatal(err)
	}
	exp := Expect{RRPID: f.RRPID, Target: f.Target, Handle: b64(t, f.Handle), CredentialHint: f.CredentialHint,
		VaultSPKI: b64(t, f.VaultSPKI)}
	c, err := Open(&b, cek, exp)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.CredentialItems) != 1 || c.CredentialItems[0].Type != "shared-signing-key" ||
		!strings.HasPrefix(c.CredentialItems[0].Value, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("content %+v", c)
	}
	// the same container under another trusted Vault key, or with another Target expected, is refused
	other, _ := GenerateSenderKeys()
	otherSPKI, _ := other.PublicSPKI(KEMX25519)
	bad := exp
	bad.VaultSPKI = otherSPKI
	if _, err := Open(&b, cek, bad); !errors.Is(err, ErrOrigin) {
		t.Fatalf("other Vault key: %v", err)
	}
	bad = exp
	bad.Target = "https://other.tacra.example"
	if _, err := Open(&b, cek, bad); !errors.Is(err, ErrAAD) {
		t.Fatalf("other Target: %v", err)
	}
}

// A bundle sealed here is opened by the reference implementation's Attester, when its environment is present.
func TestReferenceOpensGoBundle(t *testing.T) {
	py := filepath.Join(os.Getenv("HOME"), "dev/tacra-est/.venv/bin/python3")
	if _, err := os.Stat(py); err != nil {
		t.Skip("reference implementation environment not present")
	}
	sender, err := GenerateSenderKeys()
	if err != nil {
		t.Fatal(err)
	}
	cek, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cekSPKI, _ := x509.MarshalPKIXPublicKey(cek.PublicKey())
	vaultSPKI, _ := sender.PublicSPKI(KEMX25519)
	handle := []byte("0123456789abcdef0123456789abcdef")
	aad := AAD{GroupID: strings.Repeat("ab", 32), RRPID: "https://vault1.tacra.example", Target: "https://ledger.tacra.example",
		Handle: handle, CredentialHint: "workload.tacra.example"}
	want := Content{CredentialItems: []Item{{Type: "api-key", Format: "text", Value: "k-Ω-\u007f-✓"}},
		Metadata: map[string]any{"validity_seconds": 3600.0}}
	b, err := Seal(sender, cekSPKI, aad, want)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	f := map[string]any{"cek_x25519": enc(cek.Bytes()), "vault_spki": enc(vaultSPKI), "rrp_id": aad.RRPID,
		"target": aad.Target, "handle": enc(handle), "credential_hint": aad.CredentialHint, "bundle": b}
	path := filepath.Join(t.TempDir(), "go-bundle.json")
	raw, _ := json.Marshal(f)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, "testdata/xcheck.py", "open", path).CombinedOutput()
	if err != nil {
		t.Fatalf("reference Attester refused the bundle: %v\n%s", err, out)
	}
	var got Content
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reference Attester read %+v, want %+v", got, want)
	}
}

// P-256 CEKs, as the SIG's CAI generates today, use DHKEM(P-256).
func TestP256RoundTrip(t *testing.T) {
	sender, _ := GenerateSenderKeys()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cekSPKI, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	cek, _ := k.ECDH()
	vaultSPKI, _ := sender.PublicSPKI(KEMP256)
	aad := AAD{GroupID: "g", RRPID: "https://vault1.tacra.example", Target: "https://ledger.tacra.example"}
	b, err := Seal(sender, cekSPKI, aad, Content{CredentialItems: []Item{{Type: "psk", Value: "s"}}})
	if err != nil {
		t.Fatal(err)
	}
	if b.Suite.KEM != KEMP256 {
		t.Fatalf("suite %s", b.Suite.KEM)
	}
	c, err := Open(b, cek, Expect{RRPID: aad.RRPID, Target: aad.Target, VaultSPKI: vaultSPKI})
	if err != nil || c.CredentialItems[0].Value != "s" {
		t.Fatalf("%v %+v", err, c)
	}
	// a container sealed by someone else who saw CEKpub is refused
	intruder, _ := GenerateSenderKeys()
	forged, _ := Seal(intruder, cekSPKI, aad, Content{CredentialItems: []Item{{Type: "psk", Value: "x"}}})
	if _, err := Open(forged, cek, Expect{RRPID: aad.RRPID, Target: aad.Target, VaultSPKI: vaultSPKI}); !errors.Is(err, ErrOrigin) {
		t.Fatalf("container from another sender: %v", err)
	}
}

// Canonical matches Python's json.dumps(sort_keys=True, separators=(",", ":")).
func TestCanonicalMatchesReference(t *testing.T) {
	got, err := Canonical(map[string]any{"b": "Ω\u007f✓\U0001F600<&>", "a": []any{1, true, nil}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":[1,true,null],"b":"\u03a9` + "\u007f" + `\u2713\ud83d\ude00<&>"}`
	if string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
