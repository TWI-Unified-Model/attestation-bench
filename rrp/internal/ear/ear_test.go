package ear

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testdata holds an EAR from the test bench's Veraison (native deployment, own signing key) for SEV-SNP Evidence of
// the GCP run 20260928T190538Z, with the key that service published and the binding value used as nonce.
func load(t *testing.T) (*Verifier, string, []byte, []byte) {
	t.Helper()
	jwk, err := os.ReadFile("testdata/veraison-ear-key.jwk")
	if err != nil {
		t.Fatal(err)
	}
	key, err := KeyFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	jws, _ := os.ReadFile("testdata/ear-gcp-sevsnp.jws")
	bvHex, _ := os.ReadFile("testdata/binding-value.hex")
	mHex, _ := os.ReadFile("testdata/measurement.hex")
	bv, _ := hex.DecodeString(strings.TrimSpace(string(bvHex)))
	m, _ := hex.DecodeString(strings.TrimSpace(string(mHex)))
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(string(jws), ".")[1])
	iat := time.Unix(0, 0)
	if i := bytes.Index(payload, []byte(`"iat":`)); i >= 0 {
		var n int64
		for _, c := range payload[i+6:] {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int64(c-'0')
		}
		iat = time.Unix(n, 0)
	}
	v := &Verifier{Keys: []TrustedKey{{Key: key, Submods: []string{"SEVSNP"}}}, MaxAge: 2 * time.Minute,
		Skew: 5 * time.Second, Now: func() time.Time { return iat.Add(10 * time.Second) }}
	return v, strings.TrimSpace(string(jws)), bv, m
}

func TestRealEARIsAccepted(t *testing.T) {
	v, jws, bv, m := load(t)
	res, err := v.Verify(jws, bv)
	if err != nil {
		t.Fatal(err)
	}
	if res.Submod != "SEVSNP" || res.Status != "affirming" {
		t.Fatalf("got %s %s", res.Submod, res.Status)
	}
	if !bytes.Equal(res.Measurement, m) {
		t.Fatalf("annotated measurement %x, the report's is %x", res.Measurement, m)
	}
}

func TestEARRefusals(t *testing.T) {
	v, jws, bv, _ := load(t)
	other := append([]byte{bv[0] ^ 1}, bv[1:]...)
	if _, err := v.Verify(jws, other); !errors.Is(err, ErrNonce) {
		t.Fatalf("other binding value: %v", err)
	}
	parts := strings.Split(jws, ".")
	p, _ := base64.RawURLEncoding.DecodeString(parts[1])
	p = bytes.Replace(p, []byte(`"affirming"`), []byte(`"affirminG"`), 1)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(p) + "." + parts[2]
	if _, err := v.Verify(tampered, bv); !errors.Is(err, ErrSignature) {
		t.Fatalf("edited payload: %v", err)
	}
	late := *v
	late.Now = func() time.Time { return v.Now().Add(time.Hour) }
	if _, err := late.Verify(jws, bv); !errors.Is(err, ErrStale) {
		t.Fatalf("an hour later: %v", err)
	}
	// the key signs for SEVSNP only: an EAR it signed is not taken as TDX results
	tdx := *v
	tdx.Keys = []TrustedKey{{Key: v.Keys[0].Key, Submods: []string{"TDX"}}}
	if _, err := tdx.Verify(jws, bv); !errors.Is(err, ErrNotAffirming) {
		t.Fatalf("submodule not allowed for the key: %v", err)
	}
}

// TestProvisionedKey: an RRP reads each verifier's key from the file its operator provisioned, a public JWK or PEM,
// and refuses a file that holds a private key; Only keeps the keys of the verifiers a Target takes (N24).
func TestProvisionedKey(t *testing.T) {
	v, jws, bv, _ := load(t)
	want := v.Keys[0].Key
	dir := t.TempDir()
	jwkPath := "testdata/veraison-ear-key.jwk"
	if k, err := LoadKey(jwkPath); err != nil || !k.Equal(want) {
		t.Fatalf("public JWK: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(want)
	if err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(dir, "veraison.pem")
	_ = os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)
	if k, err := LoadKey(pemPath); err != nil || !k.Equal(want) {
		t.Fatalf("PEM: %v", err)
	}
	priv := filepath.Join(dir, "private.jwk")
	_ = os.WriteFile(priv, []byte(`{"kty":"EC","crv":"P-256","x":"AA","y":"AA","d":"AA"}`), 0o600)
	if _, err := LoadKey(priv); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("a private JWK was taken: %v", err)
	}
	if _, err := LoadKey(filepath.Join(dir, "absent.jwk")); err == nil {
		t.Fatal("a missing file was taken")
	}

	v.Keys[0].Name = "veraison"
	if _, err := v.Only([]string{"veraison", "tdx"}).Verify(jws, bv); err != nil {
		t.Fatalf("the Target takes the verifier that signed: %v", err)
	}
	if _, err := v.Only([]string{"tdx"}).Verify(jws, bv); !errors.Is(err, ErrSignature) {
		t.Fatalf("the Target does not take the verifier that signed: %v, want ErrSignature", err)
	}
	if _, err := v.Only(nil).Verify(jws, bv); !errors.Is(err, ErrSignature) {
		t.Fatalf("a Target that takes no verifier: %v, want ErrSignature", err)
	}
	if len(v.Keys) != 1 {
		t.Fatal("Only changed the Verifier it was called on")
	}
}
