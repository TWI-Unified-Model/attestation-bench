package ear

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
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
	v := &Verifier{Key: key, MaxAge: 2 * time.Minute, Skew: 5 * time.Second, Submods: []string{"SEVSNP"},
		Now: func() time.Time { return iat.Add(10 * time.Second) }}
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
	tdx := *v
	tdx.Submods = []string{"TDX"}
	if _, err := tdx.Verify(jws, bv); !errors.Is(err, ErrNotAffirming) {
		t.Fatalf("submodule not accepted: %v", err)
	}
}
