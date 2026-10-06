package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTrip(t *testing.T) {
	priv := newKey(t)
	k, err := FromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := ParsePrivate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(priv) {
		t.Fatal("the private key read back is not the one written")
	}
	pub, err := ParsePublic(raw) // a private JWK's public half
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(&priv.PublicKey) {
		t.Fatal("the public key read back is not the one written")
	}
	pk, err := FromPublic(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if pk.D != "" || pk.X != k.X || pk.Y != k.Y {
		t.Fatalf("public JWK %+v, want the private one's x and y and no d", pk)
	}
}

// Every refusal names what is wrong; none accepts a key it cannot vouch for.
func TestRefuses(t *testing.T) {
	good, err := FromPrivate(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	other, err := FromPrivate(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	short := good
	short.X = b64.EncodeToString(make([]byte, 31)) // RFC 7518 6.2.1.2: the full 32 octets
	offCurve := good
	offCurve.Y = b64.EncodeToString(append(make([]byte, 31), 1))
	mismatched := good
	mismatched.D = other.D
	for _, c := range []struct {
		name string
		key  Key
		want string
	}{
		{"wrong curve", Key{Kty: "EC", Crv: "P-384", X: good.X, Y: good.Y, D: good.D}, "want EC/P-256"},
		{"not EC", Key{Kty: "OKP", Crv: "P-256", X: good.X, Y: good.Y, D: good.D}, "want EC/P-256"},
		{"short coordinate", short, "32 octets"},
		{"not base64url", Key{Kty: "EC", Crv: "P-256", X: "**", Y: good.Y, D: good.D}, "32 octets"},
		{"off the curve", offCurve, "not a point on P-256"},
		{"no d", Key{Kty: "EC", Crv: "P-256", X: good.X, Y: good.Y}, "d must be"},
		{"d of another key", mismatched, "not the public key of d"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.key.Private()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Private() = %v, want an error containing %q", err, c.want)
			}
		})
	}
	if _, err := Parse([]byte("{")); err == nil {
		t.Fatal("Parse accepted invalid JSON")
	}
	if _, err := FromPublic(nil); err == nil {
		t.Fatal("FromPublic accepted nil")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromPublic(&p384.PublicKey); err == nil {
		t.Fatal("FromPublic accepted a P-384 key")
	}
}
