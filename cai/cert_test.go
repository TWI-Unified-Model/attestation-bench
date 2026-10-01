package cai

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// certAuthority issues test certificates in the profile the CAI checks (cert.go).
type certAuthority struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newCertAuthority(name string) *certAuthority {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &certAuthority{key: key, cert: cert}
}

// testCA is the CA of the tests' fake CAS.
var testCA = newCertAuthority("test CA")

// mint issues a certificate for the CSR's key, named name (or the CSR's common name), in the profile; edit, if any,
// changes the template first.
func (a *certAuthority) mint(t *testing.T, csrDER []byte, name string, edit ...func(*x509.Certificate)) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if name == "" {
		name = csr.Subject.CommonName
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	for _, e := range edit {
		e(tpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, csr.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestCertificateChecks (tacra-est N15): with the CA held for the RRP, an issued certificate must chain to it as a
// client certificate, carry a critical keyUsage with digitalSignature alone, be no CA, remain valid no longer than
// the CAI accepts, and carry the name the CSR asked for; always, it must be for the CSK.
func TestCertificateChecks(t *testing.T) {
	const rrp, name = "https://ca1.tacra.example", "payments.workload.tacra.example"
	c := &Client{caAnchors: map[string]*x509.CertPool{}}
	WithCertificateAuthority(rrp, testCA.cert)(c)
	WithCertificateMaxValidity(time.Hour)(c)
	csk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, csk)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, other)
	foreign := newCertAuthority("the conduit's own CA")

	if err := c.checkCertificate(testCA.mint(t, csrDER, ""), &csk.PublicKey, rrp, name); err != nil {
		t.Fatalf("a certificate in the profile from the held CA: %v", err)
	}
	for _, tc := range []struct {
		name string
		der  []byte
		want string
	}{
		{"another key", testCA.mint(t, otherCSR, ""), "not for the CSK"},
		{"a CA the CAI does not hold", foreign.mint(t, csrDER, ""), "not issued under a CA"},
		{"keyUsage with keyEncipherment too", testCA.mint(t, csrDER, "", func(c *x509.Certificate) {
			c.KeyUsage |= x509.KeyUsageKeyEncipherment
		}), "digitalSignature alone"},
		{"no keyUsage", testCA.mint(t, csrDER, "", func(c *x509.Certificate) { c.KeyUsage = 0 }), "present false"},
		{"serverAuth without clientAuth", testCA.mint(t, csrDER, "", func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}), "not issued under a CA"},
		{"a CA certificate", testCA.mint(t, csrDER, "", func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true }),
			"a CA certificate"},
		{"valid for a day", testCA.mint(t, csrDER, "", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(24 * time.Hour) }),
			"beyond the 1h0m0s"},
		{"another name", testCA.mint(t, csrDER, "batch.workload.tacra.example"), "which the CSR asked for"},
	} {
		err := c.checkCertificate(tc.der, &csk.PublicKey, rrp, name)
		if !errors.Is(err, ErrCertificate) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want a refusal with %q", tc.name, err, tc.want)
		}
	}
	// with no CA held for the RRP, only the key is checked, as before N15
	if err := c.checkCertificate(foreign.mint(t, csrDER, ""), &csk.PublicKey, "https://ca2.tacra.example", name); err != nil {
		t.Errorf("no CA held: %v", err)
	}
	if err := c.checkCertificate(testCA.mint(t, otherCSR, ""), &csk.PublicKey, "https://ca2.tacra.example", name); err == nil {
		t.Error("no CA held: a certificate for another key was taken")
	}
}
