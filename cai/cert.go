package cai

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ErrCertificate is a refusal of the certificate Enrollment returned.
var ErrCertificate = errors.New("cai: the issued certificate")

var oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

// WithCertificateAuthority provisions the certificates of the Credential Authority the CAI holds for rrpID, the RRP
// it binds for Enrollment (tacra-est N15; DR-B09: the Attester's side "holds its own trust anchors and validates what
// comes back against them"). A certificate Enrollment returns must then chain to one of them, as a client certificate,
// and keep the profile (checkCertificate). Without one only the key is checked.
func WithCertificateAuthority(rrpID string, certs ...*x509.Certificate) Option {
	return func(c *Client) {
		pool := c.caAnchors[rrpID]
		if pool == nil {
			pool = x509.NewCertPool()
			c.caAnchors[rrpID] = pool
		}
		for _, cert := range certs {
			pool.AddCert(cert)
		}
	}
}

// WithCertificateMaxValidity is the longest an issued certificate may remain valid (the bank profile: an hour).
func WithCertificateMaxValidity(d time.Duration) Option {
	return func(c *Client) { c.certMaxValidity = d }
}

// checkCertificate takes the certificate Enrollment returned (DER) only if it is for the CSK, and, with a CA held for
// rrpID: it chains to that CA with clientAuth among its extended key usages; it carries a critical keyUsage with
// digitalSignature alone (DR-A04; X9 CP 7.1.2, the minimum usages); it is no CA; it remains valid no longer than the
// CAI accepts; and it carries name, when the CSR asked for one.
func (c *Client) checkCertificate(der []byte, csk crypto.PublicKey, rrpID, name string) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCertificate, err)
	}
	want, err := x509.MarshalPKIXPublicKey(csk)
	if err != nil {
		return fmt.Errorf("%w: CSK: %v", ErrCertificate, err)
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, want) {
		return fmt.Errorf("%w is not for the CSK", ErrCertificate)
	}
	pool := c.caAnchors[rrpID]
	if pool == nil {
		return nil
	}
	now := time.Now()
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("%w is not issued under a CA the CAI holds for %s: %v", ErrCertificate, rrpID, err)
	}
	critical := false
	present := slices.ContainsFunc(cert.Extensions, func(e pkix.Extension) bool {
		if e.Id.Equal(oidKeyUsage) {
			critical = e.Critical
			return true
		}
		return false
	})
	if !present || !critical || cert.KeyUsage != x509.KeyUsageDigitalSignature {
		return fmt.Errorf("%w: keyUsage %#x (present %v, critical %v); the profile asks a critical digitalSignature alone",
			ErrCertificate, int(cert.KeyUsage), present, critical)
	}
	if cert.IsCA {
		return fmt.Errorf("%w is a CA certificate", ErrCertificate)
	}
	if c.certMaxValidity > 0 && cert.NotAfter.Sub(now) > c.certMaxValidity+time.Minute {
		return fmt.Errorf("%w is valid until %s, beyond the %s this CAI accepts", ErrCertificate,
			cert.NotAfter.UTC().Format(time.RFC3339), c.certMaxValidity)
	}
	if name != "" && !slices.Contains(cert.DNSNames, name) {
		return fmt.Errorf("%w names %v, not %s, which the CSR asked for", ErrCertificate, cert.DNSNames, name)
	}
	return nil
}
