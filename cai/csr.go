package cai

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/url"

	"github.com/TWI-Unified-Model/tacra/platform"
)

// createCSR makes the CSR that proves possession of the CSK. Given a name
// (the Credential Hint, with WithCSRNamingHint) the CSR carries only that as
// its common name and leaves the other names to the Credential Authority's
// policy; otherwise it names the Target.
func createCSR(csk *platform.KeyPair, target, name string) ([]byte, error) {
	signer, err := csk.Signer()
	if err != nil {
		return nil, fmt.Errorf("cai: CSR: %w", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: truncateCN(target)},
	}
	if name != "" {
		tmpl.Subject.CommonName = truncateCN(name)
	} else if u, err := url.Parse(target); err == nil && u.Scheme != "" && u.Host != "" {
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		return nil, fmt.Errorf("cai: CSR: %w", err)
	}
	return der, nil
}

func truncateCN(s string) string {
	const maxCN = 64
	if len(s) <= maxCN {
		return s
	}
	return s[:maxCN]
}
