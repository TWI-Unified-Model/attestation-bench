// Package mtls is the mutual TLS of the channels between the bench's infrastructure components: the EST server, the
// RRP gateways, the verifiers, step-ca and HashiCorp Vault (tacra-est 10-REQUIREMENTS-MATRIX N23, DR-D04: "Channels
// between infrastructure components (EST server, Verifier, CA, Vault, key manager) are mutually authenticated and
// encrypted with current TLS versions and suites"; X9 asks CA-RA communications to be mutually authenticated, KMIP
// asks TLS mutual authentication). A server takes only callers that present a certificate of its client CA, and lets
// only the identities it lists run its protocol; a client presents its own certificate. TLS 1.3 throughout.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
)

// pool reads the PEM certificates of path.
func pool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("mtls: no CA certificate in %s", path)
	}
	return p, nil
}

// ServerTLS is a listener's TLS: 1.3, and, with clientCA, a client certificate of that CA required and verified.
func ServerTLS(clientCA string) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS13}
	if clientCA == "" {
		return c, nil
	}
	p, err := pool(clientCA)
	if err != nil {
		return nil, err
	}
	c.ClientAuth, c.ClientCAs = tls.RequireAndVerifyClientCert, p
	return c, nil
}

// ClientTLS is TLS 1.3 to a server certified by caPath, presenting the certificate and key of certPath and keyPath
// when both are given.
func ClientTLS(caPath, certPath, keyPath string) (*tls.Config, error) {
	p, err := pool(caPath)
	if err != nil {
		return nil, err
	}
	c := &tls.Config{RootCAs: p, MinVersion: tls.VersionTLS13}
	if certPath != "" || keyPath != "" {
		if certPath == "" || keyPath == "" {
			return nil, errors.New("mtls: a client certificate needs both its certificate and its key")
		}
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("mtls: client certificate: %w", err)
		}
		c.Certificates = []tls.Certificate{pair}
	}
	return c, nil
}

// Names are the identities the verified client certificate of r gives: its DNS names and URIs; nil when the caller
// presented none.
func Names(r *http.Request) []string {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	leaf := r.TLS.VerifiedChains[0][0]
	names := slices.Clone(leaf.DNSNames)
	for _, u := range leaf.URIs {
		names = append(names, u.String())
	}
	return names
}

// Authorize lets a request through to h only when its caller presented a verified client certificate and, if
// allowed is not empty, that certificate names one of allowed; otherwise it answers 403 with code "client". It logs
// each refusal. With required false (a deployment without a client CA) it lets every request through.
func Authorize(required bool, allowed []string, h http.Handler) http.Handler {
	if !required {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		names := Names(r)
		ok := len(names) > 0 && (len(allowed) == 0 || slices.ContainsFunc(names, func(n string) bool {
			return slices.Contains(allowed, n)
		}))
		if !ok {
			log.Printf("client refused: %s %s from %s, certificate names %v", r.Method, r.URL.Path, r.RemoteAddr, names)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"client","detail":"the caller is not one this service takes"}` + "\n"))
			return
		}
		h.ServeHTTP(w, r)
	})
}
