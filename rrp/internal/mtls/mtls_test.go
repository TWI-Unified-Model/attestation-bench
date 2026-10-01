package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCA issues certificates for the tests: a server certificate for 127.0.0.1 and client certificates by name.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	dir  string
	path string
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	dir := t.TempDir()
	path := filepath.Join(dir, name+".crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, dir: dir, path: path}
}

// issue writes a certificate and key for name (a DNS name; "127.0.0.1" gives an IP address) and returns their paths.
func (c *testCA) issue(t *testing.T, name string, usage x509.ExtKeyUsage) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage},
		KeyUsage: x509.KeyUsageDigitalSignature}
	if ip := net.ParseIP(name); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	cp, kp := filepath.Join(c.dir, name+".crt"), filepath.Join(c.dir, name+".key")
	_ = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	return cp, kp
}

// TestMutualTLS: a server with a client CA takes only callers with a certificate of that CA, and runs its protocol
// only for the identities it lists; TLS 1.2 is refused.
func TestMutualTLS(t *testing.T) {
	infra := newTestCA(t, "infra")
	other := newTestCA(t, "other")
	srvCert, srvKey := infra.issue(t, "127.0.0.1", x509.ExtKeyUsageServerAuth)
	estCert, estKey := infra.issue(t, "est-server.bench", x509.ExtKeyUsageClientAuth)
	opCert, opKey := infra.issue(t, "operator.bench", x509.ExtKeyUsageClientAuth)
	strangerCert, strangerKey := other.issue(t, "est-server.bench", x509.ExtKeyUsageClientAuth)

	srvTLS, err := ServerTLS(infra.path)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	srvTLS.Certificates = []tls.Certificate{pair}
	mux := http.NewServeMux()
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.Handle("/protocol", Authorize(true, []string{"est-server.bench"}, ok))
	mux.Handle("/public", Authorize(true, nil, ok))
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = srvTLS
	srv.StartTLS()
	defer srv.Close()

	get := func(cert, key, path string, maxVersion uint16) (int, error) {
		c, err := ClientTLS(infra.path, cert, key)
		if err != nil {
			return 0, err
		}
		if maxVersion != 0 {
			c.MinVersion, c.MaxVersion = tls.VersionTLS12, maxVersion
		}
		resp, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: c}, Timeout: 5 * time.Second}).Get(srv.URL + path)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		return resp.StatusCode, nil
	}

	if st, err := get(estCert, estKey, "/protocol", 0); err != nil || st != 200 {
		t.Errorf("the listed caller: %d %v, want 200", st, err)
	}
	if st, err := get(opCert, opKey, "/protocol", 0); err != nil || st != 403 {
		t.Errorf("a caller of the client CA that is not listed: %d %v, want 403", st, err)
	}
	if st, err := get(opCert, opKey, "/public", 0); err != nil || st != 200 {
		t.Errorf("a caller of the client CA on a route for any of them: %d %v, want 200", st, err)
	}
	if _, err := get("", "", "/public", 0); err == nil {
		t.Error("a caller without a certificate got through the handshake")
	}
	if _, err := get(strangerCert, strangerKey, "/protocol", 0); err == nil {
		t.Error("a certificate of another CA, with the listed name, got through the handshake")
	}
	if _, err := get(estCert, estKey, "/protocol", tls.VersionTLS12); err == nil {
		t.Error("TLS 1.2 was accepted")
	}
	if _, err := ClientTLS(infra.path, estCert, ""); err == nil {
		t.Error("a client certificate without its key was accepted")
	}
}

// TestNoClientCA: without a client CA a server takes callers without certificates, and Authorize lets them through.
func TestNoClientCA(t *testing.T) {
	c, err := ServerTLS("")
	if err != nil || c.ClientAuth != tls.NoClientCert || c.MinVersion != tls.VersionTLS13 {
		t.Fatalf("ServerTLS(\"\"): %+v %v", c, err)
	}
	rec := httptest.NewRecorder()
	Authorize(false, []string{"est-server.bench"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 204 {
		t.Fatalf("status %d, want 204", rec.Code)
	}
}
