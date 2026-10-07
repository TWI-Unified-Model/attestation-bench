package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/gateway"
)

const hint = "payments.workload.tacra.example"

// csrFor is the workload's CSR for the name cn (and the URIs given), with a key of its own, as the CAI makes it.
func csrFor(t *testing.T, cn string, uris ...string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	for _, u := range uris {
		p, _ := url.Parse(u)
		tpl.URIs = append(tpl.URIs, p)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, k)
	if err != nil {
		t.Fatal(err)
	}
	return der, k
}

func csrWithOrg(t *testing.T, cn string) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn, Organization: []string{"Payments Operations"}}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// approvedLaunches is the bench's approved SEV-SNP launch measurements (trust/approved-launches.json), as hex: the
// values real hardware reports, Google Cloud's first and AWS's second.
func approvedLaunches(t *testing.T) (string, string) {
	t.Helper()
	b, err := os.ReadFile("../../../trust/approved-launches.json")
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		SEVSNP []struct {
			Measurement string `json:"measurement"`
		} `json:"sev-snp"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	if len(a.SEVSNP) < 2 {
		t.Fatalf("%d approved SEV-SNP launches; the test needs two", len(a.SEVSNP))
	}
	return a.SEVSNP[0].Measurement, a.SEVSNP[1].Measurement
}

// TestAssignIdentity is the name rule alone (tacra-est 14-DECISIONS-FROM-EVIDENCE.md, decision 1): the CA assigns
// an identity the attested launch may hold; the CSR needs no name when that is one identity and names one when it
// is several; a hint must be the identity assigned. The launches are the approved ones; the whole enrolment, through
// step-ca, runs in every hardware run.
func TestAssignIdentity(t *testing.T) {
	meas, other := approvedLaunches(t)
	const batch, ledger = "batch.workload.tacra.example", "ledger.workload.tacra.example"
	one := &gateway.Target{Identities: map[string]*gateway.Identity{
		hint:   {SANs: []string{hint}, Measurements: []string{meas}},
		ledger: {SANs: []string{ledger}, Measurements: []string{other}},
	}}
	two := &gateway.Target{Identities: map[string]*gateway.Identity{
		hint:   {SANs: []string{hint}, Measurements: []string{meas}},
		batch:  {SANs: []string{batch}, Measurements: []string{meas}},
		ledger: {SANs: []string{ledger}, Measurements: []string{other}},
	}}
	parse := func(der []byte) *x509.CertificateRequest {
		c, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	csr := func(cn string, uris ...string) *x509.CertificateRequest {
		der, _ := csrFor(t, cn, uris...)
		return parse(der)
	}
	m, _ := hex.DecodeString(meas)
	for _, c := range []struct {
		name   string
		t      *gateway.Target
		csr    *x509.CertificateRequest
		hint   string
		assign string // "" when refused
		code   string
	}{
		{"one identity, a CSR without a name, no hint", one, csr(""), "", hint, ""},
		{"one identity, a CSR without a name, the same hint", one, csr(""), hint, hint, ""},
		{"one identity, a CSR without a name, a hint for another", one, csr(""), batch, "", "credential-hint"},
		{"one identity, the CSR names it", one, csr(hint), "", hint, ""},
		{"one identity, the CSR names one of another launch", one, csr(ledger), "", "", "identity"},
		{"two identities, a CSR without a name", two, csr(""), hint, "", "csr-names"},
		{"two identities, the CSR names one, no hint", two, csr(batch), "", batch, ""},
		{"two identities, the CSR names one, the hint the other", two, csr(hint), batch, "", "credential-hint"},
		{"a CSR subject with an attribute besides the name", two, parse(csrWithOrg(t, hint)), "", "", "csr-names"},
		{"a CSR that asks for a URI of its own", one, csr("", "spiffe://tacra.example/admin"), "", "", "csr-names"},
	} {
		name, id, err := assignIdentity(c.t, m, c.csr, c.hint)
		if c.assign != "" {
			if err != nil || name != c.assign || id == nil || id.SANs[0] != c.assign {
				t.Errorf("%s: got %q %v, want %q", c.name, name, err, c.assign)
			}
			continue
		}
		var e *gateway.Error
		if !errors.As(err, &e) || e.Status != http.StatusForbidden || e.Code != c.code {
			t.Errorf("%s: got %q %v, want 403 %s", c.name, name, err, c.code)
		}
	}
}
