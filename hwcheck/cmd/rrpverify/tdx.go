package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/abi"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
)

// TDX Evidence. The veraison-services fork has no TDX scheme, so the RRP verifies the quote with
// github.com/google/go-tdx-guest (PCK chain to Intel's SGX root CA, the QE report, TCB info and QE identity from
// Intel PCS, revocation lists) and compares REPORTDATA with the binding value itself.

const reportDataRefusal = "REPORTDATA differs from the binding value"

// cachingGetter fetches each Intel PCS document once per run.
type cachingGetter struct {
	inner trust.HTTPSGetter
	mu    sync.Mutex
	m     map[string]getResult
}

type getResult struct {
	h   map[string][]string
	b   []byte
	err error
}

func (g *cachingGetter) Get(url string) (map[string][]string, []byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r, ok := g.m[url]; ok {
		return r.h, r.b, r.err
	}
	h, b, err := g.inner.Get(url)
	g.m[url] = getResult{h, b, err}
	return h, b, err
}

var pcsGetter = &cachingGetter{inner: trust.DefaultHTTPSGetter(), m: map[string]getResult{}}

func tokenProvider(token []byte) string {
	var t map[string]any
	if cborUnmarshal(token, &t) != nil {
		return ""
	}
	p, _ := t["provider"].(string)
	return strings.TrimSpace(p)
}

func tokenOutblob(token []byte) []byte {
	var t map[string]any
	if cborUnmarshal(token, &t) != nil {
		return nil
	}
	b, _ := t["outblob"].([]byte)
	return b
}

// verifyTDX checks the quote (roots nil: Intel's SGX root CA as embedded in go-tdx-guest) and that REPORTDATA
// is the binding value.
func verifyTDX(token, bv []byte, roots *x509.CertPool) error {
	quote := tokenOutblob(token)
	if len(quote) < 48+584 {
		return errors.New("no TDX quote in the token")
	}
	q, err := abi.QuoteToProto(quote)
	if err != nil {
		return fmt.Errorf("quote: %w", err)
	}
	opts := &tdxverify.Options{CheckRevocations: true, GetCollateral: true, Getter: pcsGetter, Now: time.Now(),
		TrustedRoots: roots}
	if err := tdxverify.TdxQuote(q, opts); err != nil {
		return fmt.Errorf("quote: %w", err)
	}
	if !bytes.Equal(quote[48+520:48+584], bv) {
		return errors.New(reportDataRefusal)
	}
	return nil
}

// tdxMeasurements are the TD quote body fields an appraisal of "the same launch" compares.
func tdxMeasurements(token []byte) map[string][]byte {
	q := tokenOutblob(token)
	if len(q) < 48+584 {
		return nil
	}
	b := q[48 : 48+584]
	return map[string][]byte{
		"MRSEAM": b[16:64], "TDATTRIBUTES": b[120:128], "XFAM": b[128:136], "MRTD": b[136:184],
		"MRCONFIGID": b[184:232], "MROWNER": b[232:280], "MROWNERCONFIG": b[280:328],
		"RTMR0": b[328:376], "RTMR1": b[376:424], "RTMR2": b[424:472], "RTMR3": b[472:520],
	}
}

// matchTDX returns the fields that differ from the reference, sorted.
func matchTDX(ref, ev map[string][]byte) []string {
	var diff []string
	for k, v := range ref {
		if !bytes.Equal(ev[k], v) {
			diff = append(diff, k)
		}
	}
	sort.Strings(diff)
	return diff
}

// otherRoots is a CA pool holding one freshly made self-signed certificate: a root that is not Intel's.
func otherRoots() *x509.CertPool {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "not Intel"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	must(err)
	c, err := x509.ParseCertificate(der)
	must(err)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return pool
}

// tdxPreflight checks a TDX quote captured earlier (raw outblob) three ways: as it is, with its own REPORTDATA as
// the expected value (must pass); with another expected value (REPORTDATA refusal); under a root that is not
// Intel's (chain refusal).
func tdxPreflight(args []string) {
	if len(args) != 1 {
		must(errors.New("usage: rrpverify tdx-preflight QUOTE.bin"))
	}
	quote, err := os.ReadFile(args[0])
	must(err)
	token, err := cborMarshal(map[string]any{"outblob": quote, "provider": "tdx_guest"})
	must(err)
	rd := append([]byte(nil), quote[48+520:48+584]...)
	other := append([]byte{rd[0] ^ 1}, rd[1:]...)
	for _, c := range []struct {
		name  string
		bv    []byte
		roots *x509.CertPool
	}{{"own REPORTDATA", rd, nil}, {"other expected value", other, nil}, {"root not Intel's", rd, otherRoots()}} {
		t0 := time.Now()
		err := verifyTDX(token, c.bv, c.roots)
		fmt.Printf("%-22s %8.1f ms  %v\n", c.name, float64(time.Since(t0).Microseconds())/1000, errOrValid(err))
	}
}

func errOrValid(err error) string {
	if err == nil {
		return "VALID"
	}
	return "refused: " + err.Error()
}
