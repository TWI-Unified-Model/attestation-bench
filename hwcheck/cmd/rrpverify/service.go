package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/tacra/platform"
)

// veraisonService is a deployed Veraison verification service: the RRP opens a challenge-response session whose
// nonce is the binding value it recomputed, submits the Evidence, and accepts only an EAR that is signed by the
// service's key, reports that nonce, and is affirming.
type veraisonService struct {
	base   string
	client *http.Client
	key    *ecdsa.PublicKey
	jwk    []byte // the key as the service published it, a public JWK: kept with the EARs (-save-ears)
	submod string // the EAR submodule read: SEVSNP (Veraison)
}

func newVeraisonService(base, caPath, certPath, keyPath string) (*veraisonService, error) {
	// The deployed Veraison takes callers with a certificate of the bench only (mutual TLS, N23), so this RRP presents
	// its own, as the gateways do.
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no CA certificate in " + caPath)
	}
	v := &veraisonService{base: strings.TrimRight(base, "/"),
		client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}}}
	resp, err := v.client.Get(v.base + "/.well-known/veraison/verification")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var wk struct {
		Key struct {
			Kty, Crv, X, Y string
		} `json:"ear-verification-key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wk); err != nil {
		return nil, err
	}
	if wk.Key.Kty != "EC" || wk.Key.Crv != "P-256" {
		return nil, fmt.Errorf("EAR key %s/%s, want EC/P-256", wk.Key.Kty, wk.Key.Crv)
	}
	x, err1 := base64.RawURLEncoding.DecodeString(wk.Key.X)
	y, err2 := base64.RawURLEncoding.DecodeString(wk.Key.Y)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("EAR key coordinates are not 32 octets of base64url each")
	}
	if v.key, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...)); err != nil {
		return nil, fmt.Errorf("EAR key is not a P-256 point: %w", err)
	}
	v.jwk, _ = json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": wk.Key.X, "y": wk.Key.Y})
	return v, nil
}

// earResult is what the RRP reads from a verified EAR.
type earResult struct {
	Status string
	Nonce  []byte
	JWS    string // the EAR as received
}

// verify runs one challenge-response session and returns the verified EAR's status for the scheme's submodule.
func (v *veraisonService) verify(token, nonce []byte) (*earResult, error) {
	q := url.Values{"nonce": {base64.URLEncoding.EncodeToString(nonce)}}
	resp, err := v.client.Post(v.base+"/challenge-response/v1/newSession?"+q.Encode(), "application/json", nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusCreated || loc == "" {
		return nil, fmt.Errorf("newSession: HTTP %d", resp.StatusCode)
	}
	if !strings.HasPrefix(loc, "http") {
		loc = v.base + "/challenge-response/v1/" + strings.TrimPrefix(loc, "/")
	}
	defer func() {
		req, _ := http.NewRequest(http.MethodDelete, loc, nil)
		if r, err := v.client.Do(req); err == nil {
			r.Body.Close()
		}
	}()
	req, err := http.NewRequest(http.MethodPost, loc, bytes.NewReader(token))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", platform.TSMReportMediaTypeCBOR)
	req.Header.Set("Accept", "application/vnd.veraison.challenge-response-session+json")
	resp, err = v.client.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var session struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, fmt.Errorf("session: HTTP %d: %s", resp.StatusCode, short(string(body)))
	}
	if session.Status != "complete" || session.Result == "" {
		return nil, fmt.Errorf("session %s (HTTP %d): %s", session.Status, resp.StatusCode, short(string(body)))
	}
	return v.checkEAR(session.Result)
}

// checkEAR verifies the JWS (ES256) under the service's key and extracts the submodule's status and eat_nonce.
func (v *veraisonService) checkEAR(jws string) (*earResult, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, errors.New("EAR is not a compact JWS")
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var h struct{ Alg string }
	if json.Unmarshal(hdr, &h) != nil || h.Alg != "ES256" {
		return nil, fmt.Errorf("EAR alg %q, want ES256", h.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, errors.New("EAR signature is not a 64-octet ES256 signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(v.key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, errors.New("EAR signature does not verify under the service's key")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims struct {
		Nonce   string `json:"eat_nonce"`
		Submods map[string]struct {
			Status string `json:"ear.status"`
		} `json:"submods"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	sub, ok := claims.Submods[v.submod]
	if !ok {
		return nil, fmt.Errorf("EAR has no %s submodule", v.submod)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(claims.Nonce, "="))
	if err != nil {
		return nil, errors.New("EAR eat_nonce is not base64url")
	}
	return &earResult{Status: sub.Status, Nonce: nonce, JWS: jws}, nil
}

// benchHome is the running bench's directory, as in scripts/lib.sh: BENCH_HOME, or TACRA_BENCH, or ~/.attestation-bench.
func benchHome() string {
	if d := os.Getenv("BENCH_HOME"); d != "" {
		return d
	}
	if d := os.Getenv("TACRA_BENCH"); d != "" {
		return d
	}
	return filepath.Join(os.Getenv("HOME"), ".attestation-bench")
}

// veraisonDeployment is VERAISON_DEPLOYMENT, or the bench's own Veraison.
func veraisonDeployment() string {
	if d := os.Getenv("VERAISON_DEPLOYMENT"); d != "" {
		return d
	}
	return filepath.Join(benchHome(), "veraison")
}

// serviceVerify is `rrpverify service`: the same cases and changed inputs as `verify`, against a deployed verifier
// (Veraison).
func serviceVerify(args []string) {
	fs := flag.NewFlagSet("service", flag.ExitOnError)
	in := fs.String("in", "hwrun-out", "hwrun output directory")
	handlesPath := fs.String("handles", "handles.json", "the handles this RRP minted")
	base := fs.String("url", "https://localhost:8443", "verification service (the bench's Veraison)")
	submod := fs.String("submod", "SEVSNP", "the EAR submodule to read (SEVSNP for Veraison)")
	caPath := fs.String("ca", filepath.Join(veraisonDeployment(), "certs", "rootCA.crt"), "CA of the service's TLS certificate")
	certPath := fs.String("cert", filepath.Join(benchHome(), "tls", "clients", "ca-gateway.crt"), "this RRP's client certificate (mutual TLS)")
	keyPath := fs.String("key", filepath.Join(benchHome(), "tls", "clients", "ca-gateway.key"), "its private key")
	target := fs.String("target", "https://db.tacra.example", "the Target this RRP answered Initiate for")
	rrpCA := fs.String("rrp-ca", "https://ca1.tacra.example", "this Credential Authority's identifier")
	rrpVault := fs.String("rrp-vault", "https://vault1.tacra.example", "this Secret Vault's identifier")
	notBefore := fs.Int64("not-before", 0, "unix seconds: run started (RRP clock)")
	notAfter := fs.Int64("not-after", 0, "unix seconds: run ended (RRP clock)")
	window := fs.Int64("window", 300, "absent-timestamp acceptance window, seconds")
	out := fs.String("out", "", "results file (default DIR/rrpverify-service.json)")
	saveEARs := fs.String("save-ears", "", "a directory to keep, for each honest check that passed, the EAR received "+
		"(<case>.ear.jws) and the binding value it answers (<case>.bv.hex)")
	must(fs.Parse(args))

	v, err := newVeraisonService(*base, *caPath, *certPath, *keyPath)
	must(err)
	v.submod = *submod
	if *saveEARs != "" { // the key that signed the EARs kept there, so that they can be checked again later
		must(os.MkdirAll(*saveEARs, 0o755))
		must(os.WriteFile(filepath.Join(*saveEARs, "verifier-key.jwk"), append(v.jwk, '\n'), 0o644))
	}
	var h handles
	b, err := os.ReadFile(*handlesPath)
	must(err)
	must(json.Unmarshal(b, &h))
	var metas []caseMeta
	b, err = os.ReadFile(filepath.Join(*in, "cases.json"))
	must(err)
	must(json.Unmarshal(b, &metas))

	var results []result
	for _, m := range metas {
		dir := filepath.Join(*in, m.Case)
		token, err := os.ReadFile(filepath.Join(dir, "evidence.tsm.cbor"))
		must(err)
		subject, err := os.ReadFile(filepath.Join(dir, "subject.der"))
		must(err)
		rrp, otherRRP := *rrpCA, *rrpVault
		if m.Mode == "retrieve" {
			rrp, otherRRP = *rrpVault, *rrpCA
		}
		elem, otherElem, err := expectedElement(m, h, *notBefore, *notAfter, *window)
		if err != nil {
			results = append(results, result{Case: m.Case, Check: "freshness policy", Want: "pass", Got: "fail", Error: err.Error()})
			continue
		}
		flipped := append([]byte(nil), subject...)
		flipped[len(flipped)-1] ^= 1
		honestPassed := false
		for _, c := range []struct {
			name, want string
			bv         [64]byte
		}{
			{"honest", "pass", platform.BindingValue(elem, *target, rrp, subject)},
			{"other Target", "fail", platform.BindingValue(elem, "https://other.tacra.example", rrp, subject)},
			{otherRRPCase, "fail", platform.BindingValue(elem, *target, otherRRP, subject)},
			{"other CSR / CEKpub", "fail", platform.BindingValue(elem, *target, rrp, flipped)},
			{"other freshness element", "fail", platform.BindingValue(otherElem, *target, rrp, subject)},
		} {
			if c.name == otherRRPCase && rrp == otherRRP {
				continue // no identifier bound (the #20 variant): the case would be the honest one again, and prove nothing
			}
			t0 := time.Now()
			ear, err := v.verify(token, c.bv[:])
			ms := float64(time.Since(t0).Microseconds()) / 1000
			r := result{Case: m.Case, Table: "as-delivered", Check: c.name, Want: c.want, Ms: ms}
			switch {
			case err != nil:
				r.Got, r.Error = "fail", err.Error()
			case !bytes.Equal(ear.Nonce, c.bv[:]):
				r.Got, r.Error = "fail", "EAR reports another nonce than the binding value"
			case ear.Status != "affirming":
				r.Got, r.EAR, r.Error = "fail", ear.Status, "EAR status "+ear.Status
			default:
				r.Got, r.EAR = "pass", ear.Status
			}
			if c.name == "honest" {
				honestPassed = r.Got == "pass"
				if honestPassed && *saveEARs != "" {
					must(os.MkdirAll(*saveEARs, 0o755))
					must(os.WriteFile(filepath.Join(*saveEARs, m.Case+".ear.jws"), []byte(ear.JWS+"\n"), 0o644))
					must(os.WriteFile(filepath.Join(*saveEARs, m.Case+".bv.hex"), []byte(hex.EncodeToString(c.bv[:])+"\n"), 0o644))
				}
			} else if !honestPassed {
				r.Got, r.Comment = "inconclusive", "the honest Evidence is refused too, so a refusal here proves nothing"
			}
			r.OK = r.Got == r.Want
			results = append(results, r)
		}
	}
	if *out == "" {
		*out = filepath.Join(*in, "rrpverify-service.json")
	}
	summary := map[string]any{"veraison": *base, "results": results, "target": *target, "rrp_ca": *rrpCA,
		"rrp_vault": *rrpVault, "window_s": *window, "not_before": *notBefore, "not_after": *notAfter}
	b, _ = json.MarshalIndent(summary, "", " ")
	must(os.WriteFile(*out, b, 0o644))
	bad := 0
	for _, r := range results {
		mark := "ok "
		if !r.OK {
			mark, bad = "BAD", bad+1
		}
		fmt.Printf("%s %-26s %-24s want %-4s got %-12s %-12s %7.1f ms %s\n", mark, r.Case, r.Check, r.Want, r.Got, r.EAR, r.Ms,
			short(r.Error))
	}
	fmt.Printf("%d checks, %d not as expected; written %s\n", len(results), bad, *out)
}

// earsForCases is `rrpverify ears`: for each case of one mode hwrun wrote, the Attestation Results the deployed
// verifier issues for its Evidence when asked with the binding value the Attester bound (cases.json,
// binding_value_hex). That is what an honest CAS gets in Passport for the RRP the Evidence was made for, and what the
// #20 experiment then offers to a second RRP (hwcheck/scripts/redirect.sh). Each EAR is kept only when it verifies
// under the service's key, answers that value and is affirming; anything else stops the run.
func earsForCases(args []string) {
	fs := flag.NewFlagSet("ears", flag.ExitOnError)
	in := fs.String("in", "hwrun-out", "hwrun output directory")
	mode := fs.String("mode", "enroll", "the cases of this mode: enroll or retrieve")
	base := fs.String("url", "https://localhost:8443", "verification service (the bench's Veraison)")
	submod := fs.String("submod", "SEVSNP", "the EAR submodule to read (SEVSNP for Veraison)")
	caPath := fs.String("ca", filepath.Join(veraisonDeployment(), "certs", "rootCA.crt"), "CA of the service's TLS certificate")
	certPath := fs.String("cert", filepath.Join(benchHome(), "tls", "clients", "est-server.crt"), "the conduit's client certificate (mutual TLS)")
	keyPath := fs.String("key", filepath.Join(benchHome(), "tls", "clients", "est-server.key"), "its private key")
	out := fs.String("out", "", "where to write <case>.ear.jws and verifier-key.jwk")
	must(fs.Parse(args))
	if *out == "" {
		must(errors.New("ears: -out is required"))
	}
	v, err := newVeraisonService(*base, *caPath, *certPath, *keyPath)
	must(err)
	v.submod = *submod
	must(os.MkdirAll(*out, 0o755))
	must(os.WriteFile(filepath.Join(*out, "verifier-key.jwk"), append(v.jwk, '\n'), 0o644))
	var metas []caseMeta
	b, err := os.ReadFile(filepath.Join(*in, "cases.json"))
	must(err)
	must(json.Unmarshal(b, &metas))
	n := 0
	for _, m := range metas {
		if m.Mode != *mode {
			continue
		}
		bv, err := hex.DecodeString(m.BindingValueHex)
		if err != nil || len(bv) != 64 {
			must(fmt.Errorf("ears: %s: no 64-octet binding value in cases.json", m.Case))
		}
		token, err := os.ReadFile(filepath.Join(*in, m.Case, "evidence.tsm.cbor"))
		must(err)
		start := time.Now()
		r, err := v.verify(token, bv)
		if err != nil {
			must(fmt.Errorf("ears: %s: %w", m.Case, err))
		}
		if r.Status != "affirming" || !bytes.Equal(r.Nonce, bv) {
			must(fmt.Errorf("ears: %s: the verifier answered %q for nonce %x", m.Case, r.Status, r.Nonce))
		}
		must(os.WriteFile(filepath.Join(*out, m.Case+".ear.jws"), []byte(r.JWS+"\n"), 0o644))
		fmt.Printf("ok  %-26s %s, %.1f ms\n", m.Case, r.Status, float64(time.Since(start).Microseconds())/1000)
		n++
	}
	if n == 0 {
		must(fmt.Errorf("ears: no %s case in %s", *mode, *in))
	}
	fmt.Printf("%d Attestation Results kept in %s\n", n, *out)
}
