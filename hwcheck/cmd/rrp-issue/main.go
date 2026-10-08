// Command rrp-issue is the Relying Party side of the #19/#20 redirection experiment. It plays the conduit the way the
// EST server does on the wire, but it may post to any RRP gateway, so it can send one piece of Evidence to the RRP it
// was produced for and to a second RRP, and record which one issues. It talks only to RRP gateways over mutual TLS
// with the EST server's identity, exactly as the honest conduit authenticates (N23); it is a test driver, it mints no
// Handle, holds no attestation key, and decides nothing.
//
//	rrp-issue mint     -url https://127.0.0.1:9101 -target T -ctype x509
//	rrp-issue enroll   -url https://127.0.0.1:9103 -target T -ctype x509 -kind present-nonce -handle B64 -evidence E.cbor -csr C.der
//	rrp-issue retrieve -url https://127.0.0.1:9104 -target T -ctype api-key -kind present-nonce -handle B64 -evidence E.cbor -cek K.der -hint H
//
// mint prints the attest-initiate answer (handle, freshness_kind, rrp_id). enroll and retrieve post a second leg, in
// Background Check the Evidence as the Attester produced it (-evidence), in Passport the Attestation Results a
// verifier issued for it (-ear), with any field as the conduit chooses to send it (the #19 rewrites), and print
// whether the gateway issued (a certificate; for retrieve, a container), the status and the reason. Each prints one
// JSON object.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "rrp-issue: "+format+"\n", a...)
	os.Exit(1)
}

// client is TLS 1.3 to a gateway certified by caPath, presenting the conduit's (EST server's) client certificate.
func client(caPath, certPath, keyPath string) *http.Client {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		die("read CA %s: %v", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		die("no CA certificate in %s", caPath)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		die("client certificate: %v", err)
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}}
}

func post(c *http.Client, url string, body any) (int, []byte) {
	b, _ := json.Marshal(body)
	resp, err := c.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		die("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw
}

func b64(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		die("read %s: %v", path, err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func commonFlags(fs *flag.FlagSet) (url, target, ctype, ca, cert, key *string) {
	// the running bench, as in scripts/lib.sh: BENCH_HOME, or TACRA_BENCH, or ~/.attestation-bench
	home := os.Getenv("BENCH_HOME")
	if home == "" {
		home = os.Getenv("TACRA_BENCH")
	}
	if home == "" {
		home = os.Getenv("HOME") + "/.attestation-bench"
	}
	url = fs.String("url", "https://127.0.0.1:9101", "RRP gateway base URL")
	target = fs.String("target", "https://db-nonce.tacra.example", "the Target")
	ctype = fs.String("ctype", "x509", "credential type")
	ca = fs.String("ca", home+"/tls/root.crt", "CA of the gateway's TLS certificate")
	cert = fs.String("cert", home+"/tls/clients/est-server.crt", "the conduit's client certificate")
	key = fs.String("key", home+"/tls/clients/est-server.key", "its private key")
	return
}

// secondLeg posts a second leg to the gateway's mode, enroll (the CSR, -csr) or retrieve (CEKpub, -cek), and prints
// whether the gateway issued: for enroll the certificate's serial, issuer and subject, for retrieve the container and
// the RRP identifier and Target its associated data name; otherwise the gateway's reason.
func secondLeg(mode string, args []string) {
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	url, target, ctype, ca, cert, key := commonFlags(fs)
	kind := fs.String("kind", "present-nonce", "freshness kind")
	handle := fs.String("handle", "", "the freshness handle (base64url, as mint returned it)")
	evidence := fs.String("evidence", "", "Background Check: the Evidence file (TSM report, CBOR)")
	earPath := fs.String("ear", "", "Passport: the Attestation Results file (compact JWS)")
	csr := fs.String("csr", "", "enroll: the CSR file (DER)")
	cek := fs.String("cek", "", "retrieve: CEKpub as the binding took it (the case's subject.der)")
	profile := fs.String("profile", "application/vnd.veraison.tsm-report+cbor", "the Evidence media type")
	hint := fs.String("hint", "", "the Credential Hint to send (none by default)")
	if err := fs.Parse(args); err != nil {
		die("%v", err)
	}
	subject, field := *csr, "csr"
	if mode == "retrieve" {
		subject, field = *cek, "cek_pub"
	}
	if (*evidence == "") == (*earPath == "") || subject == "" {
		die("%s needs -%s and one of -evidence (Background Check) and -ear (Passport)", mode, map[string]string{
			"csr": "csr", "cek_pub": "cek"}[field])
	}
	leg := map[string]string{"freshness_kind": *kind, "target": *target, "credential_type": *ctype, field: b64(subject)}
	if *evidence != "" { // Background Check: the Evidence as the Attester produced it; the RRP asks the verifier itself
		leg["evidence"], leg["profile"] = b64(*evidence), *profile
	} else { // Passport: the Attestation Results, which the RRP checks against the binding value it recomputes
		jws, err := os.ReadFile(*earPath)
		if err != nil {
			die("read %s: %v", *earPath, err)
		}
		leg["ear"] = strings.TrimSpace(string(jws))
	}
	if *handle != "" {
		leg["handle"] = *handle
	}
	if *hint != "" {
		leg["credential_hint"] = *hint
	}
	c := client(*ca, *cert, *key)
	st, raw := post(c, strings.TrimRight(*url, "/")+"/tacra/v1/"+mode, leg)
	res := map[string]any{"status": st, "issued": st == http.StatusOK}
	switch {
	case st == http.StatusOK && mode == "enroll":
		var out struct {
			CertificateChain []string `json:"certificate_chain"`
		}
		if json.Unmarshal(raw, &out) == nil && len(out.CertificateChain) > 0 {
			if der, err := base64.RawURLEncoding.DecodeString(out.CertificateChain[0]); err == nil {
				if crt, err := x509.ParseCertificate(der); err == nil {
					res["cert_serial"] = fmt.Sprintf("%x", crt.SerialNumber)
					res["cert_issuer"] = crt.Issuer.String()
					res["cert_subject"] = crt.Subject.String()
				}
			}
		}
	case st == http.StatusOK: // retrieve: the container, sealed to the Attester's CEKpub, which no one else can open
		var out struct {
			Container string `json:"container"`
			AAD       struct {
				RRPID  string `json:"rrp_id"`
				Target string `json:"target"`
			} `json:"aad"`
		}
		if json.Unmarshal(raw, &out) == nil {
			res["container"], res["container_rrp_id"], res["container_target"] = out.Container, out.AAD.RRPID, out.AAD.Target
		}
	default:
		var e struct{ Error, Detail string }
		_ = json.Unmarshal(raw, &e)
		res["reason"] = strings.TrimSpace(e.Error + " " + e.Detail)
		if res["reason"] == "" {
			res["reason"] = strings.TrimSpace(string(raw))
		}
	}
	b, _ := json.Marshal(res)
	fmt.Println(string(b))
}

func main() {
	if len(os.Args) < 2 {
		die("usage: rrp-issue mint|enroll|retrieve ...")
	}
	switch os.Args[1] {
	case "mint":
		fs := flag.NewFlagSet("mint", flag.ExitOnError)
		url, target, ctype, ca, cert, key := commonFlags(fs)
		if err := fs.Parse(os.Args[2:]); err != nil {
			die("%v", err)
		}
		c := client(*ca, *cert, *key)
		st, raw := post(c, strings.TrimRight(*url, "/")+"/tacra/v1/initiate",
			map[string]string{"target": *target, "credential_type": *ctype})
		if st != http.StatusOK {
			die("initiate: HTTP %d: %s", st, raw)
		}
		fmt.Printf("%s\n", raw)
	case "enroll", "retrieve":
		secondLeg(os.Args[1], os.Args[2:])
	default:
		die("unknown command %q", os.Args[1])
	}
}
