// Command e2e-attester is the workload of the end-to-end run. In an AMD SEV-SNP or Intel TDX guest it uses the SIG's
// CAI with the hardware plug-in (on a laptop, with the bench's software stand-in, tee "sim": no isolation, no
// security) to acquire, through the CAAPI (caapi-est) and the EST server, a credential for each
// configured Target, then presents it to the RATS-unaware Relying Party: the certificate as a TLS client certificate,
// the API key in a header. It writes what happened, with digests in place of secrets. Run as root on hardware
// (configfs-tsm).
//
//	e2e-attester -config e2e-attester.json -out results.json
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/TWI-Unified-Model/tacra/cai"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type config struct {
	TEE            string                       `json:"tee"`
	CAAPI          string                       `json:"caapi"`
	Hint           string                       `json:"hint"`
	Targets        []target                     `json:"targets"`
	RelyingParties map[string]map[string]string `json:"relying_parties"` // Target -> mode -> RRP identifier held
	VaultOrigins   map[string]map[string]string `json:"vault_origins"`   // RRP id -> DHKEM -> SPKI (base64url)
	VaultSigners   map[string]string            `json:"vault_signers"`   // RRP id -> signature key SPKI (base64url), hpke-base-signed
	CAAnchors      map[string]string            `json:"ca_anchors"`      // RRP id -> the Credential Authority's certificates (PEM): tacra-est N15
	LocalEpochHex  string                       `json:"local_epoch_hex"`
	// tee "sim" only: the stand-in's attestation key (private JWK), its launch measurement, and whether it reports
	// a debuggable instance
	SimKeyFile        string `json:"sim_key_file,omitempty"`
	SimMeasurementHex string `json:"sim_measurement_hex,omitempty"`
	SimDebug          bool   `json:"sim_debug,omitempty"`
	RUP               struct {
		URL       string `json:"url"`
		AnchorPEM string `json:"anchor_pem"`
	} `json:"rup"`
}

type target struct {
	Target string `json:"target"`
	Type   string `json:"type"` // "x509" or "api-key"
}

type result struct {
	Target      string  `json:"target"`
	Type        string  `json:"type"`
	OK          bool    `json:"ok"`
	Error       string  `json:"error,omitempty"`
	Attempts    int     `json:"attempts"`
	AcquireMs   float64 `json:"acquire_ms"`
	CertSerial  string  `json:"cert_serial,omitempty"`
	CertNames   string  `json:"cert_names,omitempty"`
	CertIssuer  string  `json:"cert_issuer,omitempty"`
	NotAfter    string  `json:"not_after,omitempty"`
	SecretSHA   string  `json:"secret_sha256,omitempty"`
	RUPStatus   int     `json:"rup_status"`
	RUPResponse string  `json:"rup_response,omitempty"`
}

var types = map[string]cai.CredentialType{"x509": cai.CredentialTypeX509, "api-key": cai.CredentialTypeAPIKey}

func main() {
	cfgPath := flag.String("config", "e2e-attester.json", "configuration")
	out := flag.String("out", "results.json", "results")
	flag.Parse()
	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatal(err)
	}
	epoch, err := hex.DecodeString(cfg.LocalEpochHex)
	if err != nil {
		log.Fatal("local_epoch_hex: ", err)
	}
	var plugin platform.Plugin
	switch cfg.TEE {
	case "sev-snp":
		plugin, err = platform.NewSEVSNP(platform.WithLocalEpoch(epoch))
	case "tdx":
		plugin, err = platform.NewTDX(platform.WithLocalEpoch(epoch))
	case "sim":
		plugin, err = newSim(cfg, epoch)
	default:
		err = fmt.Errorf("unknown tee %q", cfg.TEE)
	}
	if err != nil {
		log.Fatal(err)
	}
	conn, err := grpc.NewClient(cfg.CAAPI, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	opts, err := cai.RelyingParties(cfg.RelyingParties)
	if err != nil {
		log.Fatal(err)
	}
	for rrp, keys := range cfg.VaultOrigins {
		for kem, b64 := range keys {
			spki, err := base64.RawURLEncoding.DecodeString(b64)
			if err != nil {
				log.Fatal("vault origin: ", err)
			}
			opts = append(opts, cai.WithVaultOrigin(rrp, kem, spki))
		}
	}
	for rrp, b64 := range cfg.VaultSigners {
		spki, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			log.Fatal("vault signer: ", err)
		}
		opts = append(opts, cai.WithVaultSigner(rrp, spki))
	}
	for rrp, pemText := range cfg.CAAnchors {
		var certs []*x509.Certificate
		for rest := []byte(pemText); ; {
			var b *pem.Block
			if b, rest = pem.Decode(rest); b == nil {
				break
			}
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				log.Fatal("ca anchor: ", err)
			}
			certs = append(certs, cert)
		}
		if len(certs) == 0 {
			log.Fatal("ca anchor: no certificate for ", rrp)
		}
		opts = append(opts, cai.WithCertificateAuthority(rrp, certs...))
	}
	// the bank profile's longest certificate (tacra-est decision 6)
	opts = append(opts, cai.WithCertificateMaxValidity(time.Hour))
	opts = append(opts, cai.WithCSRNamingHint())
	c, err := cai.New(plugin, caapiv1.NewCredentialAcquisitionServiceClient(conn), opts...)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cfg.RUP.AnchorPEM)) {
		log.Fatal("rup anchor: no certificate")
	}

	var results []result
	for _, t := range cfg.Targets {
		r := result{Target: t.Target, Type: t.Type}
		var cred *cai.Credential
		t0 := time.Now()
		for r.Attempts = 1; r.Attempts <= 3; r.Attempts++ { // TACRA: retry from Initiate when the freshness moved
			cred, err = c.AcquireCredential(context.Background(), t.Target, types[t.Type], cfg.Hint)
			if status.Code(errors.Unwrap(err)) != codes.Aborted && status.Code(err) != codes.Aborted {
				break
			}
		}
		r.AcquireMs = float64(time.Since(t0).Microseconds()) / 1000
		if err != nil {
			r.Error = err.Error()
			results = append(results, r)
			log.Printf("%-40s acquire failed: %v", t.Target, err)
			continue
		}
		switch t.Type {
		case "x509":
			leaf, perr := x509.ParseCertificate(cred.Document)
			if perr != nil {
				r.Error = perr.Error()
				break
			}
			r.CertSerial, r.CertIssuer = hex.EncodeToString(leaf.SerialNumber.Bytes()), leaf.Issuer.CommonName
			r.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
			r.CertNames = fmt.Sprint(leaf.DNSNames, leaf.URIs)
			r.RUPStatus, r.RUPResponse, r.Error = present(cfg.RUP.URL+"/hello", pool, &tls.Certificate{
				Certificate: [][]byte{cred.Document}, PrivateKey: cred.PrivateKey, Leaf: leaf}, nil)
		case "api-key":
			sum := sha256.Sum256(cred.Document)
			r.SecretSHA = hex.EncodeToString(sum[:])
			r.RUPStatus, r.RUPResponse, r.Error = present(cfg.RUP.URL+"/api", pool, nil, cred.Document)
		}
		r.OK = r.Error == "" && r.RUPStatus == http.StatusOK
		log.Printf("%-40s %-7s acquired in %7.1f ms (%d attempt(s)); relying party answered %d", t.Target, t.Type,
			r.AcquireMs, r.Attempts, r.RUPStatus)
		results = append(results, r)
	}
	b, _ := json.MarshalIndent(results, "", " ")
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}

// present shows the credential to the RATS-unaware Relying Party.
func present(url string, pool *x509.CertPool, cert *tls.Certificate, apiKey []byte) (int, string, string) {
	tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if cert != nil {
		tc.Certificates = []tls.Certificate{*cert}
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}
	method, body := http.MethodGet, io.Reader(nil)
	if apiKey != nil {
		method, body = http.MethodPost, bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, url, body)
	if apiKey != nil {
		req.Header.Set("X-API-Key", string(apiKey))
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(bytes.TrimSpace(b)), ""
}

// newSim is the bench's software stand-in TEE, as the configuration describes it.
func newSim(cfg config, epoch []byte) (platform.Plugin, error) {
	key, err := platform.LoadSimKey(cfg.SimKeyFile)
	if err != nil {
		return nil, fmt.Errorf("sim_key_file: %w", err)
	}
	m, err := hex.DecodeString(cfg.SimMeasurementHex)
	if err != nil {
		return nil, fmt.Errorf("sim_measurement_hex: %w", err)
	}
	return platform.NewSimTEE(platform.SimTEEConfig{Key: key, Measurement: m, Debug: cfg.SimDebug}, platform.WithLocalEpoch(epoch))
}
