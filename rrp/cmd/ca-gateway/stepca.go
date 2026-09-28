package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// stepCA signs CSRs through step-ca's /1.0/sign with one-time tokens of a JWK provisioner whose private key this
// gateway holds. step-ca still applies its own name policy and duration limits.
type stepCA struct {
	url, audience, provisioner, kid string
	key                             *ecdsa.PrivateKey
	client                          *http.Client
}

type stepCAConfig struct {
	URL         string `json:"url"`
	Root        string `json:"root"`
	Provisioner string `json:"provisioner"`
	KeyFile     string `json:"provisioner_key"` // the provisioner's private JWK
}

func newStepCA(c stepCAConfig) (*stepCA, error) {
	rootPEM, err := os.ReadFile(c.Root)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("step-ca: no root certificate in " + c.Root)
	}
	jwk, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return nil, err
	}
	var k struct{ Kty, Crv, X, Y, D, Kid string }
	if err := json.Unmarshal(jwk, &k); err != nil {
		return nil, err
	}
	if k.Kty != "EC" || k.Crv != "P-256" || k.D == "" {
		return nil, errors.New("step-ca: provisioner key must be a private EC P-256 JWK")
	}
	dec := base64.RawURLEncoding.DecodeString
	x, e1 := dec(k.X)
	y, e2 := dec(k.Y)
	d, e3 := dec(k.D)
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, errors.New("step-ca: provisioner key is not base64url")
	}
	priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x),
		Y: new(big.Int).SetBytes(y)}, D: new(big.Int).SetBytes(d)}
	base := strings.TrimRight(c.URL, "/")
	return &stepCA{url: base, audience: base + "/1.0/sign", provisioner: c.Provisioner, kid: k.Kid, key: priv,
		client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}, nil
}

// token is a one-time token for the JWK provisioner: sub and sans are the names the certificate will carry.
func (s *stepCA) token(sub string, sans []string) (string, error) {
	now := time.Now()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": s.kid, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iss": s.provisioner, "aud": s.audience, "sub": sub, "sans": sans,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": fmt.Sprintf("%x", jti)})
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc(hdr) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signing))
	r, sgn, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sgn.FillBytes(sig[32:])
	return signing + "." + enc(sig), nil
}

// sign asks step-ca to certify csrDER with the given names and validity; it returns the chain, leaf first, as DER.
func (s *stepCA) sign(csrDER []byte, sub string, sans []string, validity string) ([][]byte, error) {
	ott, err := s.token(sub, sans)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{
		"csr":      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"ott":      ott,
		"notAfter": validity,
	})
	resp, err := s.client.Post(s.url+"/1.0/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("step-ca: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		CertChain []string `json:"certChain"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	var chain [][]byte
	for _, p := range out.CertChain {
		blk, _ := pem.Decode([]byte(p))
		if blk == nil {
			return nil, errors.New("step-ca: certificate chain is not PEM")
		}
		chain = append(chain, blk.Bytes)
	}
	if len(chain) == 0 {
		return nil, errors.New("step-ca: empty certificate chain")
	}
	return chain, nil
}
