package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/jwk"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/mtls"
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

// newStepCA is the client of step-ca: TLS 1.3 to a server under c.Root. The gateway authenticates to step-ca with its
// provisioner's one-time token, signed with the provisioner key it holds, for each certificate (N23: the CA-RA channel
// mutually authenticated); it presents no TLS client certificate, since step-ca checks those against its own roots
// and refuses the handshake for one of the bench's infrastructure root.
func newStepCA(c stepCAConfig) (*stepCA, error) {
	tc, err := mtls.ClientTLS(c.Root, "", "")
	if err != nil {
		return nil, fmt.Errorf("step-ca: %w", err)
	}
	raw, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return nil, err
	}
	priv, k, err := jwk.ParsePrivate(raw)
	if err != nil {
		return nil, fmt.Errorf("step-ca: provisioner key %s: %w", c.KeyFile, err)
	}
	base := strings.TrimRight(c.URL, "/")
	return &stepCA{url: base, audience: base + "/1.0/sign", provisioner: c.Provisioner, kid: k.Kid, key: priv,
		client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}}, nil
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
