package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// vaultKV reads secrets from a HashiCorp Vault KV v2 mount with a token whose policy only allows reading them.
type vaultKV struct {
	addr, mount, token string
	client             *http.Client
}

type vaultConfig struct {
	Addr      string `json:"addr"`
	CA        string `json:"ca"`
	Mount     string `json:"mount"`
	TokenFile string `json:"token_file"`
}

func newVaultKV(c vaultConfig) (*vaultKV, error) {
	caPEM, err := os.ReadFile(c.CA)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("vault: no CA certificate in " + c.CA)
	}
	tok, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, err
	}
	return &vaultKV{addr: strings.TrimRight(c.Addr, "/"), mount: strings.Trim(c.Mount, "/"),
		token: strings.TrimSpace(string(tok)), client: &http.Client{Timeout: 15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}, nil
}

// read returns the latest version of the secret at path and that version's number.
func (v *vaultKV) read(path string) (map[string]string, int, error) {
	req, err := http.NewRequest(http.MethodGet, v.addr+"/v1/"+v.mount+"/data/"+strings.Trim(path, "/"), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Vault-Token", v.token)
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("vault: HTTP %d reading %s", resp.StatusCode, path)
	}
	var out struct {
		Data struct {
			Data     map[string]string `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, 0, err
	}
	return out.Data.Data, out.Data.Metadata.Version, nil
}
