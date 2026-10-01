package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/mtls"
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

// newVaultKV is the client of HashiCorp Vault: TLS 1.3 to a server under c.CA, with this gateway's client certificate
// when one is configured (N23: Vault's listener can require it); the token's policy limits what it may read.
func newVaultKV(c vaultConfig, clientCert, clientKey string) (*vaultKV, error) {
	tc, err := mtls.ClientTLS(c.CA, clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	tok, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, err
	}
	return &vaultKV{addr: strings.TrimRight(c.Addr, "/"), mount: strings.Trim(c.Mount, "/"),
		token: strings.TrimSpace(string(tok)), client: &http.Client{Timeout: 15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tc}}}, nil
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
