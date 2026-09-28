package gateway

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// SignTestEAR re-signs the claims of a template EAR with key, replacing eat_nonce and iat. Tests use it to exercise
// an RRP without a live verifier; the claims (submodule, status, annotated evidence) come from a real EAR.
func SignTestEAR(key *ecdsa.PrivateKey, template string, nonce []byte, iat time.Time, status string) (string, error) {
	parts := strings.Split(template, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	claims["eat_nonce"] = base64.RawURLEncoding.EncodeToString(nonce)
	claims["iat"] = iat.Unix()
	if status != "" {
		for _, v := range claims["submods"].(map[string]any) {
			v.(map[string]any)["ear.status"] = status
		}
	}
	p, _ := json.Marshal(claims)
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc(h) + "." + enc(p)
	d := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + enc(sig), nil
}
