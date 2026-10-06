// Package verifierapi serves the subset of Veraison's challenge-response API that the bench's own verifiers offer
// (the TDX verifier, the sim-verifier), as the EST server and the RRP gateways use it: a session whose nonce the
// caller chooses, Evidence as a TSM report, and an EAR signed ES256 with the verifier's own key. The verifier brings
// the appraisal; this package brings the sessions, the EAR and its key.
package verifierapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/jwk"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/mtls"
)

// MediaType is the only Evidence media type these verifiers take: a Veraison TSM report.
const MediaType = "application/vnd.veraison.tsm-report+cbor"

// SessionLifetime is how long a session waits for its Evidence.
const SessionLifetime = 5 * time.Minute

// Appraise judges one piece of Evidence for a session's nonce. An empty status means the request itself is
// malformed (400, no EAR); otherwise the EAR reports status ("affirming", "contraindicated", ...) for the verifier's
// submodule with the annotations, and err says why when it is not affirming.
type Appraise func(token, nonce []byte) (status string, ann map[string]string, err error)

// Server is one verifier's API.
type Server struct {
	Key      *ecdsa.PrivateKey // signs the EARs
	Submod   string            // the EAR submodule it speaks for ("TDX", "SIM")
	PolicyID string            // ear.appraisal-policy-id
	Build    string            // ear.verifier-id build
	// Developer is ear.verifier-id developer; empty: "TACRA test bench".
	Developer string
	Appraise  Appraise
	// Trust is ear.trustworthiness-vector for an affirming result; a result that is not affirming reports hardware and
	// runtime-opaque 97 (contraindicated).
	Trust map[string]int
	// LogSessions logs the caller of each session (its certificate's names), for verifiers behind mutual TLS.
	LogSessions bool
	// Summary is the detail logged after "appraisal: affirming", from the annotations; nil logs none.
	Summary func(ann map[string]string) string

	mu       sync.Mutex
	sessions map[string]*session
}

type session struct {
	nonce   []byte
	expires time.Time
}

// Routes is the HTTP API: the well-known document, newSession, the session's Evidence, DELETE.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/veraison/verification", func(w http.ResponseWriter, r *http.Request) {
		key, err := PublicJWK(&s.Key.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ear-verification-key": key, "media-types": []string{MediaType},
			"service-state": "READY"})
	})
	mux.HandleFunc("POST /challenge-response/v1/newSession", func(w http.ResponseWriter, r *http.Request) {
		if s.LogSessions {
			log.Printf("session for %v", mtls.Names(r))
		}
		nonce, err := base64.URLEncoding.DecodeString(r.URL.Query().Get("nonce"))
		if err != nil || len(nonce) < 8 || len(nonce) > 64 {
			http.Error(w, "nonce must be 8 to 64 octets, base64url", http.StatusBadRequest)
			return
		}
		id := make([]byte, 16)
		_, _ = rand.Read(id)
		sid := hex.EncodeToString(id)
		s.mu.Lock()
		if s.sessions == nil {
			s.sessions = map[string]*session{}
		}
		for k, v := range s.sessions {
			if time.Now().After(v.expires) {
				delete(s.sessions, k)
			}
		}
		s.sessions[sid] = &session{nonce: nonce, expires: time.Now().Add(SessionLifetime)}
		s.mu.Unlock()
		w.Header().Set("Location", "session/"+sid)
		writeJSON(w, http.StatusCreated, map[string]any{"status": "waiting", "nonce": base64.URLEncoding.EncodeToString(nonce),
			"accept": []string{MediaType}})
	})
	mux.HandleFunc("POST /challenge-response/v1/session/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		se, ok := s.sessions[r.PathValue("id")]
		s.mu.Unlock()
		if !ok || time.Now().After(se.expires) {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		if r.Header.Get("Content-Type") != MediaType {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		token, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		status, ann, err := s.Appraise(token, se.nonce)
		if status == "" {
			detail := "malformed Evidence"
			if err != nil {
				detail = err.Error()
			}
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": "failed", "detail": detail})
			return
		}
		switch {
		case err != nil:
			log.Printf("appraisal: %s: %v", status, err)
		case s.Summary != nil:
			log.Printf("appraisal: %s, %s", status, s.Summary(ann))
		default:
			log.Printf("appraisal: %s", status)
		}
		sub := map[string]any{"ear.status": status, "ear.appraisal-policy-id": s.PolicyID,
			"ear.trustworthiness-vector": s.Trust, "ear.veraison.annotated-evidence": ann}
		if status != "affirming" {
			sub["ear.trustworthiness-vector"] = map[string]int{"hardware": 97, "runtime-opaque": 97}
		}
		dev := s.Developer
		if dev == "" {
			dev = "TACRA test bench"
		}
		ear, err := SignEAR(s.Key, map[string]any{"eat_profile": "tag:github.com,2023:veraison/ear", "iat": time.Now().Unix(),
			"eat_nonce":       base64.RawURLEncoding.EncodeToString(se.nonce),
			"ear.verifier-id": map[string]string{"developer": dev, "build": s.Build},
			"submods":         map[string]any{s.Submod: sub}})
		if err != nil {
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "complete", "result": ear})
	})
	mux.HandleFunc("DELETE /challenge-response/v1/session/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		delete(s.sessions, r.PathValue("id"))
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// LoadOrCreateKey reads the verifier's ES256 signing key, an EC P-256 private JWK, creating it (mode 0600) when the
// file is absent.
func LoadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		k, _, err := jwk.ParsePrivate(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return k, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	key, err := jwk.FromPrivate(k)
	if err != nil {
		return nil, err
	}
	if raw, err = json.Marshal(key); err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, raw, 0o600)
}

// PublicJWK is the EAR verification key as a public JWK: what the RRPs' operator provisions to them.
func PublicJWK(pub *ecdsa.PublicKey) (jwk.Key, error) {
	k, err := jwk.FromPublic(pub)
	k.Alg = "ES256"
	return k, err
}

// SignEAR signs claims as a compact JWS, ES256.
func SignEAR(key *ecdsa.PrivateKey, claims map[string]any) (string, error) {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	d := sha256.Sum256([]byte(signing))
	r, sv, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return signing + "." + enc.EncodeToString(sig), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
