// Command fraud-api is Demo Bank's fraud-scoring service, a stand-in for an external partner API that knows nothing
// of attestation: it admits a caller that presents the pre-shared API key it was configured with, and scores a
// transfer. Demo Bank is fictional; its accounts and amounts are made up.
//
//	fraud-api -listen :8444 -cert core.crt -key core.key -api-key-file key
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type scoreRequest struct {
	From        string `json:"from"`
	To          string `json:"to"`
	AmountCents int64  `json:"amount_cents"`
}

func main() {
	listen := flag.String("listen", ":8444", "listen address")
	cert := flag.String("cert", "", "TLS certificate")
	key := flag.String("key", "", "TLS key")
	keyFile := flag.String("api-key-file", "", "file with the API key admitted")
	flag.Parse()
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	apiKey := []byte(strings.TrimSpace(string(raw)))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/score", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), apiKey) != 1 {
			log.Printf("score refused from %s: wrong or missing API key", r.RemoteAddr)
			http.Error(w, "not admitted", http.StatusForbidden)
			return
		}
		var req scoreRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.AmountCents <= 0 {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		decision, score := "approve", int(req.AmountCents/100000) // one point per 1,000.00
		if score > 50 {
			decision = "review"
		}
		ref := make([]byte, 6)
		_, _ = rand.Read(ref)
		out := map[string]any{"decision": decision, "score": score, "ref": "FRD-" + strings.ToUpper(hex.EncodeToString(ref))}
		log.Printf("score %s: %s -> %s %d cents: %s (%d)", out["ref"], req.From, req.To, req.AmountCents, decision, score)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("fraud-api listening on %s", *listen)
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}
