// Command rup is the end-to-end run's RATS-unaware Relying Party: an ordinary HTTPS service that knows nothing of
// attestation. /hello admits a client certificate issued under the workload CA whose DNS name is on its list; /api
// admits the pre-shared API key it was configured with. It logs every admission and refusal.
//
//	rup -listen 127.0.0.1:19443 -cert rup.crt -key rup.key -client-ca workload-ca.pem -allow payments.workload.tacra.example -api-key-file key
package main

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:19443", "listen address")
	certFile := flag.String("cert", "", "server certificate")
	keyFile := flag.String("key", "", "server key")
	clientCA := flag.String("client-ca", "", "PEM bundle of the workload CA (root and intermediate)")
	allow := flag.String("allow", "", "comma-separated DNS names admitted at /hello")
	apiKeyFile := flag.String("api-key-file", "", "file holding the API key admitted at /api")
	flag.Parse()
	pem, err := os.ReadFile(*clientCA)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatal("no certificate in " + *clientCA)
	}
	keyRaw, err := os.ReadFile(*apiKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	apiKey := []byte(strings.TrimSpace(string(keyRaw)))
	allowed := strings.Split(*allow, ",")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /hello", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			log.Printf("hello refused: no client certificate from the workload CA")
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		name := ""
		for _, n := range leaf.DNSNames {
			if slices.Contains(allowed, n) {
				name = n
			}
		}
		if name == "" {
			log.Printf("hello refused: %v not admitted", leaf.DNSNames)
			http.Error(w, "not admitted", http.StatusForbidden)
			return
		}
		log.Printf("hello admitted: %s serial %s until %s", name, hex.EncodeToString(leaf.SerialNumber.Bytes()), leaf.NotAfter.UTC().Format(time.RFC3339))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"admitted": name, "serial": hex.EncodeToString(leaf.SerialNumber.Bytes()),
			"not_after": leaf.NotAfter.UTC().Format(time.RFC3339)})
	})
	mux.HandleFunc("POST /api", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), apiKey) != 1 {
			log.Printf("api refused: wrong or missing API key")
			http.Error(w, "not admitted", http.StatusForbidden)
			return
		}
		log.Printf("api admitted")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"admitted": "api-key"})
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}}
	log.Printf("rup listening on %s", *listen)
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}
