// Command sim-verifier is the test bench's Verifier for its software stand-in TEE (platform.SimTEE), so the bench
// runs on a laptop with no TEE. There is no hardware to verify: a SimTEE report is signed with an attestation key that
// is an ordinary file, so an "affirming" result here proves only that the protocol was followed, never that a
// workload was isolated. It offers the same API subset as the bench's TDX verifier (rrp/internal/verifierapi): a
// session whose nonce the caller chooses, Evidence as a TSM report (provider sim_guest), and an EAR (submodule SIM)
// signed ES256 with its own key. The report must be signed by one of the configured attestation keys, its
// report_data must be the session nonce, the instance must not be debuggable, and its measurement must be one of
// the reference values. An RRP accepts its results only when its configuration sets allow_simulated_tee.
//
//	sim-verifier -config sim-verifier.json
//	sim-verifier -config sim-verifier.json -public-jwk     (the EAR key, as the RRPs' operator provisions it)
package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/mtls"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/verifierapi"
)

type config struct {
	Listen  string `json:"listen"`
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// Mutual TLS (N23): callers present a certificate of ClientCA, and only the identities Clients names (the EST
	// server, the RRP gateways) may open sessions.
	ClientCA string   `json:"client_ca,omitempty"`
	Clients  []string `json:"clients,omitempty"`
	KeyFile  string   `json:"signing_key"` // ES256 private JWK; created if absent
	// AttestationKeys are files holding the public JWKs of the SimTEE attestation keys whose reports it takes.
	AttestationKeys []string `json:"attestation_keys"`
	// Measurements are the reference launch measurements, hex, 48 octets each.
	Measurements []string `json:"reference_measurements"`
}

// appraiser holds the trusted attestation keys and the reference measurements.
type appraiser struct {
	keys         []*ecdsa.PublicKey
	measurements []string
}

// appraise verifies a SimTEE report and returns the EAR status and the annotated fields.
func (a *appraiser) appraise(token, nonce []byte) (string, map[string]string, error) {
	var t struct {
		OutBlob  []byte `cbor:"outblob"`
		Provider string `cbor:"provider"`
	}
	if err := cbor.Unmarshal(token, &t); err != nil || strings.TrimSpace(t.Provider) != platform.SimProvider || len(t.OutBlob) == 0 {
		return "", nil, errors.New("not a TSM report of a SimTEE")
	}
	ann := map[string]string{"platform": "simulated"}
	rep, err := platform.ParseSimReport(t.OutBlob, a.keys)
	if err != nil {
		return "contraindicated", ann, err
	}
	ann["measurement"] = hex.EncodeToString(rep.Measurement)
	ann["instance_id"] = hex.EncodeToString(rep.InstanceID)
	ann["debug"] = strconv.FormatBool(rep.Debug)
	if !bytes.Equal(rep.ReportData, nonce) {
		return "contraindicated", ann, errors.New("report_data is not the session nonce")
	}
	if rep.Debug {
		return "contraindicated", ann, errors.New("the instance is debuggable")
	}
	if !slices.Contains(a.measurements, ann["measurement"]) {
		return "contraindicated", ann, fmt.Errorf("measurement %s matches no reference value", ann["measurement"])
	}
	return "affirming", ann, nil
}

// load reads the attestation keys and checks the reference measurements.
func (c *config) load() (*appraiser, error) {
	a := &appraiser{}
	for _, p := range c.AttestationKeys {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		k, err := platform.ParseSimPublicJWK(raw)
		if err != nil {
			return nil, fmt.Errorf("attestation key %s: %w", p, err)
		}
		a.keys = append(a.keys, k)
	}
	if len(a.keys) == 0 {
		return nil, errors.New("attestation_keys: none")
	}
	for _, m := range c.Measurements {
		b, err := hex.DecodeString(m)
		if err != nil || len(b) != platform.SimMeasurementSize {
			return nil, fmt.Errorf("reference_measurements: %q is not %d octets of hex", m, platform.SimMeasurementSize)
		}
		a.measurements = append(a.measurements, strings.ToLower(m))
	}
	return a, nil
}

func main() {
	path := flag.String("config", "sim-verifier.json", "configuration file")
	printKey := flag.Bool("public-jwk", false, "print the EAR verification key as a public JWK (creating the signing key if absent) and exit: "+
		"what the RRPs' operator provisions to them")
	flag.Parse()
	raw, err := os.ReadFile(*path)
	if err != nil {
		log.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatal(err)
	}
	key, err := verifierapi.LoadOrCreateKey(cfg.KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	if *printKey {
		_ = json.NewEncoder(os.Stdout).Encode(verifierapi.PublicJWK(&key.PublicKey))
		return
	}
	a, err := cfg.load()
	if err != nil {
		log.Fatal(err)
	}
	api := &verifierapi.Server{Key: key, Submod: "SIM", PolicyID: "policy:SIM-reference-measurement",
		Build: "sim-verifier (software stand-in TEE: no isolation, no security)", Appraise: a.appraise,
		LogSessions: cfg.ClientCA != "",
		// no claim about hardware (there is none); the measurement matched a reference value
		Trust:   map[string]int{"hardware": 0, "executables": 2, "configuration": 0, "runtime-opaque": 0},
		Summary: func(ann map[string]string) string { return "measurement " + ann["measurement"][:16] + "…" }}
	tc, err := mtls.ServerTLS(cfg.ClientCA)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: mtls.Authorize(cfg.ClientCA != "", cfg.Clients, api.Routes()),
		ReadHeaderTimeout: 10 * time.Second, TLSConfig: tc}
	log.Printf("sim-verifier listening on %s (software stand-in TEE, no security); attestation keys %d, reference measurements %d; client CA %q, callers %v",
		cfg.Listen, len(a.keys), len(a.measurements), cfg.ClientCA, cfg.Clients)
	log.Fatal(srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey))
}
