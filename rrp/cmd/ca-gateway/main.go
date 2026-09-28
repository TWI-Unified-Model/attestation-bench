// Command ca-gateway is the test bench's Credential Authority as a RATS Relying Party: it answers attest-initiate
// for its Targets with Handles it mints, and for attest-enroll it checks the Target's policy, freshness, the binding
// value it recomputes with its own identifier against verified Attestation Results, proof of possession, and that
// the attested launch may hold the identity the Credential Hint names; then step-ca certifies the CSR's key with the
// names the policy assigns.
//
//	ca-gateway -config ca-gateway.json
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/TWI-Unified-Model/tacra/bundle"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/fresh"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/gateway"
)

type fileConfig struct {
	gateway.Config
	StepCA stepCAConfig `json:"step_ca"`
}

// EnrollRequest is attest-enroll as the EST Server forwards it to this RRP.
type EnrollRequest struct {
	gateway.SecondLeg
	CSR bundle.B64 `json:"csr"`
}

// EnrollResponse carries the certificate chain, leaf first.
type EnrollResponse struct {
	CertificateChain []bundle.B64 `json:"certificate_chain"`
}

type server struct {
	g  *gateway.Gateway
	ca *stepCA
}

func (s *server) enroll(req *EnrollRequest) (*EnrollResponse, error) {
	csr, err := x509.ParseCertificateRequest(req.CSR)
	if err != nil {
		return nil, &gateway.Error{Status: http.StatusBadRequest, Code: "malformed", Err: err}
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, &gateway.Error{Status: http.StatusForbidden, Code: "proof-of-possession", Err: gateway.ErrPoP}
	}
	res, t, err := s.g.Check(&req.SecondLeg, req.CSR)
	if err != nil {
		return nil, err
	}
	id, ok := t.Identities[req.CredentialHint]
	if !ok {
		return nil, &gateway.Error{Status: http.StatusForbidden, Code: "credential-hint",
			Err: errors.New("no identity for this Credential Hint at this Target")}
	}
	if !gateway.Allowed(res.Measurement, id.Measurements) {
		return nil, &gateway.Error{Status: http.StatusForbidden, Code: "identity",
			Err: errors.New("the attested launch may not hold this identity")}
	}
	// The CA assigns the names; the CSR proves possession and may name only the identity requested.
	if (csr.Subject.CommonName != "" && csr.Subject.CommonName != req.CredentialHint) ||
		len(csr.DNSNames)+len(csr.URIs)+len(csr.IPAddresses)+len(csr.EmailAddresses) > 0 {
		return nil, &gateway.Error{Status: http.StatusForbidden, Code: "csr-names",
			Err: errors.New("the CSR may carry only the requested identity as its common name")}
	}
	chain, err := s.ca.sign(req.CSR, req.CredentialHint, id.SANs, id.Validity)
	if err != nil {
		return nil, &gateway.Error{Status: http.StatusBadGateway, Code: "credential-authority", Err: err}
	}
	out := &EnrollResponse{}
	for _, c := range chain {
		out.CertificateChain = append(out.CertificateChain, c)
	}
	return out, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tacra/v1/initiate", func(w http.ResponseWriter, r *http.Request) {
		var req gateway.InitiateRequest
		if err := gateway.DecodeJSON(r, &req); err != nil {
			gateway.WriteError(w, err)
			return
		}
		resp, err := s.g.Initiate(req)
		if err != nil {
			gateway.WriteError(w, err)
			return
		}
		gateway.WriteJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("POST /tacra/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req EnrollRequest
		if err := gateway.DecodeJSON(r, &req); err != nil {
			gateway.WriteError(w, err)
			return
		}
		resp, err := s.enroll(&req)
		if err != nil {
			log.Printf("enroll refused: target=%s kind=%s: %v", req.Target, req.FreshnessKind, err)
			gateway.WriteError(w, err)
			return
		}
		log.Printf("enrolled: target=%s kind=%s hint=%s", req.Target, req.FreshnessKind, req.CredentialHint)
		gateway.WriteJSON(w, http.StatusOK, resp)
	})
	return mux
}

func main() {
	path := flag.String("config", "ca-gateway.json", "configuration file")
	flag.Parse()
	var fc fileConfig
	if err := gateway.DecodeConfigFile(*path, &fc); err != nil {
		log.Fatal(err)
	}
	if err := fc.Validate(); err != nil {
		log.Fatal(err)
	}
	keys, err := fc.TrustedKeys()
	if err != nil {
		log.Fatal(err)
	}
	ca, err := newStepCA(fc.StepCA)
	if err != nil {
		log.Fatal(err)
	}
	g := &gateway.Gateway{Config: &fc.Config, Mode: "enroll", Fresh: fresh.New(nil),
		EAR: &ear.Verifier{Keys: keys, MaxAge: time.Duration(fc.EAR.MaxAgeS) * time.Second,
			Skew: time.Duration(fc.EAR.SkewS) * time.Second}}
	if err := g.LoadEpoch(); err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: fc.Listen, Handler: (&server{g: g, ca: ca}).routes(), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	log.Printf("ca-gateway %s listening on %s", fc.RRPID, fc.Listen)
	log.Fatal(srv.ListenAndServeTLS(fc.TLSCert, fc.TLSKey))
}
