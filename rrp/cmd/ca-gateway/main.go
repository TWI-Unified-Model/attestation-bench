// Command ca-gateway is the test bench's Credential Authority as a RATS Relying Party: it answers attest-initiate
// for its Targets with Handles it mints, and for attest-enroll it checks the Target's policy, freshness, the binding
// value it recomputes with its own identifier against verified Attestation Results, and proof of possession; then it
// assigns an identity of the Target that the attested launch may hold, and step-ca certifies the CSR's key with the
// names the policy gives that identity.
//
//	ca-gateway -config ca-gateway.json
package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/TWI-Unified-Model/tacra/bundle"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/fresh"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/gateway"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/mtls"
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
	name, id, err := assignIdentity(t, res.Measurement, csr, req.CredentialHint)
	if err != nil {
		return nil, err
	}
	chain, err := s.ca.sign(req.CSR, name, id.SANs, id.Validity)
	if err != nil {
		return nil, &gateway.Error{Status: http.StatusBadGateway, Code: "credential-authority", Err: err}
	}
	out := &EnrollResponse{}
	for _, c := range chain {
		out.CertificateChain = append(out.CertificateChain, c)
	}
	return out, nil
}

// assignIdentity is where the CA assigns the name: an identity of the Target that the attested launch may hold,
// chosen only by what the binding covers. With one such identity the CSR needs no name; with several, the bound CSR
// names one as its only subject attribute, the common name, since the Credential Hint travels outside the binding
// and a conduit that rewrites it could otherwise pick another (tacra-est formal/gaps p0-b7). A hint, if present,
// must be the identity assigned. The CSR asks for no names of its own: the policy gives them.
func assignIdentity(t *gateway.Target, measurement []byte, csr *x509.CertificateRequest, hint string) (string, *gateway.Identity, error) {
	if len(csr.DNSNames)+len(csr.URIs)+len(csr.IPAddresses)+len(csr.EmailAddresses) > 0 {
		return "", nil, &gateway.Error{Status: http.StatusForbidden, Code: "csr-names",
			Err: errors.New("the CSR asks for names; the CA assigns them")}
	}
	var held []string
	for n, id := range t.Identities {
		if gateway.Allowed(measurement, id.Measurements) {
			held = append(held, n)
		}
	}
	sort.Strings(held)
	var name string
	switch {
	case len(csr.Subject.Names) == 0:
		if len(held) != 1 {
			return "", nil, &gateway.Error{Status: http.StatusForbidden, Code: "csr-names",
				Err: fmt.Errorf("the attested launch may hold %d identities at this Target; the bound CSR must name one", len(held))}
		}
		name = held[0]
	case len(csr.Subject.Names) == 1 && csr.Subject.CommonName != "":
		name = csr.Subject.CommonName
		if id, ok := t.Identities[name]; !ok || !gateway.Allowed(measurement, id.Measurements) {
			return "", nil, &gateway.Error{Status: http.StatusForbidden, Code: "identity",
				Err: errors.New("the attested launch may not hold the identity the CSR names")}
		}
	default:
		return "", nil, &gateway.Error{Status: http.StatusForbidden, Code: "csr-names",
			Err: errors.New("the CSR subject must be empty or the common name alone")}
	}
	if hint != "" && hint != name {
		return "", nil, &gateway.Error{Status: http.StatusForbidden, Code: "credential-hint",
			Err: errors.New("the Credential Hint is not the identity the CA assigns")}
	}
	return name, t.Identities[name], nil
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
			log.Printf("enroll refused: target=%s kind=%s caller=%v: %v", req.Target, req.FreshnessKind, mtls.Names(r), err)
			gateway.WriteError(w, err)
			return
		}
		log.Printf("enrolled: target=%s kind=%s hint=%q caller=%v", req.Target, req.FreshnessKind, req.CredentialHint, mtls.Names(r))
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
	if fc.RATSModel == gateway.BackgroundCheck {
		if g.Appraiser, err = gateway.NewAppraiser(&fc.Config); err != nil {
			log.Fatal(err)
		}
	}
	if err := g.LoadEpoch(); err != nil {
		log.Fatal(err)
	}
	tc, err := fc.ServerTLS()
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: fc.Listen, Handler: fc.Guard((&server{g: g, ca: ca}).routes()), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: tc}
	log.Printf("ca-gateway %s listening on %s; client CA %q, protocol callers %v", fc.RRPID, fc.Listen, fc.ClientCA, fc.Clients)
	log.Fatal(srv.ListenAndServeTLS(fc.TLSCert, fc.TLSKey))
}
