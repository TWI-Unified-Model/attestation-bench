// Command caapi-est is the CAS Client of the end-to-end run: it serves the CAAPI (the CAI's side of the Credential
// Acquisition System) and carries each call to an EST server with the attest-* resources of the revised EST profile.
// It is a conduit: it passes the CAI's Evidence, CSR, CEKpub and freshness element on, and the server's answers
// back, without reading or changing them.
//
//	caapi-est -listen 127.0.0.1:50061 -est localhost:18443 -anchor bench-tls-root.crt
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/TWI-Unified-Model/tacra/bundle"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/globalsign/est"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type bridge struct {
	caapiv1.UnimplementedCredentialAcquisitionServiceServer
	est *est.Client
}

var credTypes = map[caapiv1.CredentialType]string{
	caapiv1.CredentialType_CREDENTIAL_TYPE_JWT: est.CredentialTypeJWT, caapiv1.CredentialType_CREDENTIAL_TYPE_PSK: est.CredentialTypePSK,
	caapiv1.CredentialType_CREDENTIAL_TYPE_API_KEY: est.CredentialTypeAPIKey, caapiv1.CredentialType_CREDENTIAL_TYPE_X509: est.CredentialTypeX509,
	caapiv1.CredentialType_CREDENTIAL_TYPE_WIC: est.CredentialTypeWIC, caapiv1.CredentialType_CREDENTIAL_TYPE_WIT: est.CredentialTypeWIT,
}

var kinds = map[string]caapiv1.FreshnessKind{
	est.FreshnessAbsentNone: caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_NONE, est.FreshnessAbsentTimestamp: caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_TIMESTAMP,
	est.FreshnessAbsentEpoch: caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_EPOCH, est.FreshnessPresentNonce: caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
	est.FreshnessPresentEpoch: caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_EPOCH,
}

func kindName(k caapiv1.FreshnessKind) string {
	for n, v := range kinds {
		if v == k {
			return n
		}
	}
	return ""
}

// grpcError maps an EST server refusal to a gRPC status the CAI understands.
func grpcError(err error) error {
	var e est.Error
	if !errors.As(err, &e) {
		return status.Error(codes.Unavailable, err.Error())
	}
	switch e.StatusCode() {
	case http.StatusBadRequest, http.StatusUnsupportedMediaType:
		return status.Error(codes.InvalidArgument, e.Error())
	case http.StatusForbidden, http.StatusUnauthorized:
		return status.Error(codes.PermissionDenied, e.Error())
	case http.StatusConflict:
		return status.Error(codes.Aborted, e.Error()) // freshness no longer valid: retry from Initiate
	case http.StatusTooManyRequests:
		return status.Error(codes.ResourceExhausted, e.Error())
	}
	return status.Error(codes.Unavailable, e.Error())
}

func (b *bridge) InitiateRemoteAttestation(ctx context.Context, in *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
	ct, ok := credTypes[in.GetCredentialType()]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unsupported Credential Type")
	}
	r, err := b.est.InitiateRemoteAttestation(ctx, in.GetTarget(), ct)
	if err != nil {
		return nil, grpcError(err)
	}
	out := &caapiv1.InitiateCredentialAcquisitionResponse{FreshnessKind: kinds[r.FreshnessKind]}
	if r.RRPID != "" {
		out.RrpId = &r.RRPID
	}
	if len(r.Handle) > 0 {
		out.FreshnessHandle = r.Handle
	}
	switch r.Mechanism {
	case est.MechanismEnroll:
		out.Mode = caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL
		if slices.Contains(r.AcceptableCSK, "ecdsa-p256-sha256") {
			out.SigningAlgorithm = caapiv1.SigningAlgorithm_SIGNING_ALGORITHM_ECDSA_P256.Enum()
		}
	case est.MechanismRetrieve:
		out.Mode = caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE
		for _, a := range r.AcceptableCEK {
			if strings.HasPrefix(a, "DHKEM(P-256") {
				out.EncryptionAlgorithm = caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_ECDH_P256.Enum()
			}
		}
		// the hpke-base-signed container (tacra-est decision 4), when the RRP accepts it: preferred
		if slices.Contains(r.AcceptableCEK, bundle.AcceptableSigned) {
			out.EncryptionAlgorithm = caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_MLKEM768_P256.Enum()
		}
	}
	return out, nil
}

func hintPtr(s *string) *string {
	if s == nil || *s == "" {
		return nil
	}
	return s
}

func (b *bridge) EnrollCredential(ctx context.Context, in *caapiv1.EnrollCredentialRequest) (*caapiv1.EnrollCredentialResponse, error) {
	ct, ok := credTypes[in.GetCredentialType()]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unsupported Credential Type")
	}
	cert, err := b.est.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{Target: in.GetTarget(), CredentialType: ct,
		FreshnessKind: kindName(in.GetFreshnessKind()), Handle: in.GetFreshnessElement(), CSR: in.GetCsr(),
		Evidence: in.GetEvidence(), Binding: est.Binding{Method: est.BindingInput, Hash: "sha512"},
		Profile: in.GetEvidenceProfile(), CredentialHint: hintPtr(in.CredentialHint)})
	if err != nil {
		return nil, grpcError(err)
	}
	return &caapiv1.EnrollCredentialResponse{PlaintextCredential: cert.Raw}, nil
}

func (b *bridge) RetrieveCredential(ctx context.Context, in *caapiv1.RetrieveCredentialRequest) (*caapiv1.RetrieveCredentialResponse, error) {
	ct, ok := credTypes[in.GetCredentialType()]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unsupported Credential Type")
	}
	raw, err := b.est.RetrieveCredentialRaw(ctx, &est.AttestedRetrievalRequest{Target: in.GetTarget(), CredentialType: ct,
		FreshnessKind: kindName(in.GetFreshnessKind()), Handle: in.GetFreshnessElement(), CEKPub: in.GetCekPub(),
		Evidence: in.GetEvidence(), Binding: est.Binding{Method: est.BindingInput, Hash: "sha512"},
		Profile: in.GetEvidenceProfile(), CredentialHint: hintPtr(in.CredentialHint)})
	if err != nil {
		return nil, grpcError(err)
	}
	return &caapiv1.RetrieveCredentialResponse{WrappedCredential: raw}, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:50061", "CAAPI listen address (local only)")
	host := flag.String("est", "localhost:18443", "EST server host:port")
	anchor := flag.String("anchor", "", "PEM file with the EST server's TLS trust anchor")
	flag.Parse()
	pem, err := os.ReadFile(*anchor)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatal("no certificate in " + *anchor)
	}
	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer()
	caapiv1.RegisterCredentialAcquisitionServiceServer(s, &bridge{est: &est.Client{Host: *host, ExplicitAnchor: pool}})
	log.Printf("caapi-est: CAAPI on %s, EST server %s", *listen, *host)
	log.Fatal(s.Serve(lis))
}
