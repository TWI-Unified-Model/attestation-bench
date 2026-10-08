// Command caapi-est is the CAS Client of the end-to-end run: it serves the CAAPI (the CAI's side of the Credential
// Acquisition System) and carries each call to an EST server with the attest-* resources of the revised EST profile.
// It is a conduit: it passes the CAI's Evidence, CSR, CEKpub and freshness element on, and the server's answers
// back, without reading or changing them, unless -attack names one of the drills of docs/attacks.md, section 6, in
// which it does to the Retrieval container what TACRA's untrusted conduit could:
//
//	seal  returns, in place of the Vault's container, one it sealed itself to the Attester's CEKpub with keys of its
//	      own: the container type and associated data of the Vault's, another secret (TACRA leaves the CAS Server the
//	      option of encrypting to CEKpub itself; this is that container);
//	swap  returns to each Retrieval after the first the Vault's container of the Retrieval before it;
//	hint  asks the Vault with the Credential Hint of a workload the Target serves no group to;
//	hint-group  asks the Vault with the Credential Hint of another group the Target serves to the same launches
//	      (packs/tacra-bench, other_groups): the Vault releases that group's secret, sealed to the Attester's CEKpub.
//
// Each act is one line of its log, "conduit attack NAME: Retrieval for TARGET: …", which scripts/verdict.py reads.
//
//	caapi-est -listen 127.0.0.1:50061 -est localhost:18443 -anchor bench-tls-root.crt [-attack seal|swap|hint|hint-group]
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/TWI-Unified-Model/tacra/bundle"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/globalsign/est"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type bridge struct {
	caapiv1.UnimplementedCredentialAcquisitionServiceServer
	est    *est.Client
	attack *attack // nil: an honest conduit
}

// attack is the conduit of a drill (-attack): what it does to each Retrieval.
type attack struct {
	name string

	signKey *ecdsa.PrivateKey  // seal: its own signature key, for an hpke-base-signed container
	sender  *bundle.SenderKeys // seal: its own static KEM keys, for an hpke-auth container
	mu      sync.Mutex
	prev    []byte // swap: the Vault's container of the Retrieval before this one
}

// The Credential Hints the conduit of the hint drills sends in place of the Attester's: one the Target serves no group
// to, and one it serves another group to (packs/tacra-bench, other_groups).
var otherHints = map[string]string{"hint": "reports.workload.tacra.example", "hint-group": "audit.workload.tacra.example"}

func newAttack(name string) (*attack, error) {
	switch name {
	case "":
		return nil, nil
	case "seal", "swap", "hint", "hint-group":
	default:
		return nil, fmt.Errorf("-attack %q: seal, swap, hint or hint-group", name)
	}
	a := &attack{name: name}
	var err error
	if a.signKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, err
	}
	if a.sender, err = bundle.GenerateSenderKeys(); err != nil {
		return nil, err
	}
	return a, nil
}

// nameOrNone is the drill's name, or "" for an honest conduit.
func (a *attack) nameOrNone() string {
	if a == nil {
		return ""
	}
	return a.name
}

func (a *attack) logf(target, format string, v ...any) {
	log.Printf("conduit attack %s: Retrieval for %s: %s", a.name, target, fmt.Sprintf(format, v...))
}

// container is what the conduit returns to the CAI in place of the Vault's container raw.
func (a *attack) container(target string, cekPub, raw []byte) ([]byte, error) {
	switch a.name {
	case "seal":
		var v bundle.Bundle
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		no := false
		content := bundle.Content{CredentialItems: []bundle.Item{{Type: "api-key", Value: "a key the conduit chose",
			Purpose: []string{"authenticate"}, Algorithm: "opaque-bearer", Exportable: &no}},
			Metadata: map[string]any{"validity_seconds": 3600}}
		var own *bundle.Bundle
		var err error
		switch v.Container {
		case bundle.ContainerSigned:
			own, err = bundle.SealSigned(a.signKey, cekPub, v.AAD, content)
		case bundle.Container:
			own, err = bundle.Seal(a.sender, cekPub, v.AAD, content)
		default:
			return nil, fmt.Errorf("seal: the Vault's container is %q", v.Container)
		}
		if err != nil {
			return nil, err
		}
		a.logf(target, "returned its own %s container, sealed to the Attester's CEKpub with the conduit's keys, the "+
			"Vault's associated data kept", v.Container)
		return json.Marshal(own)
	case "swap":
		a.mu.Lock()
		defer a.mu.Unlock()
		prev := a.prev
		a.prev = raw
		if prev == nil {
			a.logf(target, "the first Retrieval: returned the Vault's own container, kept for the next")
			return raw, nil
		}
		var v bundle.Bundle
		_ = json.Unmarshal(prev, &v)
		a.logf(target, "returned the Vault's container of the Retrieval before, for %s", v.AAD.Target)
		return prev, nil
	}
	return raw, nil
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
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
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
	req := &est.AttestedRetrievalRequest{Target: in.GetTarget(), CredentialType: ct,
		FreshnessKind: kindName(in.GetFreshnessKind()), Handle: in.GetFreshnessElement(), CEKPub: in.GetCekPub(),
		Evidence: in.GetEvidence(), Binding: est.Binding{Method: est.BindingInput, Hash: "sha512"},
		Profile: in.GetEvidenceProfile(), CredentialHint: hintPtr(in.CredentialHint)}
	if h, ok := otherHints[b.attack.nameOrNone()]; ok {
		b.attack.logf(in.GetTarget(), "sent the Credential Hint %q in place of the Attester's %q", h, in.GetCredentialHint())
		req.CredentialHint = &h
	}
	raw, err := b.est.RetrieveCredentialRaw(ctx, req)
	if err != nil {
		if b.attack != nil {
			b.attack.logf(in.GetTarget(), "the EST server answered: %v", err)
		}
		return nil, grpcError(err)
	}
	if b.attack != nil {
		if raw, err = b.attack.container(in.GetTarget(), in.GetCekPub(), raw); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return &caapiv1.RetrieveCredentialResponse{WrappedCredential: raw}, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:50061", "CAAPI listen address (local only)")
	host := flag.String("est", "localhost:18443", "EST server host:port")
	anchor := flag.String("anchor", "", "PEM file with the EST server's TLS trust anchor")
	attackName := flag.String("attack", "", "a drill of docs/attacks.md, section 6: seal, swap, hint or hint-group (none: honest)")
	flag.Parse()
	drill, err := newAttack(*attackName)
	if err != nil {
		log.Fatal(err)
	}
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
	caapiv1.RegisterCredentialAcquisitionServiceServer(s, &bridge{est: &est.Client{Host: *host, ExplicitAnchor: pool}, attack: drill})
	log.Printf("caapi-est: CAAPI on %s, EST server %s", *listen, *host)
	if drill != nil {
		log.Printf("caapi-est: the conduit of the drill %q (docs/attacks.md, section 6)", drill.name)
	}
	log.Fatal(s.Serve(lis))
}
