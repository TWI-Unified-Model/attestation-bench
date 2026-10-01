package cai

import (
	"bytes"
	"context"
	"errors"
	"testing"

	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
)

// recordingPlugin records the Relying Party identifier each Evidence is asked to bind; the simulated
// plug-in itself does not read it.
type recordingPlugin struct {
	*platform.Simulated
	bound []string
}

func (r *recordingPlugin) GenerateEvidence(req platform.EvidenceRequest) (*platform.Evidence, error) {
	r.bound = append(r.bound, req.RelyingParty)
	return r.Simulated.GenerateEvidence(req)
}

func initiateAs(mode Mode, rrpID string) func(context.Context, *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
	return func(context.Context, *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
		resp := &caapiv1.InitiateCredentialAcquisitionResponse{Mode: mode, FreshnessKind: FreshnessPresentNonce,
			FreshnessHandle: bytes.Repeat([]byte{7}, 32), RrpId: &rrpID}
		if mode == ModeEnroll {
			resp.SigningAlgorithm = new(SigningAlgorithmECDSAP256)
		} else {
			resp.EncryptionAlgorithm = new(EncryptionAlgorithmECDHP256)
		}
		return resp, nil
	}
}

// TACRA Section 4.5, item 3: the CAI holds the identifier for each Target and mode and does not take it
// from the CAS. The response names another Credential Authority; the Evidence binds the held one.
func TestRelyingPartyFromConfiguration(t *testing.T) {
	sim, err := platform.NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	p := &recordingPlugin{Simulated: sim}
	fake := &fakeCAAPI{init: initiateAs(ModeEnroll, "https://other-ca.example"),
		enroll: func(_ context.Context, in *caapiv1.EnrollCredentialRequest) (*caapiv1.EnrollCredentialResponse, error) {
			return &caapiv1.EnrollCredentialResponse{PlaintextCredential: testCA.mint(t, in.GetCsr(), "")}, nil
		}}
	c, err := New(p, fake, testRelyingParties...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AcquireCredential(context.Background(), "https://api.example", CredentialTypeX509, ""); err != nil {
		t.Fatal(err)
	}
	if len(p.bound) != 1 || p.bound[0] != "https://ca.example" {
		t.Fatalf("Evidence bound %v, want the held https://ca.example", p.bound)
	}
}

// The identifier is held per mode: when the CAS selects Retrieval, the Secret Vault's is bound; when it selects
// a mode for which nothing is held, the CAI produces no Evidence and asks the CAS for nothing more.
func TestRelyingPartyPerMode(t *testing.T) {
	sim, err := platform.NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	p := &recordingPlugin{Simulated: sim}
	asked := false
	fake := &fakeCAAPI{init: initiateAs(ModeEnroll, "https://ca.example"),
		enroll: func(_ context.Context, in *caapiv1.EnrollCredentialRequest) (*caapiv1.EnrollCredentialResponse, error) {
			asked = true
			return &caapiv1.EnrollCredentialResponse{PlaintextCredential: testCA.mint(t, in.GetCsr(), "")}, nil
		}}
	c, err := New(p, fake, WithRelyingParty("https://api.example", ModeRetrieve, "https://vault.example"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.AcquireCredential(context.Background(), "https://api.example", CredentialTypeX509, "")
	if !errors.Is(err, ErrNoRelyingParty) || asked || len(p.bound) != 0 {
		t.Fatalf("got %v, enroll asked %v, Evidence %v", err, asked, p.bound)
	}
	// nothing held for the Target at all
	c2, _ := New(p, fake)
	if _, err := c2.AcquireCredential(context.Background(), "https://api.example", CredentialTypeX509, ""); !errors.Is(err, ErrNoRelyingParty) {
		t.Fatalf("no configuration: %v", err)
	}
}
