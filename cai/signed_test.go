package cai

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TWI-Unified-Model/tacra/bundle"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
)

// mlkemPlugin is the simulated plug-in with an MLKEM768-P256 CEK. Its Evidence is a placeholder, since the fake CAAPI
// appraises nothing; it records the key each Evidence binds.
type mlkemPlugin struct {
	*platform.Simulated
	bound []crypto.PublicKey
}

func (m *mlkemPlugin) GenerateCEK(alg platform.EncryptionAlgorithm) (*platform.KeyPair, error) {
	if alg != platform.EncryptionAlgorithmMLKEM768P256 {
		return m.Simulated.GenerateCEK(alg)
	}
	sk, err := hpke.MLKEM768P256().GenerateKey()
	return &platform.KeyPair{Private: sk}, err
}

func (m *mlkemPlugin) GenerateEvidence(req platform.EvidenceRequest) (*platform.Evidence, error) {
	m.bound = append(m.bound, req.BoundKey)
	return &platform.Evidence{Token: []byte("evidence"), MediaType: "application/test"}, nil
}

// TestSignedContainer: Retrieval with an MLKEM768-P256 CEK and the hpke-base-signed container (tacra-est decision 4).
// The CAI sends the encapsulation key itself as CEKpub, binds that key in Evidence, and takes the credential only
// from a container signed by the Vault key it holds for the RRP, naming this request, sealed to this CEK and
// carrying items its policy takes.
func TestSignedContainer(t *testing.T) {
	const target, rrpID = "https://api.example", "https://vault.example"
	vaultKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	vaultSPKI, _ := x509.MarshalPKIXPublicKey(&vaultKey.PublicKey)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	handle := bytes.Repeat([]byte{0x0b}, 32)
	no, yes := false, true
	item := bundle.Item{Type: "api-key", Format: "raw", Value: "the-secret", Kid: "k1", Purpose: []string{"authenticate"},
		Algorithm: "API-KEY", Exportable: &no}

	var sentCEK [][]byte
	vault := func(key *ecdsa.PrivateKey, aadFn func(*bundle.AAD), it bundle.Item, validity int) *fakeCAAPI {
		return &fakeCAAPI{
			init: func(context.Context, *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
				return &caapiv1.InitiateCredentialAcquisitionResponse{Mode: ModeRetrieve, FreshnessKind: FreshnessPresentNonce,
					FreshnessHandle: handle, EncryptionAlgorithm: new(EncryptionAlgorithmMLKEM768P256)}, nil
			},
			retrieve: func(_ context.Context, in *caapiv1.RetrieveCredentialRequest) (*caapiv1.RetrieveCredentialResponse, error) {
				sentCEK = append(sentCEK, in.GetCekPub())
				aad := bundle.AAD{GroupID: "g1", RRPID: rrpID, Target: in.GetTarget(), Handle: in.GetFreshnessElement(),
					CredentialHint: in.GetCredentialHint()}
				if aadFn != nil {
					aadFn(&aad)
				}
				b, err := bundle.SealSigned(key, in.GetCekPub(), aad,
					bundle.Content{CredentialItems: []bundle.Item{it}, Metadata: map[string]any{"validity_seconds": validity}})
				if err != nil {
					return nil, err
				}
				raw, _ := json.Marshal(b)
				return &caapiv1.RetrieveCredentialResponse{WrappedCredential: raw}, nil
			},
		}
	}
	sim, err := platform.NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	acquire := func(fake *fakeCAAPI, signerFor string) (*Credential, *mlkemPlugin, error) {
		p := &mlkemPlugin{Simulated: sim}
		opts := append([]Option(nil), testRelyingParties...)
		if signerFor != "" {
			opts = append(opts, WithVaultSigner(signerFor, vaultSPKI))
		}
		c, err := New(p, fake, opts...)
		if err != nil {
			t.Fatal(err)
		}
		cred, err := c.AcquireCredential(context.Background(), target, CredentialTypeAPIKey, "")
		return cred, p, err
	}

	cred, p, err := acquire(vault(vaultKey, nil, item, 3600), rrpID)
	if err != nil {
		t.Fatalf("honest exchange: %v", err)
	}
	if string(cred.Document) != "the-secret" {
		t.Fatalf("document %q", cred.Document)
	}
	if len(sentCEK[0]) != 1249 {
		t.Fatalf("CEKpub sent is %d octets, want the 1249-octet MLKEM768-P256 encapsulation key", len(sentCEK[0]))
	}
	bound, ok := p.bound[0].(hpke.PublicKey)
	if !ok || !bytes.Equal(bound.Bytes(), sentCEK[0]) {
		t.Fatal("the Evidence did not bind the CEKpub that was sent")
	}

	for name, c := range map[string]struct {
		fake      *fakeCAAPI
		signerFor string
		want      error
	}{
		"signed by another key":                 {vault(other, nil, item, 3600), rrpID, ErrUnwrap},
		"a Vault key held only for another RRP": {vault(vaultKey, nil, item, 3600), "https://other-vault.example", ErrNoVaultSigner},
		"no Vault key held":                     {vault(vaultKey, nil, item, 3600), "", ErrNoVaultSigner},
		"another Target in the AAD":             {vault(vaultKey, func(a *bundle.AAD) { a.Target = "https://other.example" }, item, 3600), rrpID, ErrUnwrap},
		"another freshness element":             {vault(vaultKey, func(a *bundle.AAD) { a.Handle = bytes.Repeat([]byte{1}, 32) }, item, 3600), rrpID, ErrUnwrap},
		"an exportable item":                    {vault(vaultKey, nil, func() bundle.Item { i := item; i.Exportable = &yes; return i }(), 3600), rrpID, ErrUnwrap},
		"an item without attributes":            {vault(vaultKey, nil, bundle.Item{Type: "api-key", Value: "x", Kid: "k"}, 3600), rrpID, ErrUnwrap},
		"valid for a day":                       {vault(vaultKey, nil, item, 86400), rrpID, ErrUnwrap},
		"a shared private key":                  {vault(vaultKey, nil, func() bundle.Item { i := item; i.Shared = true; return i }(), 3600), rrpID, ErrUnwrap},
	} {
		if _, _, err := acquire(c.fake, c.signerFor); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}
