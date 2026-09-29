// vlekcheck: does go-sev-guest accept a SEV-SNP report (a) with no TrustedRoots, as Veraison's sevsnp
// scheme calls it, (b) with the VLEK product chain (ASVK and ARK) as TrustedRoots, (c) with both the VCEK
// and the VLEK chains? See hwcheck/evidence/20260929-go-sev-guest-v0.15.0-vlek/README.md.
//
//	cd hwcheck/vlekcheck && export GOWORK=off GOFLAGS=-mod=mod   # go.sum is not kept in this repository
//	go build -o vlekcheck-v0.15.0 .
//	go build -modfile=go.old.mod -o vlekcheck-old .   # the version veraison-services pins
//	./vlekcheck-v0.15.0 ../evidence/<run>/<case>/evidence.tsm.cbor
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	must(err)
	var m map[any]any
	must(cbor.Unmarshal(raw, &m))
	var outblob, auxblob []byte
	for k, v := range m {
		fmt.Printf("  cbor key %v (%T)\n", k, v)
		switch k {
		case "outblob":
			outblob = v.([]byte)
		case "auxblob":
			auxblob = v.([]byte)
		}
	}
	rep, err := abi.ReportToProto(outblob)
	must(err)
	certs := new(abi.CertTable)
	must(certs.Unmarshal(auxblob))
	chain := certs.Proto()
	si, err := abi.ParseSignerInfo(rep.GetSignerInfo())
	must(err)
	fmt.Printf("  report signer: %v; chain has VLEK %d B, VCEK %d B, ASK %d B, ARK %d B\n",
		si.SigningKey, len(chain.GetVlekCert()), len(chain.GetVcekCert()),
		len(chain.GetAskCert()), len(chain.GetArkCert()))
	for _, c := range []struct {
		slot string
		der  []byte
	}{{"VLEK", chain.GetVlekCert()}, {"VCEK", chain.GetVcekCert()}, {"ASK", chain.GetAskCert()}, {"ARK", chain.GetArkCert()}} {
		if len(c.der) == 0 {
			continue
		}
		cert, err := trust.ParseCert(c.der)
		must(err)
		fmt.Printf("  table slot %-4s: CN %q, issuer CN %q\n", c.slot, cert.Subject.CommonName, cert.Issuer.CommonName)
	}
	att := &spb.Attestation{Report: rep, CertificateChain: chain}
	base := verify.Options{Now: time.Now(), DisableCertFetching: true, CheckRevocations: false, Getter: trust.DefaultHTTPSGetter()}

	a := base
	fmt.Printf("(a) no TrustedRoots:            %v\n", res(verify.SnpAttestation(att, &a)))

	vlekRoots := &trust.AMDRootCerts{ProductLine: "Milan"}
	must(vlekRoots.FromKDSCertBytes(trust.AskArkMilanVlekBytes))
	b := base
	b.TrustedRoots = map[string][]*trust.AMDRootCerts{"Milan": {vlekRoots}}
	fmt.Printf("(b) TrustedRoots = Milan VLEK:  %v\n", res(verify.SnpAttestation(att, &b)))

	vcekRoots := &trust.AMDRootCerts{ProductLine: "Milan"}
	must(vcekRoots.FromKDSCertBytes(trust.AskArkMilanVcekBytes))
	c := base
	c.TrustedRoots = map[string][]*trust.AMDRootCerts{"Milan": {vcekRoots, vlekRoots}}
	fmt.Printf("(c) TrustedRoots = VCEK + VLEK: %v\n", res(verify.SnpAttestation(att, &c)))
}

func res(err error) string {
	if err == nil {
		return "ACCEPTED"
	}
	return "REJECTED: " + err.Error()
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
