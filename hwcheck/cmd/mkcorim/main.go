// Command mkcorim writes the unsigned CoRIM that provisions the Veraison sevsnp scheme: one trust anchor CoMID holding
// AMD's ARK (the self-signed certificate of a KDS cert_chain file; the scheme expects exactly one per ARK) and one
// reference-value CoMID per launch, made from a SEV-SNP report of that launch by go-gen-ref's ReportToComid, the
// converter the scheme itself applies to Evidence.
//
// Reference values taken from a report are trust on first use: they state what this launch measured, not what the
// launch should measure. Independent values (the firmware vendor's signed launch endorsements) replace them later.
// Each reference-value environment is keyed as the scheme looks it up: the class of the signing key (by chip for a
// VCEK, by CSP for a VLEK) and the 48-octet launch MEASUREMENT.
//
//	mkcorim -kds cert_chain.pem -out corim.cbor launch1/evidence.tsm.cbor launch2/evidence.tsm.cbor ...
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/uuid"
	sevsnpParser "github.com/jraman567/go-gen-ref/cmd/sevsnp"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
)

const profile = "tag:amd.com,2024:snp-corim-profile" // the profile veraison-services' sevsnp scheme registers

func main() {
	kdsPath := flag.String("kds", "", "AMD KDS cert_chain (PEM); the self-signed certificate is the ARK")
	out := flag.String("out", "corim.cbor", "where to write the CoRIM")
	flag.Parse()

	if flag.NArg() == 0 {
		must(errors.New("give one TSM report token (evidence.tsm.cbor) per launch"))
	}
	var rvs []*comid.Comid
	var signers []string
	for _, path := range flag.Args() {
		tok, err := os.ReadFile(path)
		must(err)
		var tsm struct {
			OutBlob []byte `cbor:"outblob"`
		}
		must(cbor.Unmarshal(tok, &tsm))
		report, err := abi.ReportToProto(tsm.OutBlob)
		must(err)
		rv, err := sevsnpParser.ReportToComid(report, 0)
		must(err)
		// The scheme looks reference values up by the class of the signing key and the launch MEASUREMENT
		// (GetReferenceValueIDs); ReportToComid names the environment by CHIP_ID or by nothing, so re-key it.
		if rv.Triples.ReferenceValues == nil || len(rv.Triples.ReferenceValues.Values) != 1 {
			must(errors.New("expected one reference-value triple from ReportToComid"))
		}
		inst, err := comid.NewBytesInstance(report.GetMeasurement())
		must(err)
		rv.Triples.ReferenceValues.Values[0].Environment.Instance = inst
		must(rv.Valid())
		rvs = append(rvs, rv)
		signers = append(signers, signer(report.GetSignerInfo()))
	}

	ark := arkFrom(*kdsPath)
	arkPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ark.Raw}))
	key, err := comid.NewPKIXBase64Cert(arkPEM)
	must(err)
	if len(ark.Subject.Organization) == 0 {
		must(errors.New("ARK has no organization"))
	}
	vendor, model := ark.Subject.Organization[0], ark.Subject.CommonName
	ta := comid.NewComid().SetLanguage("en-GB").SetTagIdentity(uuid.New(), 0).
		AddAttestVerifKey(&comid.KeyTriple{
			Environment: comid.Environment{Class: &comid.Class{Vendor: &vendor, Model: &model}},
			VerifKeys:   comid.CryptoKeys{key},
		})
	must(ta.Valid())

	c := corim.NewUnsignedCorim().SetID(uuid.New().String()).SetProfile(profile)
	for _, rv := range rvs {
		c.AddComid(rv)
	}
	c.AddComid(ta)
	b, err := c.ToCBOR()
	must(err)
	must(os.WriteFile(*out, b, 0o644))
	fmt.Printf("wrote %s: %d octets; trust anchor %s / %s; reference values for %d launches, reports signed by %v\n",
		*out, len(b), vendor, model, len(rvs), signers)
}

func signer(info uint32) string {
	si, err := abi.ParseSignerInfo(info)
	if err != nil {
		return fmt.Sprintf("signer info %#x", info)
	}
	return si.SigningKey.String()
}

func arkFrom(path string) *x509.Certificate {
	b, err := os.ReadFile(path)
	must(err)
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		must(err)
		if bytes.Equal(c.RawSubject, c.RawIssuer) {
			return c
		}
	}
	must(errors.New("no self-signed certificate (ARK) in " + path))
	return nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkcorim:", err)
		os.Exit(1)
	}
}
