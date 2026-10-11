package platform

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
)

// The plug-in's tests run on real data only: the draft's test vector, and the reports and certificate tables that
// hardware runs kept (hwcheck/evidence), from Google Cloud (signed with the chip's VCEK) and AWS (signed with a
// VLEK). Making Evidence needs the TSM device of a confidential VM: GenerateEvidence runs in every hardware run.
const (
	gcpRun = "../hwcheck/evidence/20261007T134801Z-gcp-sev-snp"
	awsRun = "../hwcheck/evidence/20261007T134512Z-aws-sev-snp"
)

// recorded is the TSM token of a run's honest Enrollment Evidence, as the plug-in made it on the hardware.
func recorded(t *testing.T, run string) tsmReport {
	t.Helper()
	raw, err := os.ReadFile(run + "/enroll-present-nonce/evidence.tsm.cbor")
	if err != nil {
		t.Fatal(err)
	}
	var tok tsmReport
	if err := cbor.Unmarshal(raw, &tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

// The layout of before 12 October 2026, with the RRP identifier: the draft's test vector of 30 September still holds
// for BindingValueRRP, which appraises the committed runs of 6 to 11 October.
func TestBindingValueRRPMatchesDraftTestVector(t *testing.T) {
	handle, _ := hex.DecodeString(tvHandleHex)
	subject, _ := hex.DecodeString(tvSubjectHex)
	want, _ := hex.DecodeString(tvDigestHex)
	got := BindingValueRRP(handle, tvTarget, tvRRPID, subject)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("SHA-512(binding_input) = %x, want the draft's %x", got, want)
	}
	if n := len(BindingInputRRP(handle, tvTarget, tvRRPID, subject)); n != tvBindingInputLen {
		t.Fatalf("binding_input is %d octets, the draft's vector is %d", n, tvBindingInputLen)
	}
}

// The binding of 11 October 2026: three fields, and the Target bound.
func TestBindingValueThreeFields(t *testing.T) {
	handle, _ := hex.DecodeString(tvHandleHex)
	subject, _ := hex.DecodeString(tvSubjectHex)
	in := BindingInput(handle, tvTarget, subject)
	if n := len(in); n != tvBindingInputLen-4-len(tvRRPID) {
		t.Fatalf("binding_input is %d octets, want the draft's %d less the identifier field", n, tvBindingInputLen-4-len(tvRRPID))
	}
	if BindingValue(handle, tvTarget, subject) == BindingValue(handle, "https://other.tacra.example", subject) {
		t.Fatal("the Target is not bound")
	}
	if BindingValue(handle, tvTarget, subject) == BindingValueRRP(handle, tvTarget, "", subject) {
		t.Fatal("the three-field value equals the four-field one with an empty identifier: the layouts must differ")
	}
}

// TestRealCertificateTables: the host's table, as the plug-in reads it, holds the certificate that signs the
// reports and AMD's chain above it: on Google Cloud the VCEK, issued by SEV-Milan; on AWS the VLEK, issued by
// SEV-VLEK-Milan.
func TestRealCertificateTables(t *testing.T) {
	for _, c := range []struct {
		run, signer, issuer string
	}{{gcpRun, SNPCertVCEK, "SEV-Milan"}, {awsRun, SNPCertVLEK, "SEV-VLEK-Milan"}} {
		certs, err := ParseSNPCertTable(recorded(t, c.run).AuxBlob)
		if err != nil {
			t.Fatalf("%s: %v", c.run, err)
		}
		for _, name := range []string{c.signer, SNPCertASK, SNPCertARK} {
			if _, err := trust.ParseCert(certs[name]); err != nil {
				t.Fatalf("%s: %s: %v", c.run, name, err)
			}
		}
		signer, _ := trust.ParseCert(certs[c.signer])
		if signer.Issuer.CommonName != c.issuer {
			t.Errorf("%s: the %s is issued by %q, want %q", c.run, c.signer, signer.Issuer.CommonName, c.issuer)
		}
	}
}

// TestReportSigner: the key the plug-in keeps for AttestationPublicKey is the one that signed the report, the
// certificate the report's SIGNING_KEY names; a report changed by one octet does not verify under it, and a table
// without the certificate the report names gives no key.
func TestReportSigner(t *testing.T) {
	for _, c := range []struct {
		run, name string
	}{{gcpRun, SNPCertVCEK}, {awsRun, SNPCertVLEK}} {
		tok := recorded(t, c.run)
		rep, err := abi.ReportToProto(tok.OutBlob)
		if err != nil {
			t.Fatal(err)
		}
		pub := reportSigner(rep.GetSignerInfo(), tok.AuxBlob)
		if pub == nil {
			t.Fatalf("%s: no key for the report", c.run)
		}
		certs, _ := ParseSNPCertTable(tok.AuxBlob)
		cert, _ := trust.ParseCert(certs[c.name])
		if certKey, _ := cert.PublicKey.(*ecdsa.PublicKey); !pub.Equal(certKey) {
			t.Fatalf("%s: the key is not the %s's", c.run, c.name)
		}
		if err := verify.SnpReportSignature(tok.OutBlob, cert); err != nil {
			t.Fatalf("%s: the report does not verify under the %s: %v", c.run, c.name, err)
		}
		changed := append([]byte(nil), tok.OutBlob...)
		changed[0x50] ^= 1 // REPORT_DATA
		if err := verify.SnpReportSignature(changed, cert); err == nil {
			t.Fatalf("%s: a report with REPORT_DATA changed verifies", c.run)
		}
	}
	// the Google Cloud report names its VCEK; AWS's table holds a VLEK and no VCEK
	gcp := recorded(t, gcpRun)
	rep, _ := abi.ReportToProto(gcp.OutBlob)
	if pub := reportSigner(rep.GetSignerInfo(), recorded(t, awsRun).AuxBlob); pub != nil {
		t.Fatal("a key from a table that does not hold the certificate the report names")
	}
}
