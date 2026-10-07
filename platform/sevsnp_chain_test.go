package platform

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"os"
	"testing"

	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/trust"
)

// TestCompleteCertTable, on the tables real hosts delivered (hwcheck/evidence): Google Cloud's holds the VCEK and
// AMD's chain, and is left as it is; AWS's held the VLEK alone, and the plug-in appended the Milan ASVK and ARK, which
// the run's Evidence records (cert-table-completed). The table with those two taken out again is the host's, and
// completing it gives back the run's.
func TestCompleteCertTable(t *testing.T) {
	gcp := recorded(t, gcpRun).AuxBlob
	out, added, err := completeCertTable(gcp)
	if err != nil || added || !bytes.Equal(out, gcp) {
		t.Fatalf("Google Cloud's complete table: added=%v err=%v changed=%v", added, err, !bytes.Equal(out, gcp))
	}

	aws := recorded(t, awsRun).AuxBlob
	entries, err := certTableEntries(aws)
	if err != nil {
		t.Fatal(err)
	}
	var host []certEntry
	for _, e := range entries {
		if g := hex.EncodeToString(e.guid); g != guidASK && g != guidARK {
			host = append(host, e)
		}
	}
	if len(host) != 1 || hex.EncodeToString(host[0].guid) != guidVLEK {
		t.Fatalf("AWS's table without ASK and ARK holds %d entries, want the VLEK alone", len(host))
	}
	out, added, err = completeCertTable(encodeCertTable(host))
	if err != nil || !added {
		t.Fatalf("AWS's table, VLEK alone: added=%v err=%v", added, err)
	}
	certs, err := ParseSNPCertTable(out)
	if err != nil {
		t.Fatal(err)
	}
	milanASVK, milanARK, err := kds.ParseProductCertChain(trust.AskArkMilanVlekBytes)
	if err != nil {
		t.Fatal(err)
	}
	run, _ := ParseSNPCertTable(aws)
	if !bytes.Equal(certs[SNPCertVLEK], run[SNPCertVLEK]) || !bytes.Equal(certs[SNPCertASK], milanASVK) ||
		!bytes.Equal(certs[SNPCertARK], milanARK) || !bytes.Equal(certs[SNPCertASK], run[SNPCertASK]) ||
		!bytes.Equal(certs[SNPCertARK], run[SNPCertARK]) {
		t.Fatal("AWS's VLEK completed is not VLEK + Milan ASVK + Milan ARK, as the run's Evidence holds")
	}

	// a certificate whose issuer names no AMD product line, in the VCEK's place: Google's root for its launch
	// endorsements (trust/), a real certificate that is not AMD's; the table is left as it is
	raw, err := os.ReadFile("../trust/GCE-cc-tcb-root_1.crt")
	if err != nil {
		t.Fatal(err)
	}
	google, err := trust.ParseCert(raw) // DER or PEM
	if err != nil {
		t.Fatal(err)
	}
	vcekGUID, _ := hex.DecodeString(guidVCEK)
	foreign := encodeCertTable([]certEntry{{vcekGUID, google.Raw}})
	out, added, err = completeCertTable(foreign)
	if err != nil || added || !bytes.Equal(out, foreign) {
		t.Fatalf("a table whose signer is not AMD's: added=%v err=%v", added, err)
	}
}

func TestAMDChainsAreKeyedByTheirASKName(t *testing.T) {
	for name, chain := range amdChains {
		ask, _, err := parseAMDChain(chain)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c, err := x509.ParseCertificate(ask)
		if err != nil {
			t.Fatal(err)
		}
		if c.Subject.CommonName != name {
			t.Fatalf("chain under %q has the ASK or ASVK %q", name, c.Subject.CommonName)
		}
	}
}
