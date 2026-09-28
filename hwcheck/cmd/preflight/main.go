// Command preflight feeds an SEV-SNP report captured earlier (report.bin plus the host's VCEK, ASK and ARK as the
// host delivered them) to the Veraison sevsnp scheme as a TSM report, with the report's own REPORT_DATA as the
// session nonce: it checks the signature and chain path and the certificate-table encoding, not the binding.
package main

import (
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/corim/comid"
	"github.com/veraison/services/scheme/sevsnp"
	"github.com/veraison/services/vts/appraisal"
)

var guids = map[string]string{ // byte order as the host writes them
	"VCEK": "63da758de6644564adc5f4b93be8accd",
	"ASK":  "4ab7b379bbac4fe4a02f05aef327c782",
	"ARK":  "c0b406a4a803495297433fb6014cd0ae",
}

func main() {
	dir := flag.String("dir", "", "directory with D1-report.bin and D1-cert-{VCEK,ASK,ARK}.bin")
	taPath := flag.String("ta", "", "ARK from the AMD KDS (PEM chain; the self-signed one is used)")
	flag.Parse()
	rep, err := os.ReadFile(filepath.Join(*dir, "D1-report.bin"))
	must(err)
	certs := map[string][]byte{}
	for _, n := range []string{"ARK", "ASK", "VCEK"} {
		certs[n], err = os.ReadFile(filepath.Join(*dir, "D1-cert-"+n+".bin"))
		must(err)
	}
	ta := arkFrom(*taPath)
	nonce := rep[0x50:0x90]
	for _, enc := range []string{"DER (as the GCP host delivered)", "PEM"} {
		table := buildTable(certs, enc == "PEM")
		tok, err := cbor.Marshal(map[string]any{"auxblob": table, "outblob": rep, "provider": "sev_guest"})
		must(err)
		k, err := comid.NewPKIXBase64Cert(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ta})))
		must(err)
		ev := &appraisal.Evidence{Data: tok, MediaType: sevsnp.EvidenceMediaTypeTSMCbor, Nonce: nonce}
		err = sevsnp.NewImplementation().ValidateEvidenceIntegrity(ev, []*comid.KeyTriple{{VerifKeys: comid.CryptoKeys{k}}}, nil)
		fmt.Printf("%-34s -> %v\n", enc, errOr(err))
		wrong := append([]byte{nonce[0] ^ 1}, nonce[1:]...)
		ev.Nonce = wrong
		err = sevsnp.NewImplementation().ValidateEvidenceIntegrity(ev, []*comid.KeyTriple{{VerifKeys: comid.CryptoKeys{k}}}, nil)
		fmt.Printf("%-34s    other nonce -> %v\n", "", errOr(err))
	}
}

func buildTable(certs map[string][]byte, asPEM bool) []byte {
	order := []string{"VCEK", "ASK", "ARK"}
	off := uint32(24 * (len(order) + 1))
	var head, body []byte
	for _, n := range order {
		c := certs[n]
		if asPEM {
			c = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})
		}
		g, err := hex.DecodeString(guids[n])
		must(err)
		head = append(head, g...)
		head = appendLE(head, off+uint32(len(body)))
		head = appendLE(head, uint32(len(c)))
		body = append(body, c...)
	}
	head = append(head, make([]byte, 24)...)
	return append(head, body...)
}

func arkFrom(path string) []byte {
	b, err := os.ReadFile(path)
	must(err)
	var last []byte
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		last = blk.Bytes // the KDS cert_chain lists the ASK, then the ARK
	}
	return last
}

func appendLE(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func errOr(err error) string {
	if err == nil {
		return "VALID"
	}
	return "refused: " + err.Error()
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "preflight:", err)
		os.Exit(1)
	}
}
