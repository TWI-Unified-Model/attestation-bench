// Command gce-endorsement checks a launch measurement against Google's signed firmware endorsements. It fetches the
// VMLaunchEndorsement Google publishes for that measurement (bucket gce_tcb_integrity), verifies with
// google/gce-tcb-verifier that the signing certificate chains to the GCE confidential-computing TCB root and that
// the signature over the golden measurement holds, and checks that the measurement is one the endorsement lists.
// A measurement that passes is a reference value that does not rest on a first observation: the builder of the
// firmware signed it. The root is fetched once by the operator from https://pki.goog/cloud_integrity/ and pinned.
//
//	gce-endorsement -root GCE-cc-tcb-root_1.crt -tdx <MRTD, 96 hex digits>
//	gce-endorsement -root GCE-cc-tcb-root_1.crt -snp <MEASUREMENT, 96 hex digits>
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/google/gce-tcb-verifier/extract/extractsev"
	"github.com/google/gce-tcb-verifier/extract/extracttdx"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/verify"
	"google.golang.org/protobuf/proto"
)

type result struct {
	Technology  string `json:"technology"`
	Measurement string `json:"measurement"`
	Endorsed    bool   `json:"endorsed"`
	Reason      string `json:"reason,omitempty"`
	Object      string `json:"object"`
	UEFISHA384  string `json:"uefi_sha384,omitempty"`
	SVN         uint32 `json:"svn,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
	Commit      string `json:"commit,omitempty"`
	CLSpec      uint64 `json:"cl_spec,omitempty"`
	RAMGiB      uint32 `json:"ram_gib,omitempty"`
	EarlyAccept bool   `json:"early_accept,omitempty"`
	VCPUs       uint32 `json:"launch_vmsas,omitempty"`
	Signer      string `json:"signer,omitempty"`
	RootSHA256  string `json:"root_sha256"`
	CheckedAt   string `json:"checked_at"`
}

func main() {
	rootPath := flag.String("root", "", "GCE TCB root certificate, PEM or DER (https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt)")
	tdx := flag.String("tdx", "", "TDX MRTD, hex")
	snp := flag.String("snp", "", "SEV-SNP launch MEASUREMENT, hex")
	save := flag.String("save", "", "also write the fetched endorsement to this file")
	flag.Parse()
	r, err := check(*rootPath, *tdx, *snp, *save)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gce-endorsement:", err)
		os.Exit(2)
	}
	b, _ := json.MarshalIndent(r, "", " ")
	fmt.Println(string(b))
	if !r.Endorsed {
		os.Exit(1)
	}
}

func check(rootPath, tdx, snp, save string) (*result, error) {
	raw, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, err
	}
	if p, _ := pem.Decode(raw); p != nil {
		raw = p.Bytes
	}
	root, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("root: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	sum := sha256.Sum256(root.Raw)
	r := &result{RootSHA256: hex.EncodeToString(sum[:]), CheckedAt: time.Now().UTC().Format(time.RFC3339)}

	var m []byte
	switch {
	case tdx != "" && snp == "":
		r.Technology, r.Measurement = "tdx", tdx
		m, err = hex.DecodeString(tdx)
		r.Object = extracttdx.GCETcbObjectName(m)
	case snp != "" && tdx == "":
		r.Technology, r.Measurement = "sev-snp", snp
		m, err = hex.DecodeString(snp)
		r.Object = extractsev.GCETcbObjectName(sev.GCEUefiFamilyID, m)
	default:
		return nil, errors.New("give exactly one of -tdx and -snp")
	}
	if err != nil || len(m) != 48 {
		return nil, errors.New("a measurement is 48 octets, 96 hex digits")
	}
	url := verify.GCETcbURL(r.Object)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	blob, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		r.Reason = "Google publishes no endorsement for this measurement"
		return r, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	if save != "" {
		if err := os.WriteFile(save, blob, 0o644); err != nil {
			return nil, err
		}
	}
	opts := &verify.Options{RootsOfTrust: roots, Now: time.Now()}
	if r.Technology == "sev-snp" {
		opts.SNP = &verify.SNPOptions{Measurement: m}
	}
	if err := verify.Endorsement(blob, opts); err != nil {
		r.Reason = err.Error()
		return r, nil
	}
	var e epb.VMLaunchEndorsement
	var g epb.VMGoldenMeasurement
	if err := proto.Unmarshal(blob, &e); err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(e.GetSerializedUefiGolden(), &g); err != nil {
		return nil, err
	}
	r.UEFISHA384, r.Commit, r.CLSpec = hex.EncodeToString(g.GetDigest()), hex.EncodeToString(g.GetCommit()), g.GetClSpec()
	if ts := g.GetTimestamp(); ts != nil {
		r.Timestamp = ts.AsTime().UTC().Format(time.RFC3339)
	}
	if cert, err := x509.ParseCertificate(g.GetCert()); err == nil {
		r.Signer = cert.Subject.String()
	}
	switch r.Technology {
	case "tdx": // verify.Endorsement checks no TDX content: the MRTD must be one this signed document lists
		r.SVN = g.GetTdx().GetSvn()
		for _, x := range g.GetTdx().GetMeasurements() {
			if bytes.Equal(x.GetMrtd(), m) {
				r.Endorsed, r.RAMGiB, r.EarlyAccept = true, x.GetRamGib(), x.GetEarlyAccept()
				break
			}
		}
		if !r.Endorsed {
			r.Reason = "the endorsement does not list this MRTD"
		}
	case "sev-snp": // verify.Endorsement already required the measurement to be listed
		r.SVN, r.Endorsed = g.GetSevSnp().GetSvn(), true
		keys := make([]uint32, 0, len(g.GetSevSnp().GetMeasurements()))
		for k := range g.GetSevSnp().GetMeasurements() {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, k := range keys {
			if bytes.Equal(g.GetSevSnp().GetMeasurements()[k], m) {
				r.VCPUs = k
			}
		}
	}
	return r, nil
}
