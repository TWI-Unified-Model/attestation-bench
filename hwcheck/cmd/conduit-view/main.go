// Command conduit-view prints what the conduit of TACRA, the CAS Client and the CAS Server, sees of a hardware run:
// the Evidence of each case as the platform's own library parses it (an SEV-SNP attestation report and its
// certificate table, go-sev-guest; a TDX quote and its PCK certificate chain, go-tdx-guest), each field with what it
// tells the reader about the machine, the launch, the firmware, the policy and the Attester's choice; and, where the
// run kept them, the Attestation Results the verifier issued, which the CAS Server carries in Passport. Evidence is
// signed, not encrypted: whoever carries it reads all of it (RFC 9334, Sections 11 and 12.2).
//
//	go run ./cmd/conduit-view evidence/20261008T154907Z-gcp-sev-snp evidence/20261008T160809Z-gcp-tdx
//
// It reads every <case>/evidence.tsm.cbor (hwrun's TSM reports) under each run directory given, at the top and under
// <pass>/redir of a redirection run, prints the first report once with the count of the rest, and reads the
// ears/*.ear.jws beside the cases. Values are printed as hex prefixes, except the binding value, which is the
// Attester's and public: what the fields hold is the point, not their bytes.
package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevpb "github.com/google/go-sev-guest/proto/sevsnp"
	tdxabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

const (
	reportFile   = "evidence.tsm.cbor" // hwrun's record of one TSM report: provider, outblob (the report), auxblob (its certificates)
	earsDir      = "ears"              // the Attestation Results rrpverify kept, one JWS per case
	earSuffix    = ".ear.jws"
	jwsParts     = 3 // header, payload, signature
	prefixOctets = 8 // of a value printed as a hex prefix
)

// What a field tells whoever reads the Evidence. The summary of a run names the fields of each kind.
const (
	tellsMachine  = "machine"   // which physical machine, or which provider's key domain, produced the Evidence
	tellsLaunch   = "launch"    // what was launched: the image and the keys of its owner
	tellsFirmware = "firmware"  // the platform's firmware and microcode level, and its mitigations
	tellsPolicy   = "policy"    // what the guest is allowed: debugging, migration, SMT
	tellsAttester = "attester"  // chosen by the Attester: the binding value of TACRA Section 4.5
	tellsHost     = "host"      // chosen by the host or the provider at launch
	tellsInstance = "instance"  // this VM and this report
	tellsFormat   = "format"    // the report's own version and layout
	tellsSigner   = "signature" // who signed the Evidence, and the signature
)

type field struct{ name, tells, value string }

// view is what one piece of Evidence shows its reader.
type view struct {
	provider string
	fields   []field
	chain    []string // the certificates that come with the Evidence, one line each
	summary  []string // what the conduit can tell from it
}

type tsmReport struct {
	Provider string `cbor:"provider"`
	Outblob  []byte `cbor:"outblob"`
	Auxblob  []byte `cbor:"auxblob"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: conduit-view RUN_DIR...")
		os.Exit(2)
	}
	for _, dir := range os.Args[1:] {
		text, err := describeRun(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "conduit-view: %s: %v\n", dir, err)
			os.Exit(1)
		}
		fmt.Print(text)
	}
}

// describeRun reads the Evidence of a run directory and the Attestation Results kept beside it, and returns the text
// of what the conduit sees: the first report in full, how many more there are, the certificates, the EAR of the first
// case that has one, and a summary.
func describeRun(dir string) (string, error) {
	files, err := reportFiles(dir)
	if err != nil {
		return "", err
	}
	v, err := viewOf(files[0])
	if err != nil {
		return "", fmt.Errorf("%s: %w", files[0], err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d report(s) from the %s provider; the first (%s):\n", filepath.Base(filepath.Clean(dir)),
		len(files), v.provider, relative(dir, files[0]))
	width := 0
	for _, f := range v.fields {
		if len(f.name) > width {
			width = len(f.name)
		}
	}
	for _, f := range v.fields {
		fmt.Fprintf(&b, "  %-*s  %-9s  %s\n", width, f.name, f.tells, f.value)
	}
	for _, c := range v.chain {
		fmt.Fprintf(&b, "  certificate: %s\n", c)
	}
	ears, err := earFiles(dir)
	if err != nil {
		return "", err
	}
	if len(ears) > 0 {
		lines, err := viewEAR(ears[0])
		if err != nil {
			return "", fmt.Errorf("%s: %w", ears[0], err)
		}
		fmt.Fprintf(&b, "  Attestation Results (%d kept; the first, %s):\n", len(ears), relative(dir, ears[0]))
		for _, l := range lines {
			fmt.Fprintf(&b, "    %s\n", l)
		}
	}
	b.WriteString("  the conduit can tell:\n")
	for _, s := range v.summary {
		fmt.Fprintf(&b, "    %s\n", s)
	}
	if len(ears) > 0 {
		b.WriteString("    and in Passport, from the Attestation Results, the verifier's verdict and the claims it annotated\n")
	}
	return b.String(), nil
}

// reportFiles lists the TSM reports of a run, at the top (an attack run) and under <pass>/redir (a redirection run).
func reportFiles(dir string) ([]string, error) {
	var files []string
	for _, pattern := range []string{filepath.Join(dir, "*", reportFile), filepath.Join(dir, "*", "redir", "*", reportFile)} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no %s under it: not the directory of a hardware run", reportFile)
	}
	sort.Strings(files)
	return files, nil
}

// earFiles lists the Attestation Results a run kept: ears/ at the top (an attack run) or under each pass (redirection).
func earFiles(dir string) ([]string, error) {
	var files []string
	for _, pattern := range []string{filepath.Join(dir, earsDir, "*"+earSuffix), filepath.Join(dir, "*", earsDir, "*"+earSuffix)} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	return files, nil
}

func relative(dir, path string) string {
	if r, err := filepath.Rel(dir, path); err == nil {
		return r
	}
	return path
}

// viewOf parses one TSM report with the library of its provider.
func viewOf(path string) (*view, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tsm tsmReport
	if err := cbor.Unmarshal(b, &tsm); err != nil {
		return nil, fmt.Errorf("not a TSM report: %w", err)
	}
	switch tsm.Provider {
	case "sev_guest":
		return viewSEVSNP(tsm.Outblob, tsm.Auxblob)
	case "tdx_guest":
		return viewTDX(tsm.Outblob)
	}
	return nil, fmt.Errorf("provider %q: no parser", tsm.Provider)
}

// viewSEVSNP reads an SEV-SNP attestation report (AMD 56860, Table 22) and its certificate table as go-sev-guest does.
func viewSEVSNP(report, certs []byte) (*view, error) {
	r, err := abi.ReportToProto(report)
	if err != nil {
		return nil, fmt.Errorf("report: %w", err)
	}
	signer, err := abi.ParseSignerInfo(r.GetSignerInfo())
	if err != nil {
		return nil, fmt.Errorf("SIGNER_INFO: %w", err)
	}
	policy, err := abi.ParseSnpPolicy(r.GetPolicy())
	if err != nil {
		return nil, fmt.Errorf("POLICY: %w", err)
	}
	platform, err := abi.ParseSnpPlatformInfo(r.GetPlatformInfo())
	if err != nil {
		return nil, fmt.Errorf("PLATFORM_INFO: %w", err)
	}
	v := &view{provider: "sev_guest"}
	v.fields = []field{
		{"VERSION", tellsFormat, fmt.Sprint(r.GetVersion())},
		{"GUEST_SVN", tellsLaunch, fmt.Sprint(r.GetGuestSvn())},
		{"POLICY", tellsPolicy, fmt.Sprintf("%#x: debug %t, migration agent %t, SMT %t, single socket %t", r.GetPolicy(),
			policy.Debug, policy.MigrateMA, policy.SMT, policy.SingleSocket)},
		{"FAMILY_ID", tellsLaunch, prefix(r.GetFamilyId())},
		{"IMAGE_ID", tellsLaunch, prefix(r.GetImageId())},
		{"VMPL", tellsInstance, fmt.Sprint(r.GetVmpl())},
		{"SIGNATURE_ALGO", tellsSigner, fmt.Sprint(r.GetSignatureAlgo())},
		{"CURRENT_TCB", tellsFirmware, fmt.Sprintf("%#x", r.GetCurrentTcb())},
		{"PLATFORM_INFO", tellsFirmware, fmt.Sprintf("%#x: SMT %t, TSME %t, ECC %t", r.GetPlatformInfo(),
			platform.SMTEnabled, platform.TSMEEnabled, platform.ECCEnabled)},
		{"SIGNER_INFO", tellsSigner, fmt.Sprintf("%s-signed, CHIP_ID masked by the host %t", signer.SigningKey, signer.MaskChipKey)},
		{"REPORT_DATA", tellsAttester, hex.EncodeToString(r.GetReportData()) + " (the binding value)"},
		{"MEASUREMENT", tellsLaunch, prefix(r.GetMeasurement())},
		{"HOST_DATA", tellsHost, prefix(r.GetHostData())},
		{"ID_KEY_DIGEST", tellsLaunch, prefix(r.GetIdKeyDigest())},
		{"AUTHOR_KEY_DIGEST", tellsLaunch, prefix(r.GetAuthorKeyDigest())},
		{"REPORT_ID", tellsInstance, prefix(r.GetReportId())},
		{"REPORT_ID_MA", tellsInstance, prefix(r.GetReportIdMa())},
		{"REPORTED_TCB", tellsFirmware, fmt.Sprintf("%#x", r.GetReportedTcb())},
		{"CHIP_ID", tellsMachine, chipID(r.GetChipId())},
		{"COMMITTED_TCB", tellsFirmware, fmt.Sprintf("%#x", r.GetCommittedTcb())},
		{"CURRENT_VERSION", tellsFirmware, fmt.Sprintf("%d.%d build %d", r.GetCurrentMajor(), r.GetCurrentMinor(), r.GetCurrentBuild())},
		{"COMMITTED_VERSION", tellsFirmware, fmt.Sprintf("%d.%d build %d", r.GetCommittedMajor(), r.GetCommittedMinor(), r.GetCommittedBuild())},
		{"LAUNCH_TCB", tellsFirmware, fmt.Sprintf("%#x", r.GetLaunchTcb())},
		{"LAUNCH_MIT_VECTOR", tellsFirmware, fmt.Sprintf("%#x", r.GetLaunchMitVector())},
		{"CURRENT_MIT_VECTOR", tellsFirmware, fmt.Sprintf("%#x", r.GetCurrentMitVector())},
		{"SIGNATURE", tellsSigner, prefix(r.GetSignature())},
	}
	machine := "the machine: not named: the report is VLEK-signed and its CHIP_ID is zero; the VLEK names the provider's key domain"
	if signer.SigningKey == abi.VcekReportSigner {
		machine = "the machine: CHIP_ID, and the VCEK certificate's hwID, name the chip"
	}
	if len(certs) > 0 {
		att, err := abi.ReportCertsToProto(append(append([]byte{}, report...), certs...))
		if err != nil {
			return nil, fmt.Errorf("certificate table: %w", err)
		}
		chain, err := sevChain(att.GetCertificateChain())
		if err != nil {
			return nil, err
		}
		v.chain = chain
	}
	v.summary = []string{
		machine,
		fmt.Sprintf("the launch: MEASUREMENT %s, with the owner's ID_KEY_DIGEST and the HOST_DATA the host set", short(r.GetMeasurement())),
		fmt.Sprintf("the firmware: REPORTED_TCB %#x, mitigation vector %#x, SNP firmware %d.%d", r.GetReportedTcb(),
			r.GetCurrentMitVector(), r.GetCurrentMajor(), r.GetCurrentMinor()),
		fmt.Sprintf("the policy: debug %t, migration %t, SMT %t", policy.Debug, policy.MigrateMA, policy.SMT),
		"the Attester's choice: REPORT_DATA, the binding value, which the conduit relays and cannot change",
	}
	return v, nil
}

func chipID(id []byte) string {
	for _, b := range id {
		if b != 0 {
			return "present: " + prefix(id)
		}
	}
	return "zero"
}

// sevChain describes the certificates of the table: the signing key's certificate with the extensions AMD's KDS puts
// in it (go-sev-guest's kds package reads them), and the chain above it.
func sevChain(c *sevpb.CertificateChain) ([]string, error) {
	var lines []string
	for _, e := range []struct {
		name string
		der  []byte
		key  abi.ReportSigner
	}{
		{"VCEK", c.GetVcekCert(), abi.VcekReportSigner},
		{"VLEK", c.GetVlekCert(), abi.VlekReportSigner},
		{"ASK", c.GetAskCert(), abi.NoneReportSigner},
		{"ARK", c.GetArkCert(), abi.NoneReportSigner},
	} {
		if len(e.der) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(e.der)
		if err != nil {
			return nil, fmt.Errorf("%s certificate: %w", e.name, err)
		}
		line := fmt.Sprintf("%s: subject %q, issuer %q", e.name, cert.Subject.CommonName, cert.Issuer.CommonName)
		if e.key != abi.NoneReportSigner {
			ext, err := kds.CertificateExtensions(cert, e.key)
			if err != nil {
				return nil, fmt.Errorf("%s certificate extensions: %w", e.name, err)
			}
			line += fmt.Sprintf("; product %s, TCB %#x", ext.ProductName, uint64(ext.TCBVersion))
			if len(ext.HWID) > 0 {
				line += ", hwID " + prefix(ext.HWID)
			}
			if ext.CspID != "" {
				line += ", cspID " + ext.CspID
			}
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// viewTDX reads a TDX quote (Intel TDX DCAP Quoting Library API, Quote Format v4) as go-tdx-guest does: the header,
// the TD report body, the Quoting Enclave's report and the PCK certificate chain that names the platform.
func viewTDX(quote []byte) (*view, error) {
	q, err := tdxabi.QuoteToProto(quote)
	if err != nil {
		return nil, fmt.Errorf("quote: %w", err)
	}
	q4, ok := q.(*tdxpb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("quote: %T, not a version 4 quote", q)
	}
	h, body := q4.GetHeader(), q4.GetTdQuoteBody()
	v := &view{provider: "tdx_guest"}
	v.fields = []field{
		{"VERSION", tellsFormat, fmt.Sprint(h.GetVersion())},
		{"ATTESTATION_KEY_TYPE", tellsSigner, fmt.Sprint(h.GetAttestationKeyType())},
		{"TEE_TYPE", tellsFormat, fmt.Sprintf("%#x", h.GetTeeType())},
		{"QE_SVN", tellsFirmware, hex.EncodeToString(h.GetQeSvn())},
		{"PCE_SVN", tellsFirmware, hex.EncodeToString(h.GetPceSvn())},
		{"QE_VENDOR_ID", tellsFormat, hex.EncodeToString(h.GetQeVendorId())},
		{"USER_DATA", tellsInstance, prefix(h.GetUserData())},
		{"TEE_TCB_SVN", tellsFirmware, hex.EncodeToString(body.GetTeeTcbSvn())},
		{"MRSEAM", tellsFirmware, prefix(body.GetMrSeam())},
		{"MRSIGNERSEAM", tellsFirmware, prefix(body.GetMrSignerSeam())},
		{"SEAMATTRIBUTES", tellsPolicy, hex.EncodeToString(body.GetSeamAttributes())},
		{"TDATTRIBUTES", tellsPolicy, hex.EncodeToString(body.GetTdAttributes())},
		{"XFAM", tellsPolicy, hex.EncodeToString(body.GetXfam())},
		{"MRTD", tellsLaunch, prefix(body.GetMrTd())},
		{"MRCONFIGID", tellsHost, prefix(body.GetMrConfigId())},
		{"MROWNER", tellsHost, prefix(body.GetMrOwner())},
		{"MROWNERCONFIG", tellsHost, prefix(body.GetMrOwnerConfig())},
	}
	for i, r := range body.GetRtmrs() {
		v.fields = append(v.fields, field{fmt.Sprintf("RTMR%d", i), tellsLaunch, prefix(r)})
	}
	v.fields = append(v.fields, field{"REPORTDATA", tellsAttester, hex.EncodeToString(body.GetReportData()) + " (the binding value)"})
	sd := q4.GetSignedData()
	v.fields = append(v.fields,
		field{"SIGNATURE", tellsSigner, prefix(sd.GetSignature())},
		field{"ECDSA_ATTESTATION_KEY", tellsSigner, prefix(sd.GetEcdsaAttestationKey())},
	)
	machine := "the machine: not named: the quote carries no PCK certificate chain"
	if qe := sd.GetCertificationData().GetQeReportCertificationData(); qe != nil {
		r := qe.GetQeReport()
		v.fields = append(v.fields,
			field{"QE_REPORT.MRENCLAVE", tellsFirmware, prefix(r.GetMrEnclave())},
			field{"QE_REPORT.MRSIGNER", tellsFirmware, prefix(r.GetMrSigner())},
			field{"QE_REPORT.ISVSVN", tellsFirmware, fmt.Sprint(r.GetIsvSvn())},
		)
		chain, named, err := pckChain(qe.GetPckCertificateChainData().GetPckCertChain())
		if err != nil {
			return nil, err
		}
		v.chain = chain
		if named != "" {
			machine = "the machine: the PCK certificate names the platform: " + named
		}
	}
	v.summary = []string{
		machine,
		fmt.Sprintf("the launch: MRTD %s and the RTMRs, with MROWNER and MRCONFIGID the host set", short(body.GetMrTd())),
		fmt.Sprintf("the firmware: TEE_TCB_SVN %s, MRSEAM %s, QE_SVN %s", hex.EncodeToString(body.GetTeeTcbSvn()),
			short(body.GetMrSeam()), hex.EncodeToString(h.GetQeSvn())),
		fmt.Sprintf("the policy: TDATTRIBUTES %s, XFAM %s", hex.EncodeToString(body.GetTdAttributes()), hex.EncodeToString(body.GetXfam())),
		"the Attester's choice: REPORTDATA, the binding value, which the conduit relays and cannot change",
	}
	return v, nil
}

// pckChain describes the PEM certificates of a quote's PCK chain and, from the leaf's SGX extension (go-tdx-guest's
// pcs package reads it), what names the platform: its PPID, FMSPC and PCE-ID.
func pckChain(pemChain []byte) ([]string, string, error) {
	var lines []string
	named := ""
	rest := pemChain
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("PCK chain: %w", err)
		}
		line := fmt.Sprintf("PCK chain: subject %q, issuer %q", cert.Subject.CommonName, cert.Issuer.CommonName)
		if ext, err := pcs.PckCertificateExtensions(cert); err == nil {
			named = fmt.Sprintf("PPID %s… (%d hex digits), FMSPC %s, PCE-ID %s", ext.PPID[:min(len(ext.PPID), 2*prefixOctets)],
				len(ext.PPID), ext.FMSPC, ext.PCEID)
			line += "; SGX extension: " + named
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil, "", errors.New("PCK chain: no certificate")
	}
	return lines, named, nil
}

// viewEAR reads the payload of an EAR (draft-ietf-rats-ear) the verifier signed as a JWS, and lists what it says.
func viewEAR(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimSpace(string(b)), ".")
	if len(parts) != jwsParts {
		return nil, fmt.Errorf("not a JWS: %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("JWS payload: %w", err)
	}
	var ear map[string]any
	if err := json.Unmarshal(payload, &ear); err != nil {
		return nil, fmt.Errorf("EAR: %w", err)
	}
	var lines []string
	if id, ok := ear["ear.verifier-id"].(map[string]any); ok {
		lines = append(lines, fmt.Sprintf("verifier: %v, build %v", id["developer"], id["build"]))
	}
	if n, ok := ear["eat_nonce"].(string); ok {
		lines = append(lines, fmt.Sprintf("eat_nonce: %d characters (the binding value the verifier checked)", len(n)))
	}
	submods, _ := ear["submods"].(map[string]any)
	names := make([]string, 0, len(submods))
	for name := range submods {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sub, _ := submods[name].(map[string]any)
		lines = append(lines, fmt.Sprintf("%s: status %v, policy %v", name, sub["ear.status"], sub["ear.appraisal-policy-id"]))
		if tv, ok := sub["ear.trustworthiness-vector"].(map[string]any); ok {
			lines = append(lines, "  trustworthiness vector: "+nonZero(tv))
		}
		if ae, ok := sub["ear.veraison.annotated-evidence"].(map[string]any); ok {
			keys := make([]string, 0, len(ae))
			for k := range ae {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			lines = append(lines, "  annotated evidence: "+strings.Join(keys, ", "))
		}
	}
	return lines, nil
}

// nonZero lists the claims of a trustworthiness vector that are not zero (zero: no claim made), in order.
func nonZero(tv map[string]any) string {
	keys := make([]string, 0, len(tv))
	for k, val := range tv {
		if n, ok := val.(float64); ok && n != 0 {
			keys = append(keys, fmt.Sprintf("%s %v", k, n))
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "no claim"
	}
	return strings.Join(keys, ", ")
}

// short prints the first octets of a value in hex, with an ellipsis when there are more.
func short(b []byte) string {
	if len(b) <= prefixOctets {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:prefixOctets]) + "…"
}

// prefix prints the first octets of a value in hex, and how long it is.
func prefix(b []byte) string {
	if len(b) == 0 {
		return "empty"
	}
	n := min(len(b), prefixOctets)
	if n == len(b) {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%s… (%d octets)", hex.EncodeToString(b[:n]), len(b))
}
