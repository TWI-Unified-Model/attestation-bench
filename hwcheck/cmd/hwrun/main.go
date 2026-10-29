// Command hwrun is the Attester side of the hardware check: in an AMD SEV-SNP or Intel TDX guest it drives the
// platform plug-in the way the CAI does (keys, CSR, GenerateEvidence) for Enrollment and Retrieval in all five
// Freshness Kinds, and writes each Evidence with what the Relying Party needs to recompute the binding. Run as root
// (configfs-tsm).
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/tacra/platform"
)

// backend is a hardware platform plug-in: the CAI's Plugin plus the freshness element it binds.
type backend interface {
	platform.Plugin
	FreshnessElement(platform.EvidenceRequest) ([]byte, error)
}

// handles are the Freshness Handles an RRP hands out at Initiate (JSON: base64).
type handles struct {
	NonceEnroll   []byte `json:"nonce_enroll"`
	NonceRetrieve []byte `json:"nonce_retrieve"`
	Epoch         []byte `json:"epoch"` // the epoch marker the Attester holds (absent-epoch)
	// EpochHandle is the present-epoch Handle an RRP with an epoch of its own returned at Initiate
	// (hwcheck/scripts/redirect.sh, REDIRECT_VARIANT=start-ca2); absent: Epoch, the marker the deployment's RRPs share
	EpochHandle []byte `json:"epoch_handle,omitempty"`
	MintedAt    int64  `json:"minted_at"`
}

type caseMeta struct {
	Case             string  `json:"case"`
	Mode             string  `json:"mode"`
	FreshnessKind    string  `json:"freshness_kind"`
	Target           string  `json:"target"`
	BindingLayout    string  `json:"binding_layout"` // platform.BindingLayout: the binding of 11 October 2026 (three fields)
	FreshnessElement string  `json:"freshness_element_b64,omitempty"`
	BindingValueHex  string  `json:"binding_value_hex"`
	EvidenceMs       float64 `json:"evidence_ms"`
	TokenBytes       int     `json:"token_bytes"`
	ReportSHA256     string  `json:"report_sha256"`
	SigningKey       string  `json:"signing_key"`
	ChipIDPrefix     string  `json:"chip_id_prefix"`
	Error            string  `json:"error,omitempty"`
}

func main() {
	out := flag.String("out", "hwrun-out", "output directory")
	target := flag.String("target", "https://db.tacra.example", "Target")
	// targetsPath, when given, is a JSON object {freshness-kind: Target} so one run can bind each kind to the Target
	// the bench configures for it (db-nonce is present-nonce, db-epoch present-epoch, ...); kinds it omits use -target.
	targetsPath := flag.String("targets", "", "per-kind Targets (JSON {kind: target}); -target is the fallback")
	// csrCN is the CSR's common name, the identity the Credential Authority is asked to certify. It has to be one the
	// Target's policy grants the attested launch (the bench's db-* Targets grant payments.workload.tacra.example).
	csrCN := flag.String("csr-cn", "workload.tacra.example", "the CSR's common name (the identity to certify)")
	handlesPath := flag.String("handles", "", "Freshness Handles minted by the RRP (rrpverify mint); random if empty")
	burst := flag.Int("burst", 0, "after the cases, time this many present-nonce Enrollment reports")
	// onlyKinds and onlyModes limit the cases: the pre-play check makes absent-timestamp Evidence alone, one mode per
	// Target, while the guest's clock runs ahead (hwcheck/scripts/preplay.sh)
	onlyKinds := flag.String("kinds", "", "comma-separated Freshness Kinds to make Evidence for (default: all five)")
	onlyModes := flag.String("modes", "", "comma-separated modes, enroll and retrieve (default: both)")
	// cekAlg is the CEK's algorithm for Retrieval: a Target that takes the hpke-base container alone (the
	// bench's ledger-time) needs an MLKEM768-P256 CEK
	cekAlg := flag.String("cek", "ecdh-p256", "the CEK for Retrieval: ecdh-p256 or mlkem768-p256")
	tee := flag.String("tee", "sev-snp", "sev-snp or tdx")
	flag.Parse()
	must(os.MkdirAll(*out, 0o755))

	perKindTarget := map[string]string{}
	if *targetsPath != "" {
		b, err := os.ReadFile(*targetsPath)
		must(err)
		must(json.Unmarshal(b, &perKindTarget))
	}
	targetOf := func(kind string) string {
		if t, ok := perKindTarget[kind]; ok {
			return t
		}
		return *target
	}

	h := handles{NonceEnroll: random(32), NonceRetrieve: random(32), Epoch: random(32)}
	if *handlesPath != "" {
		b, err := os.ReadFile(*handlesPath)
		must(err)
		must(json.Unmarshal(b, &h))
	}
	epoch := h.Epoch
	var p backend
	var err error
	switch *tee {
	case "sev-snp":
		p, err = platform.NewSEVSNP(platform.WithLocalEpoch(epoch))
	case "tdx":
		p, err = platform.NewTDX(platform.WithLocalEpoch(epoch))
	default:
		err = fmt.Errorf("unknown -tee %q", *tee)
	}
	must(err)
	kinds := []struct {
		name string
		kind platform.FreshnessKind
	}{
		{"present-nonce", platform.FreshnessKindPresentNonce}, {"present-epoch", platform.FreshnessKindPresentEpoch},
		{"absent-epoch", platform.FreshnessKindAbsentEpoch}, {"absent-timestamp", platform.FreshnessKindAbsentTimestamp},
		{"absent-none", platform.FreshnessKindAbsentNone},
	}
	if *onlyKinds != "" {
		want := strings.Split(*onlyKinds, ",")
		kinds = slices.DeleteFunc(kinds, func(k struct {
			name string
			kind platform.FreshnessKind
		}) bool {
			return !slices.Contains(want, k.name)
		})
		if len(kinds) != len(want) {
			must(fmt.Errorf("-kinds %q: each must be one of present-nonce, present-epoch, absent-epoch, "+
				"absent-timestamp, absent-none, once", *onlyKinds))
		}
	}
	cekAlgorithm := map[string]platform.EncryptionAlgorithm{"ecdh-p256": platform.EncryptionAlgorithmECDHP256,
		"mlkem768-p256": platform.EncryptionAlgorithmMLKEM768P256}[*cekAlg]
	if cekAlgorithm == platform.EncryptionAlgorithmUnspecified {
		must(fmt.Errorf("-cek %q: ecdh-p256 or mlkem768-p256", *cekAlg))
	}
	modes := []string{"enroll", "retrieve"}
	if *onlyModes != "" {
		want := strings.Split(*onlyModes, ",")
		modes = slices.DeleteFunc(modes, func(m string) bool { return !slices.Contains(want, m) })
		if len(modes) != len(want) {
			must(fmt.Errorf("-modes %q: each must be enroll or retrieve, once", *onlyModes))
		}
	}
	var all []caseMeta
	for _, k := range kinds {
		for _, mode := range modes {
			name := fmt.Sprintf("%s-%s", mode, k.name)
			kindTarget := targetOf(k.name)
			m := caseMeta{Case: name, Mode: mode, FreshnessKind: k.name, Target: kindTarget}
			req := platform.EvidenceRequest{FreshnessKind: k.kind, Target: kindTarget}
			switch k.kind {
			case platform.FreshnessKindPresentNonce: // the Handle the RRP returned at Initiate
				req.FreshnessHandle = h.NonceEnroll
				if mode == "retrieve" {
					req.FreshnessHandle = h.NonceRetrieve
				}
			case platform.FreshnessKindPresentEpoch: // the current epoch marker, returned at Initiate
				req.FreshnessHandle = epoch
				if len(h.EpochHandle) > 0 {
					req.FreshnessHandle = h.EpochHandle
				}
			case platform.FreshnessKindAbsentEpoch: // held locally; the CAI passes it as the handle
				req.FreshnessHandle = p.LocalEpoch()
			}
			var subject []byte
			if mode == "enroll" {
				csk, err := p.GenerateCSK(platform.SigningAlgorithmECDSAP256)
				must(err)
				signer, err := csk.Signer()
				must(err)
				csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
					Subject: pkix.Name{CommonName: *csrCN}}, signer)
				must(err)
				req.BoundKey, req.CSR, req.BoundKeyUse, subject = csk.Public(), csr, platform.BoundKeyUseSign, csr
			} else {
				cek, err := p.GenerateCEK(cekAlgorithm)
				must(err)
				req.BoundKey, req.BoundKeyUse = cek.Public(), platform.BoundKeyUseEncrypt
				subject, err = platform.CEKPub(cek.Public()) // DER SubjectPublicKeyInfo, or an MLKEM768-P256 key itself
				must(err)
			}
			elem, err := p.FreshnessElement(req)
			must(err)
			if len(elem) > 0 {
				m.FreshnessElement = base64.RawURLEncoding.EncodeToString(elem)
			}
			if k.kind == platform.FreshnessKindAbsentTimestamp {
				req.FreshnessHandle = elem // the element the request would carry in its handle field
			}
			bv := platform.BindingValue(elem, req.Target, subject)
			m.BindingValueHex = hex.EncodeToString(bv[:])
			m.BindingLayout = platform.BindingLayout
			t0 := time.Now()
			ev, err := p.GenerateEvidence(req)
			m.EvidenceMs = float64(time.Since(t0).Microseconds()) / 1000
			dir := filepath.Join(*out, name)
			must(os.MkdirAll(dir, 0o755))
			must(os.WriteFile(filepath.Join(dir, "subject.der"), subject, 0o644))
			if err != nil {
				m.Error = err.Error()
			} else {
				m.TokenBytes = len(ev.Token)
				must(os.WriteFile(filepath.Join(dir, "evidence.tsm.cbor"), ev.Token, 0o644))
				must(os.WriteFile(filepath.Join(dir, "claims.cbor"), ev.Claims, 0o644))
				fillReportFields(&m, ev.Token, *tee)
			}
			all = append(all, m)
			b, _ := json.MarshalIndent(m, "", " ")
			must(os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o644))
			fmt.Printf("%-26s %8.1f ms  %6d B  %s %s\n", name, m.EvidenceMs, m.TokenBytes, m.SigningKey, m.Error)
		}
	}
	b, _ := json.MarshalIndent(all, "", " ")
	must(os.WriteFile(filepath.Join(*out, "cases.json"), b, 0o644))
	if *burst > 0 {
		timeBurst(p, *burst, *target, filepath.Join(*out, "burst.json"))
	}
	if pub := p.AttestationPublicKey(); pub != nil {
		der, _ := x509.MarshalPKIXPublicKey(pub)
		fmt.Printf("attestation key (from the host certificate table): SHA-256(SPKI) %x\n", sha256.Sum256(der))
	}
}

// timeBurst times n GenerateEvidence calls (present-nonce, Enrollment, a fresh nonce and CSR each time).
func timeBurst(p backend, n int, target, path string) {
	csk, err := p.GenerateCSK(platform.SigningAlgorithmECDSAP256)
	must(err)
	signer, err := csk.Signer()
	must(err)
	var ms []float64
	for i := 0; i < n; i++ {
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "workload.tacra.example"}}, signer) // burst only times report generation, not issuance
		must(err)
		req := platform.EvidenceRequest{FreshnessKind: platform.FreshnessKindPresentNonce, FreshnessHandle: random(32),
			Target: target, BoundKey: csk.Public(), CSR: csr, BoundKeyUse: platform.BoundKeyUseSign}
		t0 := time.Now()
		_, err = p.GenerateEvidence(req)
		must(err)
		ms = append(ms, float64(time.Since(t0).Microseconds())/1000)
	}
	sorted := append([]float64(nil), ms...)
	sort.Float64s(sorted)
	q := func(f float64) float64 { return sorted[int(f*float64(len(sorted)-1))] }
	sum := map[string]any{"n": n, "min_ms": sorted[0], "median_ms": q(0.5), "p95_ms": q(0.95), "max_ms": sorted[len(sorted)-1],
		"samples_ms": ms}
	b, _ := json.MarshalIndent(sum, "", " ")
	must(os.WriteFile(path, b, 0o644))
	fmt.Printf("burst of %d: min %.1f ms, median %.1f ms, p95 %.1f ms, max %.1f ms\n", n, sorted[0], q(0.5), q(0.95),
		sorted[len(sorted)-1])
}

// fillReportFields reads SIGNING_KEY (48h bits 4:2) and CHIP_ID (1A0h) from an SEV-SNP report, or MRTD from a TDX
// quote (offset 48 + 136), inside the TSM token.
func fillReportFields(m *caseMeta, token []byte, tee string) {
	rep, err := platform.ReportFromTSMToken(token)
	if err != nil || len(rep) < 0x1E0 {
		return
	}
	sum := sha256.Sum256(rep)
	m.ReportSHA256 = hex.EncodeToString(sum[:])
	if tee == "tdx" {
		m.SigningKey = "TDX quote"
		m.ChipIDPrefix = "MRTD " + hex.EncodeToString(rep[48+136:48+144])
		return
	}
	switch (binary.LittleEndian.Uint32(rep[0x48:]) >> 2) & 7 {
	case 0:
		m.SigningKey = "VCEK"
	case 1:
		m.SigningKey = "VLEK"
	default:
		m.SigningKey = "other"
	}
	m.ChipIDPrefix = hex.EncodeToString(rep[0x1A0:0x1A8])
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "hwrun:", err)
		os.Exit(1)
	}
}
