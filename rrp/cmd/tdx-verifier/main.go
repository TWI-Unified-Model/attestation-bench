// Command tdx-verifier is the test bench's Verifier for Intel TDX Evidence, which the Veraison deployment cannot
// appraise (veraison-services has no TDX scheme). It offers the subset of Veraison's challenge-response API the EST
// server uses: a session whose nonce the caller chooses, Evidence as a TSM report (provider tdx_guest), and an EAR
// signed ES256 with its own key. The quote is verified with go-tdx-guest against Intel PCS collateral with
// revocation checks; REPORTDATA must be the session nonce; SEAMATTRIBUTES must be zero; the TD's ATTRIBUTES must
// have no bit of the TUD group (a TD under debug is untrusted) and none of the bits the configuration refuses;
// MRTD must be one of the configured reference values, and so must each run-time register the configuration names.
// It appraises and reports; it does not decide issuance or release.
//
//	tdx-verifier -config tdx-verifier.json
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tdx-guest/abi"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/mtls"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/verifierapi"
)

type config struct {
	Listen  string `json:"listen"`
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// Mutual TLS (N23): callers present a certificate of ClientCA, and only the identities Clients names (the EST
	// server, the RRP gateways) may open sessions.
	ClientCA string   `json:"client_ca,omitempty"`
	Clients  []string `json:"clients,omitempty"`
	KeyFile  string   `json:"signing_key"` // ES256 private JWK; created if absent
	MRTDs    []string `json:"reference_mrtd"`
	// TD ATTRIBUTES bits refused beyond the TUD group, which is always refused; a hex mask. Absent: the TUP group
	// (bits 15:4, the TD is profiled) and MIGRATABLE (bit 29).
	AttributesRefused string `json:"td_attributes_refused,omitempty"`
	// Reference values of the run-time registers, by name ("rtmr0" to "rtmr3"): a register named here must hold one
	// of its values; a register not named is only annotated.
	RTMRs map[string][]string `json:"reference_rtmr,omitempty"`
	// How long an Intel PCS document, revocation lists included, is reused before it is fetched again, in seconds;
	// absent: one hour.
	CollateralMaxAgeS int `json:"collateral_max_age,omitempty"`
}

// The TD's ATTRIBUTES (Intel TDX Module ABI Reference 348551-008US, Table 3.23): "If any bit in the TUD group is set
// to 1, the guest TD is under off-TD debug and is untrusted" (bits 3:0; bit 0 is DEBUG); the TUP group (bits 15:4)
// means the TD is subject to profiling, "which may expose side channel information to untrusted entities";
// MIGRATABLE (bit 29) has a negative security impact.
const (
	attrTUD        = uint64(0x000F)
	attrTUP        = uint64(0xFFF0)
	attrMigratable = uint64(1) << 29
	// defaultRefused is refused unless the configuration says otherwise.
	defaultRefused = attrTUP | attrMigratable
)

// Offsets in the TD Quote Body (Intel TDX DCAP Quote Generation and Verification Library, A.3.2): TEE_TCB_SVN 16,
// MRSEAM 48, MRSIGNERSEAM 48, SEAMATTRIBUTES 8 ("Must be zero for TDX 1.0"), TDATTRIBUTES 8, XFAM 8, MRTD 48, ...
const (
	offSeamAttributes = 112
	offTDAttributes   = 120
	offXFAM           = 128
)

// refusedMask is the ATTRIBUTES mask this configuration refuses, always including the TUD group.
func (c *config) refusedMask() (uint64, error) {
	if c.AttributesRefused == "" {
		return attrTUD | defaultRefused, nil
	}
	m, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(c.AttributesRefused), "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("td_attributes_refused %q: %w", c.AttributesRefused, err)
	}
	return attrTUD | m, nil
}

// checkTD applies this Verifier's rules to a TD Quote Body and annotates what it read; the quote's signature and
// REPORTDATA are checked before.
func (c *config) checkTD(body []byte, ann map[string]string) error {
	seam := binary.LittleEndian.Uint64(body[offSeamAttributes:])
	attrs := binary.LittleEndian.Uint64(body[offTDAttributes:])
	ann["seam_attributes"] = fmt.Sprintf("%016x", seam)
	ann["td_attributes"] = fmt.Sprintf("%016x", attrs)
	ann["xfam"] = fmt.Sprintf("%016x", binary.LittleEndian.Uint64(body[offXFAM:]))
	if seam != 0 {
		return fmt.Errorf("SEAMATTRIBUTES %016x is not zero", seam)
	}
	refused, err := c.refusedMask()
	if err != nil {
		return err
	}
	if attrs&attrTUD != 0 {
		return fmt.Errorf("TD ATTRIBUTES %016x: the TD is under debug (TUD bits %x)", attrs, attrs&attrTUD)
	}
	if bad := attrs & refused; bad != 0 {
		return fmt.Errorf("TD ATTRIBUTES %016x: bits %x are refused by this Verifier's configuration", attrs, bad)
	}
	if !slices.Contains(c.MRTDs, ann["mrtd"]) {
		return fmt.Errorf("MRTD %s matches no reference value", ann["mrtd"])
	}
	for _, name := range []string{"rtmr0", "rtmr1", "rtmr2", "rtmr3"} {
		if refs, ok := c.RTMRs[name]; ok && !slices.Contains(refs, ann[name]) {
			return fmt.Errorf("%s %s matches no reference value", strings.ToUpper(name), ann[name])
		}
	}
	return nil
}

// appraiser holds what the appraisal needs: the configuration and the Intel PCS getter.
type appraiser struct {
	cfg    config
	getter *cachingGetter
}

// cachingGetter keeps each Intel PCS document (TCB Info, QE Identity, the revocation lists) for at most maxAge, so
// that a revocation Intel publishes reaches this Verifier within that time rather than at its next restart.
type cachingGetter struct {
	inner  trust.HTTPSGetter
	maxAge time.Duration
	now    func() time.Time
	mu     sync.Mutex
	m      map[string]cachedDoc
}

type cachedDoc struct {
	header  map[string][]string
	body    []byte
	fetched time.Time
}

func (g *cachingGetter) Get(url string) (map[string][]string, []byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if d, ok := g.m[url]; ok && g.now().Sub(d.fetched) < g.maxAge {
		return d.header, d.body, nil
	}
	h, b, err := g.inner.Get(url)
	if err != nil {
		return h, b, err
	}
	g.m[url] = cachedDoc{header: h, body: b, fetched: g.now()}
	return h, b, nil
}

// appraise verifies the quote and returns the EAR status and the annotated fields.
func (s *appraiser) appraise(token, nonce []byte) (string, map[string]string, error) {
	var t struct {
		OutBlob  []byte `cbor:"outblob"`
		Provider string `cbor:"provider"`
	}
	if err := cbor.Unmarshal(token, &t); err != nil || strings.TrimSpace(t.Provider) != "tdx_guest" || len(t.OutBlob) < 48+584 {
		return "", nil, errors.New("not a TSM report of a TDX quote")
	}
	q, err := abi.QuoteToProto(t.OutBlob)
	if err != nil {
		return "", nil, err
	}
	if err := tdxverify.TdxQuote(q, &tdxverify.Options{CheckRevocations: true, GetCollateral: true, Getter: s.getter,
		Now: time.Now()}); err != nil {
		return "contraindicated", nil, fmt.Errorf("quote: %w", err)
	}
	body := t.OutBlob[48 : 48+584]
	ann := map[string]string{"mrtd": hex.EncodeToString(body[136:184]), "rtmr0": hex.EncodeToString(body[328:376]),
		"rtmr1": hex.EncodeToString(body[376:424]), "rtmr2": hex.EncodeToString(body[424:472]),
		"rtmr3": hex.EncodeToString(body[472:520]), "tee_tcb_svn": hex.EncodeToString(body[0:16])}
	if !bytes.Equal(body[520:584], nonce) {
		return "contraindicated", ann, errors.New("REPORTDATA is not the session nonce")
	}
	if err := s.cfg.checkTD(body, ann); err != nil {
		return "contraindicated", ann, err
	}
	return "affirming", ann, nil
}

func main() {
	path := flag.String("config", "tdx-verifier.json", "configuration file")
	printKey := flag.Bool("public-jwk", false, "print the EAR verification key as a public JWK (creating the signing key if absent) and exit: "+
		"what the RRPs' operator provisions to them")
	flag.Parse()
	raw, err := os.ReadFile(*path)
	if err != nil {
		log.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatal(err)
	}
	refused, err := cfg.refusedMask()
	if err != nil {
		log.Fatal(err)
	}
	for name := range cfg.RTMRs {
		if !slices.Contains([]string{"rtmr0", "rtmr1", "rtmr2", "rtmr3"}, name) {
			log.Fatalf("reference_rtmr: unknown register %q", name)
		}
	}
	log.Printf("TD ATTRIBUTES refused: %016x; reference RTMRs for %d registers", refused, len(cfg.RTMRs))
	key, err := verifierapi.LoadOrCreateKey(cfg.KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	if *printKey { // the EAR key, for the RRPs' operator to provision (N24)
		pub, err := verifierapi.PublicJWK(&key.PublicKey)
		if err == nil {
			err = json.NewEncoder(os.Stdout).Encode(pub)
		}
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	maxAge := time.Hour
	if cfg.CollateralMaxAgeS > 0 {
		maxAge = time.Duration(cfg.CollateralMaxAgeS) * time.Second
	}
	a := &appraiser{cfg: cfg, getter: &cachingGetter{inner: trust.DefaultHTTPSGetter(), maxAge: maxAge, now: time.Now,
		m: map[string]cachedDoc{}}}
	api := &verifierapi.Server{Key: key, Submod: "TDX", PolicyID: "policy:TDX-reference-mrtd",
		Build: "tdx-verifier (go-tdx-guest)", Appraise: a.appraise, LogSessions: cfg.ClientCA != "",
		Trust: map[string]int{"hardware": 2, "runtime-opaque": 2, "executables": 0, "configuration": 0, "file-system": 0,
			"instance-identity": 0, "sourced-data": 0, "storage-opaque": 0},
		Summary: func(ann map[string]string) string { return "MRTD " + ann["mrtd"][:16] + "…" }}
	tc, err := mtls.ServerTLS(cfg.ClientCA)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: mtls.Authorize(cfg.ClientCA != "", cfg.Clients, api.Routes()),
		ReadHeaderTimeout: 10 * time.Second, TLSConfig: tc}
	log.Printf("tdx-verifier listening on %s; reference MRTDs %d; client CA %q, callers %v", cfg.Listen, len(cfg.MRTDs),
		cfg.ClientCA, cfg.Clients)
	log.Fatal(srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey))
}
