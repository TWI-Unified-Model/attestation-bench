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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
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
)

const mediaType = "application/vnd.veraison.tsm-report+cbor"

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

type session struct {
	nonce   []byte
	expires time.Time
	result  string
}

type server struct {
	cfg      config
	key      *ecdsa.PrivateKey
	getter   *cachingGetter
	mu       sync.Mutex
	sessions map[string]*session
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

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	enc := base64.RawURLEncoding
	if raw, err := os.ReadFile(path); err == nil {
		var j struct{ D, X, Y string }
		if err := json.Unmarshal(raw, &j); err != nil {
			return nil, err
		}
		d, _ := enc.DecodeString(j.D)
		x, _ := enc.DecodeString(j.X)
		y, _ := enc.DecodeString(j.Y)
		return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x),
			Y: new(big.Int).SetBytes(y)}, D: new(big.Int).SetBytes(d)}, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "d": enc.EncodeToString(k.D.FillBytes(make([]byte, 32))),
		"x": enc.EncodeToString(k.X.FillBytes(make([]byte, 32))), "y": enc.EncodeToString(k.Y.FillBytes(make([]byte, 32)))})
	return k, os.WriteFile(path, raw, 0o600)
}

func (s *server) publicJWK() map[string]string {
	enc := base64.RawURLEncoding
	return map[string]string{"kty": "EC", "crv": "P-256", "alg": "ES256",
		"x": enc.EncodeToString(s.key.X.FillBytes(make([]byte, 32))), "y": enc.EncodeToString(s.key.Y.FillBytes(make([]byte, 32)))}
}

func (s *server) sign(claims map[string]any) (string, error) {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	signing := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	d := sha256.Sum256([]byte(signing))
	r, sv, err := ecdsa.Sign(rand.Reader, s.key, d[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return signing + "." + enc.EncodeToString(sig), nil
}

// appraise verifies the quote and returns the EAR status and the annotated fields.
func (s *server) appraise(token, nonce []byte) (string, map[string]string, error) {
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

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/veraison/verification", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ear-verification-key": s.publicJWK(), "media-types": []string{mediaType},
			"service-state": "READY"})
	})
	mux.HandleFunc("POST /challenge-response/v1/newSession", func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.ClientCA != "" {
			log.Printf("session for %v", mtls.Names(r))
		}
		nonce, err := base64.URLEncoding.DecodeString(r.URL.Query().Get("nonce"))
		if err != nil || len(nonce) < 8 || len(nonce) > 64 {
			http.Error(w, "nonce must be 8 to 64 octets, base64url", http.StatusBadRequest)
			return
		}
		id := make([]byte, 16)
		_, _ = rand.Read(id)
		sid := hex.EncodeToString(id)
		s.mu.Lock()
		for k, v := range s.sessions {
			if time.Now().After(v.expires) {
				delete(s.sessions, k)
			}
		}
		s.sessions[sid] = &session{nonce: nonce, expires: time.Now().Add(5 * time.Minute)}
		s.mu.Unlock()
		w.Header().Set("Location", "session/"+sid)
		writeJSON(w, http.StatusCreated, map[string]any{"status": "waiting", "nonce": base64.URLEncoding.EncodeToString(nonce),
			"accept": []string{mediaType}})
	})
	mux.HandleFunc("POST /challenge-response/v1/session/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		se, ok := s.sessions[r.PathValue("id")]
		s.mu.Unlock()
		if !ok || time.Now().After(se.expires) {
			http.Error(w, "no such session", http.StatusNotFound)
			return
		}
		if r.Header.Get("Content-Type") != mediaType {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		token, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		status, ann, err := s.appraise(token, se.nonce)
		if status == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"status": "failed", "detail": err.Error()})
			return
		}
		if err != nil {
			log.Printf("appraisal: %s: %v", status, err)
		} else {
			log.Printf("appraisal: affirming, MRTD %s…", ann["mrtd"][:16])
		}
		sub := map[string]any{"ear.status": status, "ear.appraisal-policy-id": "policy:TDX-reference-mrtd",
			"ear.trustworthiness-vector": map[string]int{"hardware": 2, "runtime-opaque": 2, "executables": 0,
				"configuration": 0, "file-system": 0, "instance-identity": 0, "sourced-data": 0, "storage-opaque": 0},
			"ear.veraison.annotated-evidence": ann}
		if status != "affirming" {
			sub["ear.trustworthiness-vector"] = map[string]int{"hardware": 97, "runtime-opaque": 97}
		}
		ear, err := s.sign(map[string]any{"eat_profile": "tag:github.com,2023:veraison/ear", "iat": time.Now().Unix(),
			"eat_nonce":       base64.RawURLEncoding.EncodeToString(se.nonce),
			"ear.verifier-id": map[string]string{"developer": "TACRA test bench", "build": "tdx-verifier (go-tdx-guest)"},
			"submods":         map[string]any{"TDX": sub}})
		if err != nil {
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "complete", "result": ear})
	})
	mux.HandleFunc("DELETE /challenge-response/v1/session/{id}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		delete(s.sessions, r.PathValue("id"))
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
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
	key, err := loadOrCreateKey(cfg.KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	if *printKey {
		_ = json.NewEncoder(os.Stdout).Encode((&server{key: key}).publicJWK())
		return
	}
	maxAge := time.Hour
	if cfg.CollateralMaxAgeS > 0 {
		maxAge = time.Duration(cfg.CollateralMaxAgeS) * time.Second
	}
	s := &server{cfg: cfg, key: key, sessions: map[string]*session{},
		getter: &cachingGetter{inner: trust.DefaultHTTPSGetter(), maxAge: maxAge, now: time.Now, m: map[string]cachedDoc{}}}
	tc, err := mtls.ServerTLS(cfg.ClientCA)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: mtls.Authorize(cfg.ClientCA != "", cfg.Clients, s.routes()),
		ReadHeaderTimeout: 10 * time.Second, TLSConfig: tc}
	log.Printf("tdx-verifier listening on %s; reference MRTDs %d; client CA %q, callers %v", cfg.Listen, len(cfg.MRTDs),
		cfg.ClientCA, cfg.Clients)
	log.Fatal(srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey))
}
