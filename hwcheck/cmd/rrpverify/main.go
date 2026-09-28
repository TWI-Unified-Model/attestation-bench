// Command rrpverify is the Relying Party side of the hardware check.
//
//	rrpverify mint -out handles.json
//	rrpverify verify -in DIR -handles handles.json -ark CHAIN.pem -not-before S -not-after S
//
// mint makes the Freshness Handles an RRP returns at Initiate. verify recomputes, for each case hwrun wrote, the
// binding value from the RRP's own records (its identifier, the Handle it minted or a timestamp inside its window,
// the Target it answered Initiate for, the CSR or CEKpub in the request) and asks the Veraison sevsnp scheme to
// validate the Evidence with that value as the session nonce and AMD's ARK as the trust anchor, then appraises the
// claims against reference values. Every check is repeated with one input changed; each of those must fail.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/ear"
	"github.com/veraison/services/scheme/sevsnp"
	"github.com/veraison/services/vts/appraisal"
)

type handles struct {
	NonceEnroll   []byte `json:"nonce_enroll"`
	NonceRetrieve []byte `json:"nonce_retrieve"`
	Epoch         []byte `json:"epoch"`
	MintedAt      int64  `json:"minted_at"`
}

type caseMeta struct {
	Case             string `json:"case"`
	Mode             string `json:"mode"`
	FreshnessKind    string `json:"freshness_kind"`
	FreshnessElement string `json:"freshness_element_b64,omitempty"`
	Error            string `json:"error,omitempty"`
}

type result struct {
	Case    string  `json:"case"`
	Table   string  `json:"certificate_table"` // as-delivered | pem-normalised
	Check   string  `json:"check"`
	Want    string  `json:"want"`
	Got     string  `json:"got"`
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
	Ms      float64 `json:"ms"`
	EAR     string  `json:"ear_status,omitempty"`
	Comment string  `json:"comment,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: rrpverify mint|verify ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "mint":
		mint(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: rrpverify mint|verify ...")
		os.Exit(2)
	}
}

func mint(args []string) {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	out := fs.String("out", "handles.json", "where to write the handles")
	must(fs.Parse(args))
	h := handles{NonceEnroll: random(32), NonceRetrieve: random(32), Epoch: random(32), MintedAt: time.Now().Unix()}
	b, _ := json.MarshalIndent(h, "", " ")
	must(os.WriteFile(*out, b, 0o644))
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	in := fs.String("in", "hwrun-out", "hwrun output directory")
	handlesPath := fs.String("handles", "handles.json", "the handles this RRP minted")
	arkPath := fs.String("ark", "", "AMD certificate chain from the KDS (PEM; the ARK is the self-signed one)")
	target := fs.String("target", "https://db.tacra.example", "the Target this RRP answered Initiate for")
	rrpCA := fs.String("rrp-ca", "https://ca1.tacra.example", "this Credential Authority's identifier")
	rrpVault := fs.String("rrp-vault", "https://vault1.tacra.example", "this Secret Vault's identifier")
	notBefore := fs.Int64("not-before", 0, "unix seconds: run started (RRP clock)")
	notAfter := fs.Int64("not-after", 0, "unix seconds: run ended (RRP clock)")
	window := fs.Int64("window", 300, "absent-timestamp acceptance window, seconds")
	out := fs.String("out", "", "results file (default DIR/rrpverify-<veraison>.json)")
	must(fs.Parse(args))

	var h handles
	b, err := os.ReadFile(*handlesPath)
	must(err)
	must(json.Unmarshal(b, &h))
	ark, ask := kdsChain(*arkPath)
	ta := trustAnchor(ark)
	otherTA := trustAnchor(ask) // a genuine AMD certificate that is not the ARK

	var metas []caseMeta
	b, err = os.ReadFile(filepath.Join(*in, "cases.json"))
	must(err)
	must(json.Unmarshal(b, &metas))

	impl := sevsnp.NewImplementation()
	var results []result
	var golden *comid.ValueTriple
	goldenFrom := ""
	type passing struct {
		name   string
		claims map[string]any
	}
	var passed []passing

	for _, m := range metas {
		if m.Error != "" {
			results = append(results, result{Case: m.Case, Check: "evidence", Want: "pass", Got: "fail", Error: m.Error})
			continue
		}
		dir := filepath.Join(*in, m.Case)
		token, err := os.ReadFile(filepath.Join(dir, "evidence.tsm.cbor"))
		must(err)
		subject, err := os.ReadFile(filepath.Join(dir, "subject.der"))
		must(err)
		rrp, otherRRP := *rrpCA, *rrpVault
		if m.Mode == "retrieve" {
			rrp, otherRRP = *rrpVault, *rrpCA
		}
		elem, otherElem, err := expectedElement(m, h, *notBefore, *notAfter, *window)
		if err != nil {
			results = append(results, result{Case: m.Case, Check: "freshness policy", Want: "pass", Got: "fail",
				Error: err.Error()})
			continue
		}
		if m.FreshnessKind == "absent-timestamp" {
			// the RRP's own window check on the element carried in the request
			stale := binary.BigEndian.Uint64(elem) - uint64(*window) - 3600
			_, _, perr := expectedElement(caseMeta{FreshnessKind: m.FreshnessKind,
				FreshnessElement: base64.RawURLEncoding.EncodeToString(platform.TimestampElement(int64(stale)))},
				h, *notBefore, *notAfter, *window)
			results = append(results, outcome(m.Case, "-", "timestamp an hour outside the window", "fail", perr, 0))
		}
		flipped := append([]byte(nil), subject...)
		flipped[len(flipped)-1] ^= 1

		tables := map[string][]byte{"as-delivered": token}
		if norm, err := pemNormalised(token); err == nil {
			tables["pem-normalised"] = norm
		} else {
			results = append(results, result{Case: m.Case, Check: "normalise certificate table", Want: "pass",
				Got: "fail", Error: err.Error()})
		}
		for _, tbl := range []string{"as-delivered", "pem-normalised"} {
			tok, ok := tables[tbl]
			if !ok {
				continue
			}
			checks := []struct {
				name string
				want string
				bv   [64]byte
				ta   []*comid.KeyTriple
			}{
				{"honest", "pass", platform.BindingValue(elem, rrp, *target, subject), ta},
				{"other Target", "fail", platform.BindingValue(elem, rrp, "https://other.tacra.example", subject), ta},
				{"other RRP identifier", "fail", platform.BindingValue(elem, otherRRP, *target, subject), ta},
				{"other CSR / CEKpub", "fail", platform.BindingValue(elem, rrp, *target, flipped), ta},
				{"other freshness element", "fail", platform.BindingValue(otherElem, rrp, *target, subject), ta},
				{"trust anchor = ASK, not ARK", "fail", platform.BindingValue(elem, rrp, *target, subject), otherTA},
			}
			for _, c := range checks {
				ev := &appraisal.Evidence{Data: tok, MediaType: sevsnp.EvidenceMediaTypeTSMCbor, Nonce: c.bv[:]}
				t0 := time.Now()
				err := impl.ValidateEvidenceIntegrity(ev, c.ta, nil)
				ms := float64(time.Since(t0).Microseconds()) / 1000
				r := outcome(m.Case, tbl, c.name, c.want, err, ms)
				if c.name == "honest" && err == nil {
					claims, cerr := impl.ExtractClaims(ev, c.ta)
					if cerr == nil {
						passed = append(passed, passing{m.Case + " / " + tbl, claims})
					}
					if golden == nil && cerr == nil {
						golden, err = refValsFromClaims(claims)
						must(err)
						goldenFrom = m.Case + " / " + tbl
					}
				}
				results = append(results, r)
			}
		}
	}

	// Appraisal against reference values: the golden triple is taken from the first Evidence that validated
	// (trust on first use, stated as such), and a copy with one MEASUREMENT byte changed must not affirm.
	if golden != nil {
		bad := tamperMeasurement(golden)
		for _, p := range passed {
			for _, rv := range []struct {
				name string
				want string
				vt   *comid.ValueTriple
			}{{"appraise: reference values of this launch", "affirming", golden},
				{"appraise: MEASUREMENT one byte different", "not affirming", bad}} {
				res, err := impl.AppraiseClaims(p.claims, []*comid.ValueTriple{rv.vt})
				r := result{Case: p.name, Check: rv.name, Want: rv.want, Comment: "reference values from " + goldenFrom}
				if err != nil {
					r.Got, r.Error = "error", err.Error()
				} else {
					st := res.Submods["SEVSNP"].Status
					r.EAR = st.String()
					r.Got = "not affirming"
					if *st == ear.TrustTierAffirming {
						r.Got = "affirming"
					}
				}
				r.OK = r.Got == r.Want
				results = append(results, r)
			}
		}
	}

	build := veraisonBuild()
	if *out == "" {
		*out = filepath.Join(*in, "rrpverify-"+strings.ReplaceAll(filepath.Base(strings.Fields(build)[0]), "/", "_")+".json")
	}
	summary := map[string]any{"veraison": build, "results": results, "golden_from": goldenFrom,
		"target": *target, "rrp_ca": *rrpCA, "rrp_vault": *rrpVault, "window_s": *window,
		"not_before": *notBefore, "not_after": *notAfter}
	b, _ = json.MarshalIndent(summary, "", " ")
	must(os.WriteFile(*out, b, 0o644))
	bad := 0
	fmt.Printf("veraison: %s\n", build)
	for _, r := range results {
		mark := "ok "
		if !r.OK {
			mark, bad = "BAD", bad+1
		}
		fmt.Printf("%s %-26s %-14s %-38s want %-13s got %-13s %6.2f ms %s\n", mark, r.Case, r.Table, r.Check, r.Want,
			r.Got, r.Ms, short(r.Error))
	}
	fmt.Printf("%d checks, %d not as expected; written %s\n", len(results), bad, *out)
}

func outcome(name, tbl, check, want string, err error, ms float64) result {
	r := result{Case: name, Table: tbl, Check: check, Want: want, Got: "pass", Ms: ms}
	if err != nil {
		r.Got, r.Error = "fail", err.Error()
	}
	r.OK = r.Got == r.Want
	return r
}

// expectedElement is the freshness element from the RRP's own records, and a different one the RRP must refuse.
func expectedElement(m caseMeta, h handles, notBefore, notAfter, window int64) (elem, other []byte, err error) {
	switch m.FreshnessKind {
	case "present-nonce":
		if m.Mode == "retrieve" {
			return h.NonceRetrieve, h.NonceEnroll, nil // the other session's Handle
		}
		return h.NonceEnroll, h.NonceRetrieve, nil
	case "present-epoch", "absent-epoch":
		return h.Epoch, random(len(h.Epoch)), nil // another epoch marker
	case "absent-timestamp":
		// carried in the request: the CAAPI Enroll/Retrieve messages have no field for it yet
		e, err := base64.RawURLEncoding.DecodeString(m.FreshnessElement)
		if err != nil || len(e) != 8 {
			return nil, nil, errors.New("absent-timestamp element is not 8 octets")
		}
		ts := int64(binary.BigEndian.Uint64(e))
		if ts < notBefore-window || ts > notAfter+window {
			return nil, nil, fmt.Errorf("timestamp %d outside [%d, %d]", ts, notBefore-window, notAfter+window)
		}
		return e, platform.TimestampElement(ts + 1), nil
	case "absent-none":
		return nil, make([]byte, 8), nil // an element where none is expected
	}
	return nil, nil, fmt.Errorf("unknown freshness kind %q", m.FreshnessKind)
}

// pemNormalised rewrites the certificate table inside a TSM token with every DER entry PEM-encoded, the form the
// Veraison sevsnp scheme reads; the table is not covered by the report signature.
func pemNormalised(token []byte) ([]byte, error) {
	var t map[string]any
	if err := cborUnmarshal(token, &t); err != nil {
		return nil, err
	}
	aux, _ := t["auxblob"].([]byte)
	if len(aux) == 0 {
		return nil, errors.New("no certificate table")
	}
	type entry struct{ guid, cert []byte }
	var entries []entry
	for i := 0; i+24 <= len(aux); i += 24 {
		g := aux[i : i+16]
		if bytes.Equal(g, make([]byte, 16)) {
			break
		}
		off, n := binary.LittleEndian.Uint32(aux[i+16:]), binary.LittleEndian.Uint32(aux[i+20:])
		if uint64(off)+uint64(n) > uint64(len(aux)) {
			return nil, errors.New("certificate table entry out of range")
		}
		c := aux[off : off+n]
		if len(c) > 0 && c[0] == 0x30 {
			c = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})
		}
		entries = append(entries, entry{append([]byte(nil), g...), c})
	}
	off := uint32(24 * (len(entries) + 1))
	var head, body []byte
	for _, e := range entries {
		head = append(head, e.guid...)
		head = binary.LittleEndian.AppendUint32(head, off+uint32(len(body)))
		head = binary.LittleEndian.AppendUint32(head, uint32(len(e.cert)))
		body = append(body, e.cert...)
	}
	head = append(head, make([]byte, 24)...)
	t["auxblob"] = append(head, body...)
	return cborMarshal(t)
}

// kdsChain returns the ARK (self-signed) and the ASK from a KDS cert_chain file.
func kdsChain(path string) (ark, ask []byte) {
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
			ark = blk.Bytes
		} else {
			ask = blk.Bytes
		}
	}
	if ark == nil || ask == nil {
		must(errors.New("the KDS chain needs the ARK and the ASK"))
	}
	return ark, ask
}

func trustAnchor(der []byte) []*comid.KeyTriple {
	k, err := comid.NewPKIXBase64Cert(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	must(err)
	return []*comid.KeyTriple{{VerifKeys: comid.CryptoKeys{k}}}
}

func refValsFromClaims(claims map[string]any) (*comid.ValueTriple, error) {
	b, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	var c corim.UnsignedCorim
	if err := c.FromJSON(b); err != nil {
		return nil, err
	}
	it, iterErr := c.IterRefVals()
	vts := slices.Collect(it)
	if err := iterErr(); err != nil {
		return nil, err
	}
	if len(vts) != 1 {
		return nil, fmt.Errorf("%d reference-value triples", len(vts))
	}
	return vts[0], nil
}

func tamperMeasurement(vt *comid.ValueTriple) *comid.ValueTriple {
	b, err := json.Marshal(vt)
	must(err)
	var cp comid.ValueTriple
	must(json.Unmarshal(b, &cp))
	for i := range cp.Measurements.Values {
		m := &cp.Measurements.Values[i]
		if k, err := m.Key.GetKeyUint(); err == nil && k == 641 && m.Val.Digests != nil {
			(*m.Val.Digests)[0].HashValue[0] ^= 1
		}
	}
	return &cp
}

func veraisonBuild() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/veraison/services" {
				if d.Replace != nil {
					return d.Replace.Path + " " + d.Replace.Version
				}
				return d.Version
			}
		}
	}
	return "unknown"
}

func short(s string) string {
	if len(s) > 90 {
		return s[:90] + "…"
	}
	return s
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
		fmt.Fprintln(os.Stderr, "rrpverify:", err)
		os.Exit(1)
	}
}
