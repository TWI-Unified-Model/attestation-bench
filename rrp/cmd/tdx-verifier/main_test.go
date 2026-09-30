package main

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// recordedBody returns the TD Quote Body of a quote recorded on Google Cloud TDX on 29 September 2026 (hwcheck
// evidence), whose TD ATTRIBUTES are 0x10000000: SEPT_VE_DISABLE only.
func recordedBody(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../hwcheck/evidence/20260929T184031Z-gcp-tdx/enroll-present-nonce/evidence.tsm.cbor")
	if err != nil {
		t.Fatal(err)
	}
	var tsm struct {
		OutBlob []byte `cbor:"outblob"`
	}
	if err := cbor.Unmarshal(raw, &tsm); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), tsm.OutBlob[48:48+584]...)
}

func annotate(body []byte) map[string]string {
	return map[string]string{"mrtd": hex.EncodeToString(body[136:184]), "rtmr0": hex.EncodeToString(body[328:376]),
		"rtmr1": hex.EncodeToString(body[376:424]), "rtmr2": hex.EncodeToString(body[424:472]),
		"rtmr3": hex.EncodeToString(body[472:520])}
}

func withAttributes(body []byte, set uint64) []byte {
	b := append([]byte(nil), body...)
	binary.LittleEndian.PutUint64(b[offTDAttributes:], binary.LittleEndian.Uint64(b[offTDAttributes:])|set)
	return b
}

func TestRecordedQuotePasses(t *testing.T) {
	body := recordedBody(t)
	ann := annotate(body)
	cfg := &config{MRTDs: []string{ann["mrtd"]}, RTMRs: map[string][]string{"rtmr1": {ann["rtmr1"]}, "rtmr2": {ann["rtmr2"]}}}
	if err := cfg.checkTD(body, ann); err != nil {
		t.Fatalf("the recorded quote is refused: %v", err)
	}
	if ann["td_attributes"] != "0000000010000000" || ann["seam_attributes"] != "0000000000000000" {
		t.Fatalf("annotations: %v", ann)
	}
}

func TestRefusals(t *testing.T) {
	body := recordedBody(t)
	mrtd := annotate(body)["mrtd"]
	for _, c := range []struct {
		name    string
		body    []byte
		cfg     config
		wantErr string
	}{
		{"DEBUG", withAttributes(body, 1), config{MRTDs: []string{mrtd}}, "under debug"},
		{"DEBUG, even when the configuration refuses nothing else", withAttributes(body, 1), config{MRTDs: []string{mrtd}, AttributesRefused: "0"}, "under debug"},
		{"another TUD bit", withAttributes(body, 1<<2), config{MRTDs: []string{mrtd}}, "under debug"},
		{"PERF_PROF (TUP)", withAttributes(body, 1<<5), config{MRTDs: []string{mrtd}}, "refused by this Verifier"},
		{"MIGRATABLE", withAttributes(body, 1<<29), config{MRTDs: []string{mrtd}}, "refused by this Verifier"},
		{"SEAMATTRIBUTES", func() []byte {
			b := append([]byte(nil), body...)
			b[offSeamAttributes] = 1
			return b
		}(), config{MRTDs: []string{mrtd}}, "SEAMATTRIBUTES"},
		{"MRTD", body, config{MRTDs: []string{strings.Repeat("00", 48)}}, "MRTD"},
		{"RTMR2", body, config{MRTDs: []string{mrtd}, RTMRs: map[string][]string{"rtmr2": {strings.Repeat("00", 48)}}}, "RTMR2"},
	} {
		err := c.cfg.checkTD(c.body, annotate(c.body))
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: got %v, want an error containing %q", c.name, err, c.wantErr)
		}
	}
	// With the default mask cleared, profiling is admitted, and the TD under debug still is not.
	cfg := config{MRTDs: []string{mrtd}, AttributesRefused: "0"}
	if err := cfg.checkTD(withAttributes(body, 1<<5), annotate(body)); err != nil {
		t.Errorf("PERF_PROF with an empty refused mask: %v", err)
	}
}

type countingGetter struct{ n int }

func (g *countingGetter) Get(string) (map[string][]string, []byte, error) {
	g.n++
	return nil, []byte{byte(g.n)}, nil
}

// A PCS document is reused for maxAge and fetched again after it, so that a revocation reaches the Verifier.
func TestCollateralIsRefetched(t *testing.T) {
	clock := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	inner := &countingGetter{}
	g := &cachingGetter{inner: inner, maxAge: time.Hour, now: func() time.Time { return clock }, m: map[string]cachedDoc{}}
	_, b1, _ := g.Get("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform")
	clock = clock.Add(59 * time.Minute)
	_, b2, _ := g.Get("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform")
	clock = clock.Add(2 * time.Minute)
	_, b3, _ := g.Get("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform")
	if inner.n != 2 || b1[0] != 1 || b2[0] != 1 || b3[0] != 2 {
		t.Fatalf("fetches %d, bodies %v %v %v", inner.n, b1, b2, b3)
	}
}
