package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
)

// realResult verifies the EAR the bench's Veraison issued for the GCP SEV-SNP run 20260928T190538Z (an EPYC Milan
// chip) and returns the Attestation Results the RRP acts on.
func realResult(t *testing.T) *ear.Result {
	t.Helper()
	jwk, _ := os.ReadFile("../ear/testdata/veraison-ear-key.jwk")
	key, err := ear.KeyFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	jws, _ := os.ReadFile("../ear/testdata/ear-gcp-sevsnp.jws")
	bvHex, _ := os.ReadFile("../ear/testdata/binding-value.hex")
	bv, _ := hex.DecodeString(strings.TrimSpace(string(bvHex)))
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(string(jws), ".")[1])
	var iat int64
	if i := bytes.Index(payload, []byte(`"iat":`)); i >= 0 {
		for _, c := range payload[i+6:] {
			if c < '0' || c > '9' {
				break
			}
			iat = iat*10 + int64(c-'0')
		}
	}
	v := &ear.Verifier{Keys: []ear.TrustedKey{{Key: key, Submods: []string{"SEVSNP"}}}, MaxAge: 2 * time.Minute,
		Skew: 5 * time.Second, Now: func() time.Time { return time.Unix(iat, 0).Add(10 * time.Second) }}
	res, err := v.Verify(strings.TrimSpace(string(jws)), bv)
	if err != nil {
		t.Fatal(err)
	}
	if res.SNP == nil {
		t.Fatal(res.SNPErr)
	}
	return res
}

// Google Cloud security bulletin GCP-2025-007 (EntrySign): bootloader 4, SNP 24, microcode 219; the first support
// for a Milan floor (tacra-est impl/policy/bank-default.json).
var milanFloor = map[string]int{"bl": 4, "snp": 24, "ucode": 219}

func milanPolicy(chip []byte) *PlatformPolicy {
	return &PlatformPolicy{SEVSNP: &SNPPolicy{RequireMachineIdentity: true, AllowedChipIDs: []string{hex.EncodeToString(chip)},
		AllowedProducts: []string{"Milan"}, TCBFloors: map[string]map[string]int{"Milan": milanFloor},
		CheckCommittedTCB: true, SMT: "allow-with-microcode-floor"}}
}

func TestPlatformPolicyOnRealResults(t *testing.T) {
	res := realResult(t)
	chip := res.SNP.ChipID
	if err := milanPolicy(chip).Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := milanPolicy(chip).Check(res); err != nil {
		t.Fatalf("Milan admitted, chip listed, floor met: %v", err)
	}
	bank := &PlatformPolicy{SEVSNP: &SNPPolicy{RequireMachineIdentity: true, AllowedProducts: []string{"Genoa", "Turin"},
		TCBFloors: map[string]map[string]int{"Milan": milanFloor}, CheckCommittedTCB: true, SMT: "allow-with-microcode-floor"}}
	for _, c := range []struct {
		name string
		p    *PlatformPolicy
		want string
	}{
		{"the bank's product lines (no Milan)", bank, "is not admitted"},
		{"another chip listed", milanPolicy(bytes.Repeat([]byte{7}, 64)), "not a listed machine"},
		{"SMT forbidden", func() *PlatformPolicy { p := milanPolicy(chip); p.SEVSNP.SMT = "forbid"; return p }(), "SMT is enabled"},
		{"a floor above the report's SNP 0x1D", func() *PlatformPolicy {
			p := milanPolicy(chip)
			p.SEVSNP.TCBFloors = map[string]map[string]int{"Milan": {"bl": 4, "snp": 0x1E, "ucode": 219}}
			return p
		}(), "REPORTED_TCB snp 29 is below the floor 30"},
		{"no floor for Milan", func() *PlatformPolicy { p := milanPolicy(chip); p.SEVSNP.TCBFloors = nil; return p }(), "no TCB floor"},
		{"SMT on, floor without microcode", func() *PlatformPolicy {
			p := milanPolicy(chip)
			p.SEVSNP.TCBFloors = map[string]map[string]int{"Milan": {"bl": 4, "snp": 24}}
			return p
		}(), "no microcode floor is met"},
	} {
		_, err := c.p.Check(res)
		if err == nil || !errors.Is(err, ErrPlatform) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}

func TestPlatformPolicyOnAlteredClaims(t *testing.T) {
	base := *realResult(t).SNP
	p := milanPolicy(base.ChipID)
	for _, c := range []struct {
		name  string
		alter func(c *ear.SNPClaims)
		want  string
	}{
		{"DEBUG", func(c *ear.SNPClaims) { c.Policy |= 1 << 19 }, "POLICY.DEBUG"},
		{"MIGRATE_MA", func(c *ear.SNPClaims) { c.Policy |= 1 << 18 }, "POLICY.MIGRATE_MA"},
		{"bit 17 zero", func(c *ear.SNPClaims) { c.Policy &^= 1 << 17 }, "bit 17"},
		{"VLEK-signed (the provider's key)", func(c *ear.SNPClaims) { c.Class = ear.ClassByCSP }, "names no machine"},
		{"CHIP_ID masked", func(c *ear.SNPClaims) { c.ChipID = nil }, "names no machine"},
		{"report version 2 (no CPUID)", func(c *ear.SNPClaims) { c.HasCPUID = false }, "no CPUID"},
		{"COMMITTED_TCB below the floor", func(c *ear.SNPClaims) { c.CommittedTCB = 0xDE17000000000004 }, "COMMITTED_TCB snp 23"},
	} {
		claims := base
		claims.ChipID = append([]byte(nil), base.ChipID...)
		c.alter(&claims)
		_, err := p.Check(&ear.Result{Submod: "SEVSNP", SNP: &claims})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	// Turin: the same value of REPORTED_TCB reads differently in its layout (Table 4: SNP is byte 3)
	turin := base
	turin.Family, turin.Model = 0x1A, 0x02
	turin.ReportedTCB, turin.CommittedTCB = 0x5100000005040302, 0x5100000005040302
	tp := &PlatformPolicy{SEVSNP: &SNPPolicy{RequireMachineIdentity: true, AllowedProducts: []string{"Turin"},
		TCBFloors:         map[string]map[string]int{"Turin": {"fmc": 2, "bl": 3, "tee": 4, "snp": 5, "ucode": 0x51}},
		CheckCommittedTCB: true, SMT: "allow-with-microcode-floor"}}
	if _, err := tp.Check(&ear.Result{Submod: "SEVSNP", SNP: &turin}); err != nil {
		t.Fatalf("Turin at its floor: %v", err)
	}
	tp.SEVSNP.TCBFloors["Turin"]["snp"] = 6
	if _, err := tp.Check(&ear.Result{Submod: "SEVSNP", SNP: &turin}); err == nil || !strings.Contains(err.Error(), "snp 5 is below the floor 6") {
		t.Fatalf("Turin below its SNP floor: %v", err)
	}
}

func TestTDXPolicy(t *testing.T) {
	p := &PlatformPolicy{TDX: &TDXPolicy{AttributesRefused: "2000fff0"}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	// Google Cloud TDX of 29 September 2026: ATTRIBUTES 0x10000000, SEPT_VE_DISABLE only
	if _, err := p.Check(&ear.Result{Submod: "TDX", TDX: map[string]string{"td_attributes": "0000000010000000"}}); err != nil {
		t.Fatalf("recorded ATTRIBUTES: %v", err)
	}
	for attrs, want := range map[string]string{"0000000010000001": "under debug", "0000000010000020": "refused",
		"0000000030000000": "refused"} {
		if _, err := p.Check(&ear.Result{Submod: "TDX", TDX: map[string]string{"td_attributes": attrs}}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ATTRIBUTES %s: got %v, want %q", attrs, err, want)
		}
	}
	if _, err := p.Check(&ear.Result{Submod: "TDX", TDX: map[string]string{}}); err == nil {
		t.Error("no ATTRIBUTES annotated: accepted")
	}
}

// benchRule reads the platform rule of trust/platform-policy.json as scripts/trustzone.py gives it to the gateways
// (its sevsnp and tdx parts), refusing, as the gateways do, a field they do not know.
func benchRule(t *testing.T) *PlatformPolicy {
	t.Helper()
	raw, err := os.ReadFile("../../../trust/platform-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]json.RawMessage
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	rule, err := json.Marshal(map[string]json.RawMessage{"sevsnp": file["sevsnp"], "tdx": file["tdx"]})
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(rule))
	d.DisallowUnknownFields()
	var p PlatformPolicy
	if err := d.Decode(&p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return &p
}

// packRule is the platform rule a pack's RRPs apply, as scripts/trustzone.py writes it: trust/platform-policy.json
// with the pack's named waivers (platform_waivers).
func packRule(t *testing.T, pack string) *PlatformPolicy {
	t.Helper()
	p := benchRule(t)
	raw, err := os.ReadFile("../../../packs/" + pack + "/pack.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Waivers struct {
			SEVSNP struct {
				Mitigation map[string]map[string]string `json:"mitigation_waivers"`
			} `json:"sevsnp"`
		} `json:"platform_waivers"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	p.SEVSNP.MitigationWaivers = file.Waivers.SEVSNP.Mitigation
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

// The rule on the hosts the bench's hardware runs met, the real results of 7 October 2026: Google Cloud's (VCEK,
// CHIP_ID) and AWS's (VLEK, no CHIP_ID). The shared rule requires AMD's mitigation bits, and neither host sets bit 4
// (AMD-SB-3034). The bench's pack admits both under its named waiver, which the check returns for the RRP's record;
// the Demo Bank's pack, a bank's, refuses both for bit 4. A TCB floor one above the host's value refuses it, for that
// reason, whichever component it is.
func TestBenchPlatformRule(t *testing.T) {
	bench, bank := packRule(t, "tacra-bench"), packRule(t, "demo-bank")
	for _, platform := range []string{"gcp", "aws"} {
		res := realV5Result(t, platform)
		launch, current := res.SNP.LaunchMitVector, res.SNP.CurrentMitVector
		want := fmt.Sprintf("admitted without bit 4, AMD-SB-3034: Milan mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) "+
			"is not set (LAUNCH_MIT_VECTOR %#x, CURRENT_MIT_VECTOR %#x)", launch, current)
		if waived, err := bench.Check(res); err != nil || len(waived) != 1 || waived[0] != want {
			t.Errorf("%s, the bench's rule: got %q %v, want admitted under %q", platform, waived, err, want)
		}
		refusal := fmt.Sprintf("mitigation bit 4 (AMD-SB-3034 (CVE-2025-54510)) is not set in LAUNCH_MIT_VECTOR %#x", launch)
		if _, err := bank.Check(res); err == nil || !errors.Is(err, ErrPlatform) || !strings.Contains(err.Error(), refusal) {
			t.Errorf("%s, the Demo Bank's rule: got %v, want %q", platform, err, refusal)
		}
	}
	res := realV5Result(t, "gcp")
	for comp, at := range tcbLayouts["Milan"] {
		host := int(res.SNP.ReportedTCB >> (8 * at) & 0xFF)
		q := packRule(t, "tacra-bench")
		q.SEVSNP.TCBFloors["Milan"][comp] = host + 1
		want := fmt.Sprintf("REPORTED_TCB %s %d is below the floor %d", comp, host, host+1)
		if _, err := q.Check(res); err == nil || !errors.Is(err, ErrPlatform) || !strings.Contains(err.Error(), want) {
			t.Errorf("a Milan %s floor of %d: got %v, want %q", comp, host+1, err, want)
		}
	}
	// TDX: the GCP TDs' ATTRIBUTES, SEPT_VE_DISABLE only, pass; a TD under debug, profiled or migratable does not
	for attrs, want := range map[string]string{
		"0000000010000000": "",
		"0000000010000001": "under debug",
		"0000000010000010": "bits 10 are refused",
		"0000000030000000": "bits 20000000 are refused",
	} {
		_, err := bench.Check(&ear.Result{Submod: "TDX", TDX: map[string]string{"td_attributes": attrs}})
		if (want == "" && err != nil) || (want != "" && (err == nil || !strings.Contains(err.Error(), want))) {
			t.Errorf("TD ATTRIBUTES %s: got %v, want %q", attrs, err, want)
		}
	}
}

// realV5Result verifies an EAR the bench's Veraison issued on 7 October 2026 with the mitigation vectors annotated
// (../ear/testdata, "gcp" or "aws": the enroll-present-nonce case of the hardware runs 20261007T055700Z-gcp-sev-snp and
// 20261007T060138Z-aws-sev-snp, replayed with rrpverify service -save-ears).
func realV5Result(t *testing.T, platform string) *ear.Result {
	t.Helper()
	jwk, _ := os.ReadFile("../ear/testdata/veraison-ear-key-20261007.jwk")
	key, err := ear.KeyFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	jwsB, _ := os.ReadFile("../ear/testdata/ear-" + platform + "-sevsnp-v5.jws")
	bvHex, _ := os.ReadFile("../ear/testdata/binding-value-" + platform + "-v5.hex")
	bv, _ := hex.DecodeString(strings.TrimSpace(string(bvHex)))
	jws := strings.TrimSpace(string(jwsB))
	var claims struct {
		IAT int64 `json:"iat"`
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(jws, ".")[1])
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	v := &ear.Verifier{Keys: []ear.TrustedKey{{Key: key, Submods: []string{"SEVSNP"}}}, MaxAge: 2 * time.Minute,
		Skew: 5 * time.Second, Now: func() time.Time { return time.Unix(claims.IAT, 0).Add(10 * time.Second) }}
	res, err := v.Verify(jws, bv)
	if err != nil {
		t.Fatal(err)
	}
	if res.SNP == nil || !res.SNP.HasMitVectors {
		t.Fatalf("%s: no mitigation vectors: %+v %v", platform, res.SNP, res.SNPErr)
	}
	return res
}

// The bits AMD attests a fix by, on the real results of both clouds: AMD-SB-3020 names bit 1 for Milan, which both
// hosts set; AMD-SB-3034 names bit 4, which neither sets, so the rule that asks for it refuses both and names the
// bit, its bulletin and the vector. A report without vectors is refused when a bit is required; a bit set at launch
// but not now is refused for the current vector. PLATFORM_INFO bit 5 (BadRAM, AMD-SB-3015) is set on both hosts.
func TestMitigationAndPlatformInfoBits(t *testing.T) {
	sb3020 := map[string]string{"1": "AMD-SB-3020"}
	amd := map[string]string{"1": "AMD-SB-3020", "4": "AMD-SB-3034"}
	rule := func(mit, pinfo map[string]string) *PlatformPolicy {
		p := benchRule(t)
		p.SEVSNP.RequiredMitigationBits = map[string]map[string]string{"Milan": mit}
		p.SEVSNP.RequiredPlatformInfoBits = map[string]map[string]string{"Milan": pinfo}
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		return p
	}
	badram := map[string]string{"5": "AMD-SB-3015: ALIAS_CHECK_COMPLETE"}
	for _, c := range []struct {
		platform string
		vector   string
	}{{"gcp", "0xb"}, {"aws", "0x10f"}} {
		res := realV5Result(t, c.platform)
		if _, err := rule(sb3020, badram).Check(res); err != nil {
			t.Errorf("%s, bit 1 and BadRAM: %v", c.platform, err)
		}
		want := "mitigation bit 4 (AMD-SB-3034) is not set in LAUNCH_MIT_VECTOR " + c.vector
		if _, err := rule(amd, badram).Check(res); err == nil || !errors.Is(err, ErrPlatform) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s, AMD's bits: got %v, want %q", c.platform, err, want)
		}
		if _, err := rule(nil, map[string]string{"4": "a bit no host sets"}).Check(res); err == nil ||
			!strings.Contains(err.Error(), "PLATFORM_INFO bit 4 (a bit no host sets) is not set") {
			t.Errorf("%s, PLATFORM_INFO bit 4: %v", c.platform, err)
		}
	}
	gcp := *realV5Result(t, "gcp").SNP
	gcp.LaunchMitVector |= 1 << 4
	if _, err := rule(amd, nil).Check(&ear.Result{Submod: "SEVSNP", SNP: &gcp}); err == nil ||
		!strings.Contains(err.Error(), "mitigation bit 4 (AMD-SB-3034) is not set in CURRENT_MIT_VECTOR 0xb") {
		t.Errorf("bit 4 at launch only: %v", err)
	}
	gcp.CurrentMitVector |= 1 << 4
	if _, err := rule(amd, nil).Check(&ear.Result{Submod: "SEVSNP", SNP: &gcp}); err != nil {
		t.Errorf("bit 4 at launch and now: %v", err)
	}
	if _, err := rule(sb3020, nil).Check(realResult(t)); err == nil || !strings.Contains(err.Error(), "carries no mitigation vector") {
		t.Errorf("the EAR of 28 September, without vectors: %v", err)
	}
	// a waiver admits what it names and nothing else, and the check says which it applied
	waive := func(p *PlatformPolicy, bits map[string]string) *PlatformPolicy {
		p.SEVSNP.MitigationWaivers = map[string]map[string]string{"Milan": bits}
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		return p
	}
	res := realV5Result(t, "gcp")
	if w, err := waive(rule(amd, badram), map[string]string{"4": "a waiver"}).Check(res); err != nil || len(w) != 1 ||
		!strings.HasPrefix(w[0], "a waiver: Milan mitigation bit 4 (AMD-SB-3034) is not set (LAUNCH_MIT_VECTOR 0xb") {
		t.Errorf("bit 4 waived: got %q %v", w, err)
	}
	if _, err := waive(rule(amd, badram), map[string]string{"1": "a waiver of another bit"}).Check(res); err == nil ||
		!strings.Contains(err.Error(), "mitigation bit 4 (AMD-SB-3034) is not set") {
		t.Errorf("bit 1 waived, bit 4 missing: %v", err)
	}
	if w, err := waive(rule(amd, nil), map[string]string{"4": "a waiver"}).Check(&ear.Result{Submod: "SEVSNP", SNP: &gcp}); err != nil || len(w) != 0 {
		t.Errorf("bit 4 set at launch and now, under a waiver of it: got %q %v, want nothing waived", w, err)
	}
	notRequired := rule(sb3020, nil)
	notRequired.SEVSNP.MitigationWaivers = map[string]map[string]string{"Milan": {"4": "a waiver"}}
	if err := notRequired.Validate(); err == nil || !strings.Contains(err.Error(), "bit 4 is waived but not required") {
		t.Errorf("a waiver of a bit not required: %v", err)
	}
	for _, bad := range []*PlatformPolicy{
		{SEVSNP: &SNPPolicy{SMT: "forbid", RequiredMitigationBits: map[string]map[string]string{"Rome": sb3020}}},
		{SEVSNP: &SNPPolicy{SMT: "forbid", RequiredMitigationBits: map[string]map[string]string{"Milan": {"64": "x"}}}},
		{SEVSNP: &SNPPolicy{SMT: "forbid", RequiredPlatformInfoBits: map[string]map[string]string{"Milan": {"05": "x"}}}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("accepted %+v", bad.SEVSNP)
		}
	}
}
