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
	if err := milanPolicy(chip).Check(res); err != nil {
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
		err := c.p.Check(res)
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
		err := p.Check(&ear.Result{Submod: "SEVSNP", SNP: &claims})
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
	if err := tp.Check(&ear.Result{Submod: "SEVSNP", SNP: &turin}); err != nil {
		t.Fatalf("Turin at its floor: %v", err)
	}
	tp.SEVSNP.TCBFloors["Turin"]["snp"] = 6
	if err := tp.Check(&ear.Result{Submod: "SEVSNP", SNP: &turin}); err == nil || !strings.Contains(err.Error(), "snp 5 is below the floor 6") {
		t.Fatalf("Turin below its SNP floor: %v", err)
	}
}

func TestTDXPolicy(t *testing.T) {
	p := &PlatformPolicy{TDX: &TDXPolicy{AttributesRefused: "2000fff0"}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	// Google Cloud TDX of 29 September 2026: ATTRIBUTES 0x10000000, SEPT_VE_DISABLE only
	if err := p.Check(&ear.Result{Submod: "TDX", TDX: map[string]string{"td_attributes": "0000000010000000"}}); err != nil {
		t.Fatalf("recorded ATTRIBUTES: %v", err)
	}
	for attrs, want := range map[string]string{"0000000010000001": "under debug", "0000000010000020": "refused",
		"0000000030000000": "refused"} {
		if err := p.Check(&ear.Result{Submod: "TDX", TDX: map[string]string{"td_attributes": attrs}}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ATTRIBUTES %s: got %v, want %q", attrs, err, want)
		}
	}
	if err := p.Check(&ear.Result{Submod: "TDX", TDX: map[string]string{}}); err == nil {
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

// The bench's rule admits the hosts its hardware runs met (trust/platform-policy.json, "hosts"): the GCP host of the
// real EAR, and an AWS host, VLEK-signed, without CHIP_ID, its COMMITTED_TCB above its REPORTED_TCB. A floor one above
// the host's value refuses it, for that reason, whichever component it is.
func TestBenchPlatformRule(t *testing.T) {
	p := benchRule(t)
	res := realResult(t)
	if err := p.Check(res); err != nil {
		t.Fatalf("the GCP SEV-SNP host: %v", err)
	}
	aws := *res.SNP
	aws.Class, aws.ChipID = ear.ClassByCSP, nil
	aws.Policy = 0x2030000                // PAGE_SWAP_DISABLE (bit 25), the reserved bit 17, SMT (bit 16)
	aws.PlatformInfo = 0x27               // SMT_EN, TSME_EN, ECC_EN, ALIAS_CHECK_COMPLETE
	aws.CommittedTCB = 0xE11F000000000004 // bl 4, tee 0, snp 31, ucode 225 (e2e/evidence/20261007T045331Z-aws-…)
	if err := p.Check(&ear.Result{Submod: "SEVSNP", SNP: &aws}); err != nil {
		t.Fatalf("the AWS SEV-SNP host: %v", err)
	}
	for comp, host := range map[string]int{"bl": 4, "snp": 29, "ucode": 222} {
		q := benchRule(t)
		q.SEVSNP.TCBFloors["Milan"][comp] = host + 1
		want := fmt.Sprintf("REPORTED_TCB %s %d is below the floor %d", comp, host, host+1)
		if err := q.Check(res); err == nil || !errors.Is(err, ErrPlatform) || !strings.Contains(err.Error(), want) {
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
		err := p.Check(&ear.Result{Submod: "TDX", TDX: map[string]string{"td_attributes": attrs}})
		if (want == "" && err != nil) || (want != "" && (err == nil || !strings.Contains(err.Error(), want))) {
			t.Errorf("TD ATTRIBUTES %s: got %v, want %q", attrs, err, want)
		}
	}
}
