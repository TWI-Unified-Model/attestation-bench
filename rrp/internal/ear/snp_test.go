package ear

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// The fields of the report of the GCP run 20260928T190538Z as Veraison annotated them (testdata/ear-gcp-sevsnp.jws):
// a VCEK-signed report of an EPYC Milan chip (CPUID family 19h, model 01h), POLICY 0x30000 (SMT allowed, bit 17),
// PLATFORM_INFO 0x25 (SMT enabled, ECC, alias check complete), TCB bootloader 4, SNP 0x1D, microcode 0xDE.
func TestRealEARClaims(t *testing.T) {
	v, jws, bv, _ := load(t)
	res, err := v.Verify(jws, bv)
	if err != nil {
		t.Fatal(err)
	}
	c := res.SNP
	if c == nil {
		t.Fatalf("no SEV-SNP claims: %v", res.SNPErr)
	}
	if c.Class != ClassByChip || c.Policy != 0x30000 || c.PlatformInfo != 0x25 ||
		c.ReportedTCB != 0xDE1D000000000004 || c.CommittedTCB != 0xDE1D000000000004 ||
		!c.HasCPUID || c.Family != 0x19 || c.Model != 0x01 || c.Stepping != 0x01 || len(c.ChipID) != 64 {
		t.Fatalf("claims %+v", c)
	}
	if got := hex.EncodeToString(c.ChipID[:8]); got != "d0876de8176e7a44" {
		t.Fatalf("CHIP_ID starts %s", got)
	}
}

// loadV5 returns an EAR the bench's Veraison issued on 7 October 2026, with go-gen-ref annotating the mitigation
// vectors, for the Evidence of a hardware run replayed through it (`rrpverify service -save-ears`): "gcp" is
// hwcheck/evidence/20261007T055700Z-gcp-sev-snp, "aws" 20261007T060138Z-aws-sev-snp, both the enroll-present-nonce
// case. The verifier trusts that deployment's key and reads the EAR at the time it was issued.
func loadV5(t *testing.T, platform string) (*Verifier, string, []byte) {
	t.Helper()
	jwk, err := os.ReadFile("testdata/veraison-ear-key-20261007.jwk")
	if err != nil {
		t.Fatal(err)
	}
	key, err := KeyFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	jwsB, _ := os.ReadFile("testdata/ear-" + platform + "-sevsnp-v5.jws")
	bvHex, _ := os.ReadFile("testdata/binding-value-" + platform + "-v5.hex")
	bv, _ := hex.DecodeString(strings.TrimSpace(string(bvHex)))
	jws := strings.TrimSpace(string(jwsB))
	var claims struct {
		IAT int64 `json:"iat"`
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(jws, ".")[1])
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	iat := time.Unix(claims.IAT, 0)
	return &Verifier{Keys: []TrustedKey{{Key: key, Submods: []string{"SEVSNP"}}}, MaxAge: 2 * time.Minute,
		Skew: 5 * time.Second, Now: func() time.Time { return iat.Add(10 * time.Second) }}, jws, bv
}

// The mitigation vectors as the RRP reads them from real results: the Google Cloud host 0xb at launch and now
// (bits 0, 1, 3), the AWS host 0x10f (bits 0 to 3, and 8); neither sets bit 4. The EAR of 28 September predates the
// annotation and has none.
func TestRealEARMitigationVectors(t *testing.T) {
	for _, c := range []struct {
		platform        string
		class           string
		platformInfo    uint64
		launch, current uint64
	}{
		{"gcp", ClassByChip, 0x25, 0xb, 0xb},
		{"aws", ClassByCSP, 0x27, 0x10f, 0x10f},
	} {
		v, jws, bv := loadV5(t, c.platform)
		res, err := v.Verify(jws, bv)
		if err != nil {
			t.Fatalf("%s: %v", c.platform, err)
		}
		s := res.SNP
		if s == nil {
			t.Fatalf("%s: no SEV-SNP claims: %v", c.platform, res.SNPErr)
		}
		if s.Class != c.class || s.PlatformInfo != c.platformInfo || !s.HasMitVectors || s.LaunchMitVector != c.launch ||
			s.CurrentMitVector != c.current || s.ReportedTCB != 0xDE1D000000000004 {
			t.Fatalf("%s: claims %+v", c.platform, s)
		}
	}
	v, jws, bv, _ := load(t)
	res, err := v.Verify(jws, bv)
	if err != nil {
		t.Fatal(err)
	}
	if res.SNP.HasMitVectors {
		t.Fatalf("the EAR of 28 September carries mitigation vectors: %+v", res.SNP)
	}
}
