package ear

import (
	"encoding/hex"
	"testing"
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
