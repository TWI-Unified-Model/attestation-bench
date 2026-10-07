package main

import (
	"strings"
	"testing"
)

// The reports of two committed hardware runs of 7 October 2026, as go-sev-guest reads them: a Google Cloud host
// (VCEK-signed, with a CHIP_ID) and an AWS host (VLEK-signed, without one, its committed TCB above the reported one).
// Each has TCB[SNP] 0x1D; neither sets mitigation bit 4, which AMD-SB-3034 names for Milan.
func TestCommittedRuns(t *testing.T) {
	for _, c := range []struct {
		dir  string
		want []string
	}{
		{"../../evidence/20261007T050654Z-gcp-sev-snp", []string{
			"version 5", "POLICY 0x30000", "PLATFORM_INFO 0x25",
			"REPORTED_TCB 0xde1d000000000004 (bl 4, tee 0, snp 29, ucode 222)",
			"COMMITTED_TCB 0xde1d000000000004 (bl 4, tee 0, snp 29, ucode 222)",
			"CPUID family 0x19 model 0x1", "CHIP_ID present",
			"LAUNCH_MIT_VECTOR 0xb (bits 0, 1, 3)", "CURRENT_MIT_VECTOR 0xb (bits 0, 1, 3)",
		}},
		{"../../evidence/20261007T051142Z-aws-sev-snp", []string{
			"version 5", "POLICY 0x2030000", "PLATFORM_INFO 0x27",
			"REPORTED_TCB 0xde1d000000000004 (bl 4, tee 0, snp 29, ucode 222)",
			"COMMITTED_TCB 0xe11f000000000004 (bl 4, tee 0, snp 31, ucode 225)",
			"CPUID family 0x19 model 0x1", "CHIP_ID zero",
			"CURRENT_MIT_VECTOR 0x10f (bits 0, 1, 2, 3, 8)",
		}},
	} {
		lines, n, err := runReports(c.dir)
		if err != nil {
			t.Fatal(err)
		}
		if n != 10 || len(lines) != 1 || lines[0].count != 10 {
			t.Fatalf("%s: %d reports, %d distinct; want 10 identical", c.dir, n, len(lines))
		}
		for _, w := range c.want {
			if !strings.Contains(lines[0].text, w) {
				t.Errorf("%s: %q\nlacks %q", c.dir, lines[0].text, w)
			}
		}
	}
	if _, _, err := runReports("../../evidence/20261007T051341Z-gcp-tdx"); err == nil {
		t.Error("a TDX run read as SEV-SNP reports")
	}
}
