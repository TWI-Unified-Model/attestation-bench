package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The attack runs of 8 October 2026 on the three platforms, as the conduit sees them: a Google Cloud SEV-SNP host
// (VCEK-signed, the chip named), an AWS host (VLEK-signed, CHIP_ID zero, the provider's key domain named) and a
// Google Cloud TDX host (the PCK chain naming the platform). Each run's binding value, which hwrun recorded beside
// the report, is the REPORT_DATA the view shows.
func TestCommittedRuns(t *testing.T) {
	for _, c := range []struct {
		dir  string
		want []string
	}{
		{"../../evidence/20261008T154907Z-gcp-sev-snp", []string{
			"from the sev_guest provider", "VCEK-signed, CHIP_ID masked by the host false", "CHIP_ID", "present:",
			"the machine: CHIP_ID, and the VCEK certificate's hwID, name the chip", "certificate: VCEK:", "hwID",
			"certificate: ARK:", "SEVSNP: status affirming", "trustworthiness vector: hardware 2, runtime-opaque 2",
			"and in Passport, from the Attestation Results",
		}},
		{"../../evidence/20261008T155945Z-aws-sev-snp", []string{
			"VLEK-signed, CHIP_ID masked by the host false", "zero",
			"the machine: not named: the report is VLEK-signed and its CHIP_ID is zero", "certificate: VLEK:", "cspID",
		}},
		{"../../evidence/20261008T160809Z-gcp-tdx", []string{
			"from the tdx_guest provider", "MRTD", "RTMR3", "QE_REPORT.MRSIGNER",
			"the machine: the PCK certificate names the platform: PPID", "FMSPC", "PCE-ID", "TDX: status affirming",
			"annotated evidence: mrtd, rtmr0, rtmr1, rtmr2, rtmr3",
		}},
	} {
		text, err := describeRun(c.dir)
		if err != nil {
			t.Fatalf("%s: %v", c.dir, err)
		}
		for _, w := range c.want {
			if !strings.Contains(text, w) {
				t.Errorf("%s: the view lacks %q:\n%s", c.dir, w, text)
			}
		}
		if !strings.Contains(text, bindingValue(t, c.dir)+" (the binding value)") {
			t.Errorf("%s: the view does not show the run's binding value as the Attester's field:\n%s", c.dir, text)
		}
	}
}

// bindingValue is the binding value hwrun recorded for the first case of the run, as viewOf reads the cases.
func bindingValue(t *testing.T, dir string) string {
	t.Helper()
	files, err := reportFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(files[0]), "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		BindingValueHex string `json:"binding_value_hex"`
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	return meta.BindingValueHex
}

func TestNotARun(t *testing.T) {
	if _, err := describeRun(t.TempDir()); err == nil {
		t.Error("an empty directory read as a run")
	}
}
