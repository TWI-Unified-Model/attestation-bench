package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/gateway"
)

// TestGroupIDPerTarget (tacra-est N2): the Target is part of the credential group. For the bench's approved
// SEV-SNP launches (trust/approved-launches.json, the measurements real hardware reports), one Target and one hint
// give one group, every time; another Target, launch, platform, hint or policy version gives another group. The
// release itself, through the live Vault, runs in every hardware run.
func TestGroupIDPerTarget(t *testing.T) {
	b, err := os.ReadFile("../../../trust/approved-launches.json")
	if err != nil {
		t.Fatal(err)
	}
	var approved struct {
		SEVSNP []struct {
			Measurement string `json:"measurement"`
		} `json:"sev-snp"`
	}
	if err := json.Unmarshal(b, &approved); err != nil {
		t.Fatal(err)
	}
	if len(approved.SEVSNP) < 2 {
		t.Fatalf("%d approved SEV-SNP launches; the test needs two", len(approved.SEVSNP))
	}
	gcp, err := hex.DecodeString(approved.SEVSNP[0].Measurement)
	if err != nil {
		t.Fatal(err)
	}
	aws, err := hex.DecodeString(approved.SEVSNP[1].Measurement)
	if err != nil {
		t.Fatal(err)
	}
	const hint, ledgerA, ledgerB = "payments.workload.tacra.example", "https://ledger-a.tacra.example", "https://ledger-b.tacra.example"
	snp := gateway.Platform("SEVSNP")
	base := groupID(gcp, snp, ledgerA, hint, "1")
	if len(base) != 64 {
		t.Fatalf("group ID %q is not 32 octets in hex", base)
	}
	if again := groupID(gcp, snp, ledgerA, hint, "1"); again != base {
		t.Fatalf("the same inputs gave two groups: %s, %s", base, again)
	}
	for _, c := range []struct {
		name string
		id   string
	}{
		{"another Target", groupID(gcp, snp, ledgerB, hint, "1")},
		{"another launch", groupID(aws, snp, ledgerA, hint, "1")},
		{"another platform", groupID(gcp, gateway.Platform("TDX"), ledgerA, hint, "1")},
		{"another hint", groupID(gcp, snp, ledgerA, "batch.workload.tacra.example", "1")},
		{"another policy version", groupID(gcp, snp, ledgerA, hint, "2")},
	} {
		if c.id == base {
			t.Errorf("%s gave the same group", c.name)
		}
	}
}
