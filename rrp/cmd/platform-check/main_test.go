package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/gateway"
)

// The checks on real EARs the bench's Veraison issued on 7 October 2026 for Google Cloud's and AWS's SEV-SNP hosts
// (../../internal/ear/testdata), under the bench's rule as scripts/trustzone.py writes it for its pack: the shared rule
// (trust/platform-policy.json) with packs/tacra-bench's waivers.

// benchRule is that rule, with the pack's waivers or without them.
func benchRule(t *testing.T, withWaivers bool) *gateway.PlatformPolicy {
	t.Helper()
	raw, err := os.ReadFile("../../../trust/platform-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]json.RawMessage
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	var snp map[string]any
	if err := json.Unmarshal(file["sevsnp"], &snp); err != nil {
		t.Fatal(err)
	}
	if withWaivers {
		packRaw, err := os.ReadFile("../../../packs/tacra-bench/pack.json")
		if err != nil {
			t.Fatal(err)
		}
		var pack struct {
			Waivers struct {
				SEVSNP map[string]any `json:"sevsnp"`
			} `json:"platform_waivers"`
		}
		if err := json.Unmarshal(packRaw, &pack); err != nil {
			t.Fatal(err)
		}
		snp["mitigation_waivers"] = pack.Waivers.SEVSNP["mitigation_waivers"]
	}
	rule, _ := json.Marshal(map[string]any{"sevsnp": snp, "tdx": file["tdx"]})
	p, err := parseRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// realKept is a real EAR and the binding value it answers, with the key that signed it.
func realKept(t *testing.T, platform string) (*ecdsa.PublicKey, []kept) {
	t.Helper()
	jwk, err := os.ReadFile("../../internal/ear/testdata/veraison-ear-key-20261007.jwk")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ear.KeyFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := os.ReadFile("../../internal/ear/testdata/ear-" + platform + "-sevsnp-v5.jws")
	if err != nil {
		t.Fatal(err)
	}
	bvHex, err := os.ReadFile("../../internal/ear/testdata/binding-value-" + platform + "-v5.hex")
	if err != nil {
		t.Fatal(err)
	}
	bv, err := hex.DecodeString(strings.TrimSpace(string(bvHex)))
	if err != nil {
		t.Fatal(err)
	}
	return key, []kept{{"enroll-present-nonce", strings.TrimSpace(string(jws)), bv}}
}

func TestChecksOnRealEARs(t *testing.T) {
	bench := benchRule(t, true)
	for _, platform := range []string{"gcp", "aws"} {
		key, items := realKept(t, platform)
		results := checkAll(key, items, "SEVSNP", bench)
		// the bench's rule, a bank's, and one floor raised for each Milan TCB component (bl, snp, ucode)
		if len(results) != 5 {
			t.Fatalf("%s: %d checks, want 5: %+v", platform, len(results), results)
		}
		for _, r := range results {
			if !r.OK {
				t.Errorf("%s: %s: want %s, got %s: %s", platform, r.Check, r.Want, r.Got, r.Error)
			}
		}
		if !strings.Contains(results[0].Comment, "admitted without bit 4, AMD-SB-3034") {
			t.Errorf("%s: the bench's rule admitted without naming its waiver: %q", platform, results[0].Comment)
		}
		if !strings.Contains(results[1].Error, "mitigation bit 4 (AMD-SB-3034") {
			t.Errorf("%s: a bank's refusal does not name bit 4: %q", platform, results[1].Error)
		}
	}
	// controls: without the pack's waiver the bench's rule refuses, and the check says so; an EAR answering another
	// binding value does not verify, and no rule is applied to it
	key, items := realKept(t, "gcp")
	if r := checkAll(key, items, "SEVSNP", benchRule(t, false)); r[0].OK || r[0].Got != "fail" {
		t.Errorf("the bench's rule without its waiver: %+v", r[0])
	}
	items[0].bv[0] ^= 1
	if r := checkAll(key, items, "SEVSNP", bench); len(r) != 1 || r[0].Check != "the EAR verifies" || r[0].OK {
		t.Errorf("an EAR checked against another binding value: %+v", r)
	}
}
