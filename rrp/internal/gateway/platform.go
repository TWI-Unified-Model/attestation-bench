package gateway

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
)

// PlatformPolicy is this RRP's rule on what verified, affirming Attestation Results report about the platform: which
// machine, which product line, which TCB, which guest policy. "Affirming" says the Evidence matched the verifier's
// reference values; it does not say the platform is one this RRP accepts. The rules are those of the reference
// Verifier of tacra-est (impl/verifier.py, impl/policy/bank-default.json).
type PlatformPolicy struct {
	SEVSNP *SNPPolicy `json:"sevsnp,omitempty"`
	TDX    *TDXPolicy `json:"tdx,omitempty"`
}

// SNPPolicy is the rule for SEV-SNP.
type SNPPolicy struct {
	// A machine must be named: a VLEK-signed report (the provider's key) or one without CHIP_ID is refused.
	RequireMachineIdentity bool `json:"require_machine_identity"`
	// The machines admitted, by CHIP_ID (hex); empty admits any named machine.
	AllowedChipIDs []string `json:"allowed_chip_ids,omitempty"`
	// The product lines admitted, named from the report's CPUID family and extended model (AMD 57230 Rev. 1.05,
	// Table 4). The CPUID bytes are as trustworthy as the chain the verifier checked: the verifier must hold no root
	// of a product line refused here, since a line whose keys are compromised can sign any CPUID (tacra-est formal
	// p0-platform/p0-n12-product-b).
	AllowedProducts []string `json:"allowed_products"`
	// The minimum of each TCB component, per product line; a product line without a floor is refused.
	TCBFloors map[string]map[string]int `json:"tcb_floors"`
	// Apply the floors to COMMITTED_TCB as well as REPORTED_TCB.
	CheckCommittedTCB bool `json:"check_committed_tcb"`
	// "forbid", or "allow-with-microcode-floor": SMT only when the product's floor names a microcode level, met.
	SMT string `json:"smt"`
	// Per product line, the mitigation bits that must be set in both mitigation vectors, the one verified at the
	// guest's launch and the one verified now (report version 5; AMD names a fix's bit in its bulletin), each bit
	// with the reason the refusal gives, e.g. {"Milan": {"4": "AMD-SB-3034"}}. A report without the vectors is refused
	// when its product line requires a bit.
	RequiredMitigationBits map[string]map[string]string `json:"required_mitigation_bits,omitempty"`
	// Per product line, the PLATFORM_INFO bits that must be set, each with its reason, e.g.
	// {"Milan": {"5": "AMD-SB-3015: ALIAS_CHECK_COMPLETE"}}.
	RequiredPlatformInfoBits map[string]map[string]string `json:"required_platform_info_bits,omitempty"`
}

// TDXPolicy is the rule for TDX, on the TD ATTRIBUTES the bench's TDX verifier annotates.
type TDXPolicy struct {
	// ATTRIBUTES bits refused besides the TUD group (bits 3:0), which is always refused; a hex mask.
	AttributesRefused string `json:"td_attributes_refused"`
}

// snpProducts: AMD 57230 Rev. 1.05, Table 4 (family, extended model -> product name).
var snpProducts = map[[2]byte]string{{0x19, 0x0}: "Milan", {0x19, 0x1}: "Genoa", {0x19, 0xA}: "Siena",
	{0x1A, 0x0}: "Turin", {0x1A, 0x1}: "Turin", {0x1A, 0x5}: "Venice"}

// tcbLayouts: the byte of each component in the 64-bit TCB_VERSION (AMD 56860 Rev. 1.59, Table 5 for Milan and
// Genoa, Table 4 for Turin). Venice is not decoded, so it has no floor and is refused.
var tcbLayouts = map[string]map[string]uint{
	"Milan": {"bl": 0, "tee": 1, "snp": 6, "ucode": 7}, "Genoa": {"bl": 0, "tee": 1, "snp": 6, "ucode": 7},
	"Siena": {"bl": 0, "tee": 1, "snp": 6, "ucode": 7},
	"Turin": {"fmc": 0, "bl": 1, "tee": 2, "snp": 3, "ucode": 7},
}

// Validate checks the policy.
func (p *PlatformPolicy) Validate() error {
	if s := p.SEVSNP; s != nil {
		if s.SMT != "forbid" && s.SMT != "allow-with-microcode-floor" {
			return fmt.Errorf("platform.sevsnp.smt %q: forbid or allow-with-microcode-floor", s.SMT)
		}
		for product, floor := range s.TCBFloors {
			layout, ok := tcbLayouts[product]
			if !ok {
				return fmt.Errorf("platform.sevsnp.tcb_floors: no TCB layout for %q", product)
			}
			for comp, v := range floor {
				if _, ok := layout[comp]; !ok || v < 0 || v > 255 {
					return fmt.Errorf("platform.sevsnp.tcb_floors[%s]: %s=%d", product, comp, v)
				}
			}
		}
		for name, m := range map[string]map[string]map[string]string{"required_mitigation_bits": s.RequiredMitigationBits,
			"required_platform_info_bits": s.RequiredPlatformInfoBits} {
			for product, bits := range m {
				if _, ok := tcbLayouts[product]; !ok {
					return fmt.Errorf("platform.sevsnp.%s: unknown product line %q", name, product)
				}
				if _, err := bitsOf(bits); err != nil {
					return fmt.Errorf("platform.sevsnp.%s[%s]: %w", name, product, err)
				}
			}
		}
		for _, c := range s.AllowedChipIDs {
			if b, err := hex.DecodeString(c); err != nil || len(b) != 64 {
				return fmt.Errorf("platform.sevsnp.allowed_chip_ids: %q is not 64 octets of hex", c)
			}
		}
	}
	if t := p.TDX; t != nil {
		if _, err := parseMask(t.AttributesRefused); err != nil {
			return err
		}
	}
	return nil
}

// bitsOf returns the bit numbers of a map keyed by them ("0" to "63"), in ascending order.
func bitsOf(m map[string]string) ([]int, error) {
	bits := make([]int, 0, len(m))
	for k := range m {
		b, err := strconv.Atoi(k)
		if err != nil || b < 0 || b > 63 || strconv.Itoa(b) != k {
			return nil, fmt.Errorf("bit %q: a number from 0 to 63", k)
		}
		bits = append(bits, b)
	}
	slices.Sort(bits)
	return bits, nil
}

func parseMask(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	m, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("td_attributes_refused %q: %w", s, err)
	}
	return m, nil
}

// ErrPlatform is wrapped by every refusal of the platform policy.
var ErrPlatform = errors.New("the platform is not one this RRP accepts")

// Check applies the policy to verified Attestation Results.
func (p *PlatformPolicy) Check(res *ear.Result) error {
	switch res.Submod {
	case "SEVSNP":
		if p.SEVSNP == nil {
			return nil
		}
		if res.SNP == nil {
			return fmt.Errorf("%w: no SEV-SNP claims in the Attestation Results: %v", ErrPlatform, res.SNPErr)
		}
		return p.SEVSNP.check(res.SNP)
	case "TDX":
		if p.TDX == nil {
			return nil
		}
		return p.TDX.check(res.TDX)
	case "SIM":
		// the software stand-in has no platform to judge; whether it is accepted at all is allow_simulated_tee
		return nil
	}
	// a submodule this policy has no rule for is refused, not passed
	return fmt.Errorf("%w: no platform rule for submodule %q", ErrPlatform, res.Submod)
}

func (s *SNPPolicy) check(c *ear.SNPClaims) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrPlatform}, a...)...)
	}
	// The guest policy (AMD 56860 Table 12)
	if c.Policy>>19&1 == 1 {
		return fail("POLICY.DEBUG is set")
	}
	if c.Policy>>18&1 == 1 {
		return fail("POLICY.MIGRATE_MA is set")
	}
	if c.Policy>>17&1 != 1 || c.Policy>>26 != 0 {
		return fail("POLICY %#x: bit 17 must be one and bits 63:26 zero", c.Policy)
	}
	// The machine
	if s.RequireMachineIdentity && (c.Class != ear.ClassByChip || len(c.ChipID) == 0) {
		return fail("the report names no machine (class %s)", c.Class)
	}
	if len(s.AllowedChipIDs) > 0 && !slices.ContainsFunc(s.AllowedChipIDs, func(h string) bool {
		b, _ := hex.DecodeString(h)
		return len(c.ChipID) > 0 && bytes.Equal(b, c.ChipID)
	}) {
		return fail("CHIP_ID %x… is not a listed machine", c.ChipID[:min(8, len(c.ChipID))])
	}
	// The product line
	if !c.HasCPUID {
		return fail("the report carries no CPUID (report version below 3), so its product line is unknown")
	}
	product, ok := snpProducts[[2]byte{c.Family, c.Model >> 4}]
	if !ok || !slices.Contains(s.AllowedProducts, product) {
		return fail("product line %q (CPUID family %#x, model %#x) is not admitted", product, c.Family, c.Model)
	}
	// The TCB
	floor, ok := s.TCBFloors[product]
	if !ok {
		return fail("no TCB floor is configured for %s", product)
	}
	layout := tcbLayouts[product]
	component := func(tcb uint64, name string) int { return int(tcb >> (8 * layout[name]) & 0xFF) }
	for name, min := range floor {
		if component(c.ReportedTCB, name) < min {
			return fail("REPORTED_TCB %s %d is below the floor %d", name, component(c.ReportedTCB, name), min)
		}
		if s.CheckCommittedTCB && component(c.CommittedTCB, name) < min {
			return fail("COMMITTED_TCB %s %d is below the floor %d", name, component(c.CommittedTCB, name), min)
		}
	}
	// The mitigations AMD attests by a bit of the mitigation vectors: verified at launch and now
	if required := s.RequiredMitigationBits[product]; len(required) > 0 {
		bits, _ := bitsOf(required)
		if !c.HasMitVectors {
			return fail("the report carries no mitigation vector (version below 5), and %s requires mitigation bits %v",
				product, bits)
		}
		for _, b := range bits {
			if c.LaunchMitVector>>b&1 == 0 {
				return fail("mitigation bit %d (%s) is not set in LAUNCH_MIT_VECTOR %#x", b, required[strconv.Itoa(b)],
					c.LaunchMitVector)
			}
			if c.CurrentMitVector>>b&1 == 0 {
				return fail("mitigation bit %d (%s) is not set in CURRENT_MIT_VECTOR %#x", b, required[strconv.Itoa(b)],
					c.CurrentMitVector)
			}
		}
	}
	if required := s.RequiredPlatformInfoBits[product]; len(required) > 0 {
		bits, _ := bitsOf(required)
		for _, b := range bits {
			if c.PlatformInfo>>b&1 == 0 {
				return fail("PLATFORM_INFO bit %d (%s) is not set (%#x)", b, required[strconv.Itoa(b)], c.PlatformInfo)
			}
		}
	}
	// SMT (PLATFORM_INFO.SMT_EN, AMD 56860 Table 28)
	if c.PlatformInfo&1 == 1 {
		if s.SMT == "forbid" {
			return fail("SMT is enabled on the platform")
		}
		if u, ok := floor["ucode"]; !ok || component(c.ReportedTCB, "ucode") < u {
			return fail("SMT is enabled and no microcode floor is met")
		}
	}
	return nil
}

func (t *TDXPolicy) check(ann map[string]string) error {
	raw, ok := ann["td_attributes"]
	if !ok {
		return fmt.Errorf("%w: the TDX verifier annotated no TD ATTRIBUTES", ErrPlatform)
	}
	attrs, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		return fmt.Errorf("%w: TD ATTRIBUTES %q", ErrPlatform, raw)
	}
	mask, _ := parseMask(t.AttributesRefused)
	if attrs&0xF != 0 {
		return fmt.Errorf("%w: the TD is under debug (ATTRIBUTES %016x)", ErrPlatform, attrs)
	}
	if bad := attrs & mask; bad != 0 {
		return fmt.Errorf("%w: TD ATTRIBUTES bits %x are refused", ErrPlatform, bad)
	}
	return nil
}
