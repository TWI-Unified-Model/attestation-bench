package ear

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/corim/comid"
)

// The environment class of the CoMID a Veraison verifier annotates for an SEV-SNP report (go-gen-ref, cmd/sevsnp):
// the chip for a VCEK-signed report, the cloud provider for a VLEK-signed one.
const (
	ClassByChip = "1.3.6.1.4.1.3704.3.1"
	ClassByCSP  = "1.3.6.1.4.1.3704.3.2"
)

// SNPClaims are the fields of an SEV-SNP report that a Veraison verifier annotates in its EAR: go-gen-ref's parser
// writes POLICY (MKey 2) and PLATFORM_INFO (7) as big-endian raw values, REPORTED_TCB (647) and COMMITTED_TCB (3329)
// as SVNs, CPUID family, model and stepping (648-650) for report version 3 and later, CHIP_ID (3328) when it is not
// zero, and, with the bench's patch to go-gen-ref, the mitigation vectors LAUNCH_MIT_VECTOR (4032) and
// CURRENT_MIT_VECTOR (4096) as big-endian raw values for report version 5 and later.
type SNPClaims struct {
	Class        string
	Policy       uint64
	PlatformInfo uint64
	ReportedTCB  uint64
	CommittedTCB uint64
	HasCPUID     bool
	Family       byte
	Model        byte
	Stepping     byte
	ChipID       []byte
	// The mitigations the firmware had verified at the guest's launch, and has verified now; HasMitVectors is false
	// for a report before version 5, or a verifier that does not annotate them.
	LaunchMitVector  uint64
	CurrentMitVector uint64
	HasMitVectors    bool
}

func snpClaims(raw json.RawMessage) (*SNPClaims, error) {
	var a struct {
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || len(a.Tags) == 0 {
		return nil, errors.New("ear: no annotated CoMID")
	}
	b, err := base64.StdEncoding.DecodeString(a.Tags[0])
	if err != nil {
		return nil, fmt.Errorf("ear: annotated CoMID: %w", err)
	}
	var t cbor.RawTag
	if cbor.Unmarshal(b, &t) == nil && t.Number == 506 {
		b = t.Content
		var wrapped []byte
		if cbor.Unmarshal(b, &wrapped) == nil {
			b = wrapped
		}
	}
	var c comid.Comid
	if err := c.FromCBOR(b); err != nil {
		return nil, fmt.Errorf("ear: annotated CoMID: %w", err)
	}
	if c.Triples.ReferenceValues == nil || len(c.Triples.ReferenceValues.Values) != 1 {
		return nil, errors.New("ear: annotated CoMID: expected one reference-value triple")
	}
	vt := c.Triples.ReferenceValues.Values[0]
	out := &SNPClaims{}
	if vt.Environment.Class != nil && vt.Environment.Class.ClassID != nil {
		out.Class = vt.Environment.Class.ClassID.String()
	}
	seen := map[uint64]bool{}
	for _, m := range vt.Measurements.Values {
		k, err := m.Key.GetKeyUint()
		if err != nil {
			continue
		}
		switch k {
		case 2, 7, 4032, 4096:
			v, err := rawUint(m, 8)
			if err != nil {
				return nil, fmt.Errorf("ear: MKey %d: %w", k, err)
			}
			switch k {
			case 2:
				out.Policy = v
			case 7:
				out.PlatformInfo = v
			case 4032:
				out.LaunchMitVector = v
			default:
				out.CurrentMitVector = v
			}
		case 647, 3329:
			v, err := svnUint(m)
			if err != nil {
				return nil, fmt.Errorf("ear: MKey %d: %w", k, err)
			}
			if k == 647 {
				out.ReportedTCB = v
			} else {
				out.CommittedTCB = v
			}
		case 648, 649, 650:
			v, err := rawUint(m, 1)
			if err != nil {
				return nil, fmt.Errorf("ear: MKey %d: %w", k, err)
			}
			switch k {
			case 648:
				out.Family = byte(v)
			case 649:
				out.Model = byte(v)
			default:
				out.Stepping = byte(v)
			}
		case 3328:
			if m.Val.RawValue == nil {
				return nil, errors.New("ear: MKey 3328: no raw value")
			}
			if out.ChipID, err = m.Val.RawValue.GetBytes(); err != nil {
				return nil, fmt.Errorf("ear: MKey 3328: %w", err)
			}
		default:
			continue
		}
		seen[k] = true
	}
	for _, k := range []uint64{2, 7, 647, 3329} {
		if !seen[k] {
			return nil, fmt.Errorf("ear: the annotated CoMID has no MKey %d", k)
		}
	}
	out.HasCPUID = seen[648] && seen[649]
	out.HasMitVectors = seen[4032] && seen[4096]
	return out, nil
}

// rawUint reads a big-endian raw value of exactly n octets.
func rawUint(m comid.Measurement, n int) (uint64, error) {
	if m.Val.RawValue == nil {
		return 0, errors.New("no raw value")
	}
	b, err := m.Val.RawValue.GetBytes()
	if err != nil {
		return 0, err
	}
	if len(b) != n {
		return 0, fmt.Errorf("raw value of %d octets, want %d", len(b), n)
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, nil
}

// svnUint reads an SVN measurement (a TCB_VERSION) as the 64-bit value.
func svnUint(m comid.Measurement) (uint64, error) {
	if m.Val.SVN == nil {
		return 0, errors.New("no SVN")
	}
	switch v := m.Val.SVN.Value.(type) {
	case *comid.TaggedSVN:
		return strconv.ParseUint(v.String(), 10, 64)
	case *comid.TaggedMinSVN:
		return strconv.ParseUint(v.String(), 10, 64)
	}
	return 0, fmt.Errorf("unsupported SVN type %T", m.Val.SVN.Value)
}
