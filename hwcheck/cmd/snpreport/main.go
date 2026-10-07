// Command snpreport prints the launch measurement and the platform fields of the SEV-SNP attestation reports a hardware
// run kept, as go-sev-guest parses them: the report's version, POLICY, MEASUREMENT, PLATFORM_INFO, the reported,
// committed and launch TCBs, the CPUID, whether a CHIP_ID is present, and the launch and current mitigation vectors
// with the bits each sets. It reads
// every <step>/evidence.tsm.cbor of each run directory given (the TSM reports hwrun wrote); identical reports are
// printed once, with their count.
//
//	go run ./cmd/snpreport evidence/20261007T050654Z-gcp-sev-snp evidence/20261007T051142Z-aws-sev-snp
//
// It reads the reports themselves, all the fields the Attestation Results carry and a few more, for runs made before
// the results carried the mitigation vectors (docs/limits.md, "A TCB floor is not every mitigation").
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-sev-guest/abi"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: snpreport RUN_DIR...")
		os.Exit(2)
	}
	for _, dir := range os.Args[1:] {
		lines, n, err := runReports(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "snpreport: %s: %v\n", dir, err)
			os.Exit(1)
		}
		fmt.Printf("%s: %d report(s)\n", filepath.Base(filepath.Clean(dir)), n)
		for _, l := range lines {
			fmt.Printf("  %d x %s\n", l.count, l.text)
		}
	}
}

type line struct {
	text  string
	count int
}

// runReports reads every TSM report of a run directory and returns its distinct descriptions, in order of first
// appearance, with their counts, and the number of reports read.
func runReports(dir string) ([]line, int, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*", "evidence.tsm.cbor"))
	if err != nil {
		return nil, 0, err
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("no */evidence.tsm.cbor: not the directory of an SEV-SNP hardware run")
	}
	sort.Strings(files)
	var out []line
	index := map[string]int{}
	for _, f := range files {
		r, err := readReport(f)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", f, err)
		}
		d := describe(r)
		if i, ok := index[d]; ok {
			out[i].count++
			continue
		}
		index[d] = len(out)
		out = append(out, line{text: d, count: 1})
	}
	return out, len(files), nil
}

// readReport parses the attestation report in a TSM report as hwrun writes it: a CBOR map whose provider names the
// TEE (configfs-tsm) and whose outblob is the report.
func readReport(path string) (*pb.Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tsm struct {
		Provider string `cbor:"provider"`
		Outblob  []byte `cbor:"outblob"`
	}
	if err := cbor.Unmarshal(b, &tsm); err != nil {
		return nil, err
	}
	if tsm.Provider != "sev_guest" {
		return nil, fmt.Errorf("a report of provider %q, not sev_guest", tsm.Provider)
	}
	return abi.ReportToProto(tsm.Outblob)
}

func describe(r *pb.Report) string {
	chip := "CHIP_ID zero (a VLEK-signed report names no chip)"
	for _, b := range r.GetChipId() {
		if b != 0 {
			chip = "CHIP_ID present"
			break
		}
	}
	family, model := r.GetCpuid1EaxFms()>>8&0xF+r.GetCpuid1EaxFms()>>20&0xFF, r.GetCpuid1EaxFms()>>4&0xF|r.GetCpuid1EaxFms()>>12&0xF0
	return strings.Join([]string{
		fmt.Sprintf("version %d", r.GetVersion()),
		fmt.Sprintf("POLICY %#x", r.GetPolicy()),
		fmt.Sprintf("MEASUREMENT %x", r.GetMeasurement()),
		fmt.Sprintf("PLATFORM_INFO %#x", r.GetPlatformInfo()),
		"REPORTED_TCB " + tcb(r.GetReportedTcb(), family),
		"COMMITTED_TCB " + tcb(r.GetCommittedTcb(), family),
		"LAUNCH_TCB " + tcb(r.GetLaunchTcb(), family),
		fmt.Sprintf("CPUID family %#x model %#x", family, model),
		chip,
		"LAUNCH_MIT_VECTOR " + vector(r.GetLaunchMitVector()),
		"CURRENT_MIT_VECTOR " + vector(r.GetCurrentMitVector()),
	}, "; ")
}

// tcb names the components of a TCB_VERSION by the byte each takes in the product's layout (AMD 56860, Tables 4 and
// 5): EPYC Milan and Genoa (family 0x19) and Turin (family 0x1A) place them differently.
func tcb(v uint64, family uint32) string {
	b := func(i uint) uint64 { return v >> (8 * i) & 0xFF }
	if family == 0x1A {
		return fmt.Sprintf("0x%016x (fmc %d, bl %d, tee %d, snp %d, ucode %d)", v, b(0), b(1), b(2), b(3), b(7))
	}
	return fmt.Sprintf("0x%016x (bl %d, tee %d, snp %d, ucode %d)", v, b(0), b(1), b(6), b(7))
}

// vector prints a mitigation vector and the numbers of the bits it sets.
func vector(v uint64) string {
	var bits []string
	for i := 0; i < 64; i++ {
		if v>>i&1 == 1 {
			bits = append(bits, fmt.Sprint(i))
		}
	}
	if len(bits) == 0 {
		return fmt.Sprintf("%#x (no bit)", v)
	}
	return fmt.Sprintf("%#x (bits %s)", v, strings.Join(bits, ", "))
}
