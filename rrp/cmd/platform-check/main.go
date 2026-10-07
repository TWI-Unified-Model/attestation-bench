// Command platform-check applies the RRPs' platform rule (rrp/internal/gateway) to the Attestation Results an attack
// run kept: the honest EARs the deployed verifier issued for real hardware (rrpverify service -save-ears), each
// verified again under the key the run kept with them, against the binding value it answers, as of its issue time.
// Three rules, each a check in rrpverify's form:
//   - the bench's own, as the running RRPs apply it, its named waivers included: it must admit them;
//   - a bank's, the same rule without waivers (the Demo Bank's pack names none): it must refuse Evidence the bench
//     admitted under a waiver, for a mitigation bit, and admit any other;
//   - the bench's rule one step stricter than the host: on SEV-SNP each TCB floor one above the host's value, on TDX
//     the TD's own ATTRIBUTES refused. It must refuse them, for that reason.
//
// verdict.py judges the file with the run's other checks. The run keeps the rule as the RRPs had it
// (platform-rule.json), so its files alone give the same checks again.
//
//	platform-check -ears RUN/ears -rule RUN/platform-rule.json -submod SEVSNP|TDX -out RUN/rrpverify-platform.json
package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/tacra/rrp/internal/ear"
	"github.com/TWI-Unified-Model/tacra/rrp/internal/gateway"
)

// result is one check, in rrpverify's form (hwcheck/cmd/rrpverify).
type result struct {
	Case    string `json:"case"`
	Check   string `json:"check"`
	Want    string `json:"want"`
	Got     string `json:"got"` // pass, fail (for the reason expected), or other (refused for another reason)
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// kept is one honest EAR a run kept, with the binding value it answers.
type kept struct {
	name, jws string
	bv        []byte
}

func main() {
	earsDir := flag.String("ears", "", "the run's ears/ directory: <case>.ear.jws, <case>.bv.hex, verifier-key.jwk")
	rulePath := flag.String("rule", "", "the platform rule the running RRPs apply, as the run keeps it (platform-rule.json)")
	submod := flag.String("submod", "SEVSNP", "the EAR submodule: SEVSNP or TDX")
	out := flag.String("out", "", "where to write the checks (rrpverify-platform.json)")
	flag.Parse()
	if *earsDir == "" || *rulePath == "" || *out == "" {
		fail(errors.New("-ears, -rule and -out are required"))
	}
	raw, err := os.ReadFile(*rulePath)
	if err != nil {
		fail(err)
	}
	bench, err := parseRule(raw)
	if err != nil {
		fail(fmt.Errorf("%s: %w", *rulePath, err))
	}
	key, items, err := readKept(*earsDir)
	if err != nil {
		fail(err)
	}
	results := checkAll(key, items, *submod, bench)
	b, _ := json.MarshalIndent(map[string]any{"rule": filepath.Base(*rulePath), "submod": *submod, "results": results}, "", " ")
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		fail(err)
	}
	bad := 0
	for _, r := range results {
		mark := "ok "
		if !r.OK {
			mark, bad = "BAD", bad+1
		}
		note := r.Error
		if note == "" {
			note = r.Comment
		}
		fmt.Printf("%s %-26s %-40s want %-4s got %-5s %s\n", mark, r.Case, r.Check, r.Want, r.Got, note)
	}
	fmt.Printf("%d checks, %d not as expected; written %s\n", len(results), bad, *out)
}

// parseRule decodes a platform rule as the gateways do, refusing a field they do not know.
func parseRule(raw []byte) (*gateway.PlatformPolicy, error) {
	if len(raw) == 0 {
		return nil, errors.New("no platform rule")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var p gateway.PlatformPolicy
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("platform rule: %w", err)
	}
	if p.SEVSNP == nil || p.TDX == nil {
		return nil, errors.New("the platform rule has no sevsnp or no tdx section")
	}
	return &p, p.Validate()
}

// readKept reads the EARs a run kept and the verifier's key it kept with them.
func readKept(dir string) (*ecdsa.PublicKey, []kept, error) {
	jwk, err := os.ReadFile(filepath.Join(dir, "verifier-key.jwk"))
	if err != nil {
		return nil, nil, err
	}
	key, err := ear.KeyFromJWK(jwk)
	if err != nil {
		return nil, nil, fmt.Errorf("verifier-key.jwk: %w", err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.ear.jws"))
	sort.Strings(files)
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("no EAR in %s", dir)
	}
	var items []kept
	for _, f := range files {
		jws, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, err
		}
		bvHex, err := os.ReadFile(strings.TrimSuffix(f, ".ear.jws") + ".bv.hex")
		if err != nil {
			return nil, nil, err
		}
		bv, err := hex.DecodeString(strings.TrimSpace(string(bvHex)))
		if err != nil {
			return nil, nil, err
		}
		items = append(items, kept{strings.TrimSuffix(filepath.Base(f), ".ear.jws"), strings.TrimSpace(string(jws)), bv})
	}
	return key, items, nil
}

// verify checks a kept EAR under the verifier's key against the binding value it answers, as of its issue time: the
// check the RRP made when it received it.
func verify(key *ecdsa.PublicKey, k kept, submod string) (*ear.Result, error) {
	parts := strings.Split(k.jws, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims struct {
		IAT int64 `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	v := &ear.Verifier{Keys: []ear.TrustedKey{{Key: key, Submods: []string{submod}}}, MaxAge: 2 * time.Minute,
		Skew: 5 * time.Second, Now: func() time.Time { return time.Unix(claims.IAT, 0) }}
	return v.Verify(k.jws, k.bv)
}

// checkAll applies the three rules to each kept EAR.
func checkAll(key *ecdsa.PublicKey, items []kept, submod string, bench *gateway.PlatformPolicy) []result {
	var out []result
	for _, k := range items {
		res, err := verify(key, k, submod)
		if err != nil {
			out = append(out, result{Case: k.name, Check: "the EAR verifies", Want: "pass", Got: "fail", Error: err.Error()})
			continue
		}
		out = append(out, checks(k.name, res, bench)...)
	}
	return out
}

// judged is a check's result: pass when the rule admitted, fail when it refused for the reason expected (reason, a part
// of the refusal), other when it refused for another.
func judged(name, check, want, reason string, waived []string, err error) result {
	r := result{Case: name, Check: check, Want: want, Got: "pass"}
	if err != nil {
		r.Got, r.Error = "fail", err.Error()
		if reason != "" && !strings.Contains(err.Error(), reason) {
			r.Got = "other"
		}
	}
	if len(waived) > 0 {
		r.Comment = "admitted under the rule's waiver: " + strings.Join(waived, "; ")
	}
	r.OK = r.Got == r.Want
	return r
}

// checks applies the three rules to one EAR.
func checks(name string, res *ear.Result, bench *gateway.PlatformPolicy) []result {
	waived, err := bench.Check(res)
	out := []result{judged(name, "the bench's rule", "pass", "", waived, err)}

	want := "pass"
	if len(waived) > 0 {
		want = "fail" // the mitigation bit the bench waived, which a bank does not
	}
	w, err := withoutWaivers(bench).Check(res)
	out = append(out, judged(name, "a bank's rule, no waiver", want, "mitigation bit", w, err))

	switch res.Submod {
	case "SEVSNP":
		product, _ := gateway.ProductOf(res.SNP)
		floor := bench.SEVSNP.TCBFloors[product]
		comps := make([]string, 0, len(floor))
		for c := range floor {
			comps = append(comps, c)
		}
		sort.Strings(comps)
		for _, c := range comps {
			host, _ := gateway.TCBComponent(product, c, res.SNP.ReportedTCB)
			q := *bench
			s := *bench.SEVSNP
			s.TCBFloors = copyFloors(bench.SEVSNP.TCBFloors)
			s.TCBFloors[product][c] = host + 1
			q.SEVSNP = &s
			_, err := q.Check(res)
			out = append(out, judged(name, fmt.Sprintf("a %s %s floor one above the host's", product, c), "fail",
				fmt.Sprintf("REPORTED_TCB %s %d is below the floor %d", c, host, host+1), nil, err))
		}
	case "TDX":
		attrs, err := strconv.ParseUint(res.TDX["td_attributes"], 16, 64)
		if err != nil || attrs&^0xF == 0 {
			out = append(out, result{Case: name, Check: "the TD's ATTRIBUTES refused", Want: "fail", Got: "other",
				Error: "the TD has no ATTRIBUTES bit outside the debug group to refuse"})
			break
		}
		q := *bench
		t := *bench.TDX
		t.AttributesRefused = fmt.Sprintf("%#x", attrs&^0xF)
		q.TDX = &t
		_, err = q.Check(res)
		out = append(out, judged(name, "the TD's ATTRIBUTES refused", "fail", "are refused", nil, err))
	}
	return out
}

// withoutWaivers is a copy of the rule with no waiver: the rule a bank applies.
func withoutWaivers(p *gateway.PlatformPolicy) *gateway.PlatformPolicy {
	q := *p
	if p.SEVSNP != nil {
		s := *p.SEVSNP
		s.MitigationWaivers = nil
		q.SEVSNP = &s
	}
	return &q
}

func copyFloors(f map[string]map[string]int) map[string]map[string]int {
	out := make(map[string]map[string]int, len(f))
	for p, m := range f {
		out[p] = make(map[string]int, len(m))
		for c, v := range m {
			out[p][c] = v
		}
	}
	return out
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "platform-check:", err)
	os.Exit(1)
}
