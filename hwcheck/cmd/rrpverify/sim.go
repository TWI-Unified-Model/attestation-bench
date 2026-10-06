package main

// The bench's software stand-in TEE (platform.SimTEE; no isolation, no security) in the in-process suite: the same
// honest and changed-input checks as for TDX, against the stand-in's attestation key (-sim-key), and the launch
// measurement against the reference value (-sim-measurement).

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/tacra/platform"
)

const simReportDataRefusal = "report_data is not the binding value"

// simPassing is a case whose honest report verified, with the measurement it reported.
type simPassing struct {
	name        string
	measurement []byte
}

// verifySim checks a SimTEE token as the bench's sim-verifier does, with bv as the session nonce.
func verifySim(token, bv []byte, keys []*ecdsa.PublicKey) (*platform.SimReport, error) {
	outblob, err := platform.ReportFromTSMToken(token)
	if err != nil {
		return nil, err
	}
	r, err := platform.ParseSimReport(outblob, keys)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.ReportData, bv) {
		return nil, errors.New(simReportDataRefusal)
	}
	if r.Debug {
		return nil, errors.New("the instance is debuggable")
	}
	return r, nil
}

// simChecks runs, for one case, the honest check and one check per changed input: the Target, the RRP identifier,
// the CSR or CEKpub, the freshness element, and the attestation key (another key). A refusal counts only when the
// honest report passes and the refusal is the one the check tests.
func simChecks(name string, token, elem, otherElem []byte, rrp, otherRRP, target string, subject, flipped []byte,
	keys, otherKeys []*ecdsa.PublicKey) ([]result, *simPassing) {
	bv := func(e []byte, r, t string, subj []byte) []byte {
		v := platform.BindingValue(e, t, r, subj)
		return v[:]
	}
	var out []result
	var pass *simPassing
	honestPassed := false
	for _, c := range []struct {
		name, want, reason string
		bv                 []byte
		keys               []*ecdsa.PublicKey
	}{
		{"honest", "pass", "", bv(elem, rrp, target, subject), keys},
		{"other Target", "fail", simReportDataRefusal, bv(elem, rrp, "https://other.tacra.example", subject), keys},
		{"other RRP identifier", "fail", simReportDataRefusal, bv(elem, otherRRP, target, subject), keys},
		{"other CSR / CEKpub", "fail", simReportDataRefusal, bv(elem, rrp, target, flipped), keys},
		{"other freshness element", "fail", simReportDataRefusal, bv(otherElem, rrp, target, subject), keys},
		{"attestation key = another key", "fail", "not signed by a trusted attestation key", bv(elem, rrp, target, subject), otherKeys},
	} {
		t0 := time.Now()
		rep, err := verifySim(token, c.bv, c.keys)
		r := outcome(name, "sim-report", c.name, c.want, err, float64(time.Since(t0).Microseconds())/1000)
		if c.name == "honest" {
			honestPassed = err == nil
			if honestPassed {
				pass = &simPassing{name: name, measurement: rep.Measurement}
			}
		}
		switch {
		case c.reason != "" && !honestPassed:
			r.Got, r.OK = "inconclusive", false
			r.Comment = "the honest Evidence is refused too, so a refusal here proves nothing"
		case c.reason != "" && err != nil && !strings.Contains(err.Error(), c.reason):
			r.Got, r.OK = "refused for another reason", false
			r.Comment = "inconclusive: the refusal is not the one this check tests"
		}
		r.Comment = strings.TrimSpace(r.Comment + " verifier: platform.ParseSimReport (software stand-in, no security)")
		out = append(out, r)
	}
	return out, pass
}

// simAppraisal compares each passing case's measurement with the reference value: the reference must be affirming
// and a copy with one byte changed must not. With no reference given, the first passing case's measurement is the
// reference (trust on first use, stated in each result).
func simAppraisal(passed []simPassing, reference []byte) []result {
	if len(passed) == 0 {
		return nil
	}
	from := "the reference value given (-sim-measurement)"
	if len(reference) == 0 {
		reference, from = passed[0].measurement, "trust on first use: "+passed[0].name
	}
	bad := append([]byte(nil), reference...)
	bad[0] ^= 1
	var out []result
	for _, p := range passed {
		for _, rv := range []struct {
			name, want string
			ref        []byte
		}{{"appraise: reference measurement", "affirming", reference},
			{"appraise: measurement one byte different", "not affirming", bad}} {
			r := result{Case: p.name + " / sim-report", Check: rv.name, Want: rv.want, Got: "affirming",
				Comment: "reference from " + from}
			if !bytes.Equal(p.measurement, rv.ref) {
				r.Got, r.Error = "not affirming", "measurement "+hex.EncodeToString(p.measurement)+" is not the reference"
			}
			r.OK = r.Got == r.Want
			out = append(out, r)
		}
	}
	return out
}
