package sevsnp

// Experiment, not for submission: Veraison main (b1cd67e) with the single change
// DisableCertFetching: false, as proposed on PR #490, against the AWS VLEK report
// with the certificate table as the AWS host supplies it (the VLEK alone).

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"

	"errors"
	"github.com/google/go-sev-guest/abi"
	sevsnp "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/ratsd/tokens"
	"github.com/veraison/services/vts/appraisal"
)

//go:embed test/evidence/sevsnp-aws-vlek-tsm-report.cbor
var expAWS []byte

const expAWSReportData = "6131f96c32e9cb962b4c0c7507c9c7fe36ec4c527a73a7809c786251dbe5809fa9b84cd8aec306f3d151a78acb323d8e753e085aa6f829d636792a1ae43fba44"

func expHostTable(t *testing.T, table []byte) []byte {
	t.Helper()
	guid := table[:16]
	off := binary.LittleEndian.Uint32(table[16:])
	n := binary.LittleEndian.Uint32(table[20:])
	der := table[off : off+n]
	head := append([]byte{}, guid...)
	head = binary.LittleEndian.AppendUint32(head, 48)
	head = binary.LittleEndian.AppendUint32(head, uint32(len(der)))
	head = append(head, make([]byte, 24)...)
	return append(head, der...)
}

func expTrustAnchor(t *testing.T) []*comid.KeyTriple {
	t.Helper()
	roots := trust.DefaultRootCerts["Milan"]
	arkPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: roots.ProductCerts.Ark.Raw})
	ta, err := comid.NewPKIXBase64Cert(string(arkPEM))
	require.NoError(t, err)
	return []*comid.KeyTriple{{VerifKeys: comid.CryptoKeys{ta}}}
}

// E1: the flag alone. Where does main fail with the AWS host's table?
func Test_E1_FetchingFlagAlone(t *testing.T) {
	var tsm tokens.TSMReport
	require.NoError(t, tsm.FromCBOR(expAWS))
	tsm.AuxBlob = expHostTable(t, tsm.AuxBlob)
	hostToken, err := tsm.ToCBOR()
	require.NoError(t, err)

	reportData, err := hex.DecodeString(expAWSReportData)
	require.NoError(t, err)

	ev := &appraisal.Evidence{Data: hostToken, MediaType: EvidenceMediaTypeTSMCbor, Nonce: reportData}
	s := NewImplementation()

	ids, err := s.GetTrustAnchorIDs(ev)
	t.Logf("E1 GetTrustAnchorIDs: ids=%v err=%v", ids, err)

	err = s.ValidateEvidenceIntegrity(ev, expTrustAnchor(t), nil)
	t.Logf("E1 ValidateEvidenceIntegrity: err=%v (ErrNoARK=%v)", err, errors.Is(err, ErrNoARK))
}

type loggingGetter struct {
	t    *testing.T
	urls []string
	g    trust.HTTPSGetter
}

func (l *loggingGetter) Get(url string) ([]byte, error) {
	l.urls = append(l.urls, url)
	body, err := l.g.Get(url)
	l.t.Logf("KDS GET %s -> %d bytes, err=%v", url, len(body), err)
	return body, err
}

// E2: what Raman's route needs from go-sev-guest: the VLEK alone, fetching on. Which URLs, what result.
func Test_E2_FetchingWithVLEKAlone(t *testing.T) {
	var tsm tokens.TSMReport
	require.NoError(t, tsm.FromCBOR(expAWS))
	table := expHostTable(t, tsm.AuxBlob)

	var certTable abi.CertTable
	require.NoError(t, certTable.Unmarshal(table))
	chain := certTable.Proto()
	require.NotEmpty(t, chain.GetVlekCert())
	require.Empty(t, chain.GetAskCert())
	require.Empty(t, chain.GetArkCert())

	// AWS writes the table as DER (PR #488); main's readCert is PEM-only, so take the entry as it is
	vlek := chain.GetVlekCert()
	t.Logf("E2 VLEK entry: %d bytes, PEM? %v", len(vlek), bytes.HasPrefix(vlek, []byte("-----BEGIN")))

	report, err := abi.ReportToProto(tsm.OutBlob)
	require.NoError(t, err)

	trust.ClearProductCertCache()
	lg := &loggingGetter{t: t, g: trust.DefaultHTTPSGetter()}
	att := sevsnp.Attestation{Report: report, CertificateChain: &sevsnp.CertificateChain{VlekCert: vlek}}
	err = verify.SnpAttestationContext(context.Background(), &att, &verify.Options{
		Getter: lg, Now: time.Now(), DisableCertFetching: false, CheckRevocations: false,
	})
	t.Logf("E2 verify.SnpAttestation (VLEK alone, fetching on): err=%v; KDS calls=%d", err, len(lg.urls))
	t.Logf("E2 chain after fill: ASK/ASVK=%d bytes ARK=%d bytes", len(att.CertificateChain.GetAskCert()), len(att.CertificateChain.GetArkCert()))

	// second verification in the same process: served from go-sev-guest's product cache?
	lg2 := &loggingGetter{t: t, g: trust.DefaultHTTPSGetter()}
	att2 := sevsnp.Attestation{Report: report, CertificateChain: &sevsnp.CertificateChain{VlekCert: vlek}}
	err = verify.SnpAttestationContext(context.Background(), &att2, &verify.Options{
		Getter: lg2, Now: time.Now(), DisableCertFetching: false, CheckRevocations: false,
	})
	t.Logf("E2 second run: err=%v; KDS calls=%d", err, len(lg2.urls))
}

//go:embed test/evidence/sevsnp-gcp-tsm-report.cbor
var expGCP []byte

// leafOnly returns the report and the chain holding the report's signing certificate alone, as the host's table
// would carry it when the host supplies no ASK/ASVK and ARK.
func expLeafOnly(t *testing.T, token []byte) (*sevsnp.Attestation, string) {
	t.Helper()
	var tsm tokens.TSMReport
	require.NoError(t, tsm.FromCBOR(token))
	var certTable abi.CertTable
	require.NoError(t, certTable.Unmarshal(tsm.AuxBlob))
	chain := certTable.Proto()
	report, err := abi.ReportToProto(tsm.OutBlob)
	require.NoError(t, err)
	info, err := abi.ParseSignerInfo(report.GetSignerInfo())
	require.NoError(t, err)
	switch info.SigningKey {
	case abi.VcekReportSigner:
		require.NotEmpty(t, chain.GetVcekCert())
		return &sevsnp.Attestation{Report: report, CertificateChain: &sevsnp.CertificateChain{VcekCert: chain.GetVcekCert()}}, "VCEK"
	case abi.VlekReportSigner:
		require.NotEmpty(t, chain.GetVlekCert())
		return &sevsnp.Attestation{Report: report, CertificateChain: &sevsnp.CertificateChain{VlekCert: chain.GetVlekCert()}}, "VLEK"
	}
	t.Fatalf("unexpected signer %v", info.SigningKey)
	return nil, ""
}

func expVerifyFetching(t *testing.T, att *sevsnp.Attestation) (error, []string) {
	t.Helper()
	lg := &loggingGetter{t: t, g: trust.DefaultHTTPSGetter()}
	err := verify.SnpAttestationContext(context.Background(), att, &verify.Options{
		Getter: lg, Now: time.Now(), DisableCertFetching: false, CheckRevocations: false,
	})
	return err, lg.urls
}

// E3: go-sev-guest's product-chain cache is keyed by product line alone (trust.GetProductChainContext), while the
// KDS path differs by signer (vcek/v1 vs vlek/v1). One Verifier process, fetching on, Milan reports of both kinds
// whose hosts supply the leaf alone: does the second kind still verify?
func Test_E3_ProductChainCacheAcrossSigners(t *testing.T) {
	gcp, gcpKind := expLeafOnly(t, expGCP)
	aws, awsKind := expLeafOnly(t, expAWS)
	t.Logf("E3 fixtures: GCP report signed by %s, AWS report signed by %s", gcpKind, awsKind)

	for _, order := range []struct {
		name          string
		first, second *sevsnp.Attestation
		firstKind     string
		secondKind    string
	}{
		{"VCEK then VLEK", gcp, aws, gcpKind, awsKind},
		{"VLEK then VCEK", aws, gcp, awsKind, gcpKind},
	} {
		t.Run(order.name, func(t *testing.T) {
			trust.ClearProductCertCache()
			a := &sevsnp.Attestation{Report: order.first.Report, CertificateChain: &sevsnp.CertificateChain{
				VcekCert: order.first.CertificateChain.GetVcekCert(), VlekCert: order.first.CertificateChain.GetVlekCert()}}
			err, urls := expVerifyFetching(t, a)
			t.Logf("E3 %s: first (%s alone): err=%v urls=%v", order.name, order.firstKind, err, urls)
			b := &sevsnp.Attestation{Report: order.second.Report, CertificateChain: &sevsnp.CertificateChain{
				VcekCert: order.second.CertificateChain.GetVcekCert(), VlekCert: order.second.CertificateChain.GetVlekCert()}}
			err, urls = expVerifyFetching(t, b)
			t.Logf("E3 %s: second (%s alone, same process): err=%v urls=%v", order.name, order.secondKind, err, urls)
		})
	}

	// control: each kind alone in a fresh cache
	for _, c := range []struct {
		name string
		att  *sevsnp.Attestation
	}{{"VCEK alone, fresh cache", gcp}, {"VLEK alone, fresh cache", aws}} {
		t.Run(c.name, func(t *testing.T) {
			trust.ClearProductCertCache()
			a := &sevsnp.Attestation{Report: c.att.Report, CertificateChain: &sevsnp.CertificateChain{
				VcekCert: c.att.CertificateChain.GetVcekCert(), VlekCert: c.att.CertificateChain.GetVlekCert()}}
			err, urls := expVerifyFetching(t, a)
			t.Logf("E3 control %s: err=%v urls=%v", c.name, err, urls)
		})
	}
}
