// Reproduction for google/go-sev-guest: trust.GetProductChain's cache is keyed by product line alone.
// go test ./... -v   (reaches kdsintf.amd.com)
package repro

import (
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
)


type report struct {
	name           string
	signer         abi.ReportSigner
	intermediateCN string // the CN of the certificate that signs the leaf
	report, leaf   []byte
}

// The two reports and their leaf certificates (DER), base64: a VCEK-signed report from a Google Cloud
// n2d-standard-2 guest (AMD Milan, 7 October 2026) and a VLEK-signed report from an AWS EC2 c6a.large guest
// (AMD Milan, 6 October 2026), each with the certificate the host's table supplied for it.
const (
	gcpMilanVcekReport = `
BQAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAEAAAAAAAd3iUAAAAAAAAA
AAAAAAAAAAD4lrpCKCS7W7AgHaRZnJEk0kq4lsw87AoMOpzqyaUgj0y8fTqg+JXMxhz3gRxbLMYupBxwdxFQ5kwJy3ZoU5Uk
zNxc8BuiVSa9ZVA9lZMbeHtDhaMnfP5ESK3fnD6JSUiujPewmWIOPiJxfeL7XSb6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJ6tqFVsI1C47bF/gqB8pPrpp59cZJ6clfJpzeaprzcf//////////
////////////////////////////////BAAAAAAAHd4ZAQEAAAAAAAAAAAAAAAAAAAAAAAAAAADQh23oF256RAH4dh1UVc0Y
iTKYRt2+nuqKhKGeGPosO4/rVtyd97zZDTGGQgd7Ad6cr6NHoKYjuFJcmKOv0iseBAAAAAAAHd4BOgEAAToBAAQAAAAAAB3e
CwAAAAAAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeYGrDG/fMAWeycPidWA8/YXwWvcznjT92ulUq9r/tTn6YA3oxyIwuN9WvUsQ91k0
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtfrB2vcotTKc8l55qcmDuF8BRYj/hFjAHGF8pKY325U0Z7GfAK9NlWSfRLjmswKZ
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`
	gcpMilanVcekDER = `
MIIFQzCCAvegAwIBAgIBADBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFl
AwQCAgUAogMCATAwezEUMBIGA1UECwwLRW5naW5lZXJpbmcxCzAJBgNVBAYTAlVTMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEL
MAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2VkIE1pY3JvIERldmljZXMxEjAQBgNVBAMMCVNFVi1NaWxhbjAeFw0yNjA0
MDYxODE0MDRaFw0zMzA0MDYxODE0MDRaMHoxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwL
U2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZpY2VzMREwDwYDVQQDDAhTRVYt
VkNFSzB2MBAGByqGSM49AgEGBSuBBAAiA2IABAZ/K11pZxzV+6dbS+IP/DENeikffXOizovi2my7FCrflzJ3K7AhCZY8dkZj
25K52fkn3X83gvpfeyPq52dfzZCsKuboxEeTfmXM2+B4eiLBCkat7adFcuoWud3jRdi+a6OCARcwggETMBAGCSsGAQQBnHgB
AQQDAgEAMBcGCSsGAQQBnHgBAgQKFghNaWxhbi1CMDARBgorBgEEAZx4AQMBBAMCAQQwEQYKKwYBBAGceAEDAgQDAgEAMBEG
CisGAQQBnHgBAwQEAwIBADARBgorBgEEAZx4AQMFBAMCAQAwEQYKKwYBBAGceAEDBgQDAgEAMBEGCisGAQQBnHgBAwcEAwIB
ADARBgorBgEEAZx4AQMDBAMCAR0wEgYKKwYBBAGceAEDCAQEAgIA3jBNBgkrBgEEAZx4AQQEQNCHbegXbnpEAfh2HVRVzRiJ
MphG3b6e6oqEoZ4Y+iw7j+tW3J33vNkNMYZCB3sB3pyvo0egpiO4UlyYo6/SKx4wQQYJKoZIhvcNAQEKMDSgDzANBglghkgB
ZQMEAgIFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgIFAKIDAgEwA4ICAQCSq35AnhLzcIY3lRTRSXdm2FR1jaM27Pbr
aTa5swxxippySHCYOoc/llJyv6tnExBHeQNXIOi4Usziq17WWFPaUyUbPP4LW28pijiiJBdnKKZHKh7z/i6XUxdvVZUN9Ldh
YojKXeZt/t9LA7uHcLKyBVH/GoXr0qykHq1Bn9CxooxiANOjjTvMSTf2KcrATxfjAcVU63Hv5eTvpv2p/XTlEdg5d793jgq5
7aNNvEmTIg0YJ+pfihHdxhICkflYI/n8Rf1Ysjk+tQzMKd3Wle4kD31Az4Sq53CjtEdJ9AgXvPgtt36TBFnWVh8LaEvqwMvz
cZqOmNENQDwavpwrgmNtUu1a8UA5x9bmsSVgMGvpKSWG6OfQpRDTKT9rFCGyaLcC3bWYyat1Hbe7ebRSS+PGftYPkEaA0moC
U8cv/3oREnjgLf5p1KBtfDCOp1u0vXRA4R6ijVHifNOqp5mnaS3OYPLAoSoZ1MiODBNb5+xca8PaBn2QRmOXMlvS5QYsK0G1
7t3G/MBDnBCxON9AOWe7c2KX+828k9HS141t5Xl4JEBoQ8M9VPLYNOVsJyri3vWDwHl0R7ymkq0+dZ6HppEicZ6iaGtxmquK
W+A89Q0134slZUD2warMVG9+2Mz0IfkjpbPDJR5D7zhe7NLAqzZxVfaw3zIYM1av+OeKl9h4Mg==`
	awsMilanVlekReport = `
BQAAAAAAAAAAAAMCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAEAAAAAAAd4ScAAAAAAAAA
BAAAAAAAAABhMflsMunLlitMDHUHycf+NuxMUnpzp4CceGJR2+WAn6m4TNiuwwbz0VGnissyPY51Pghapvgp1jZ5KhrkP7pE
eonM6qugu93cT3dazKPvFdH5v4q8zcYRXPrX+46uET3z7gu1Dvo025xTrgZbHcdmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACfQkwmsX2h8rhvETLooZmc4ahjINoFeBJw6PdBoMRAVv//////////
////////////////////////////////BAAAAAAAHd4ZAQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAHd4BOgEAAToBAAQAAAAAAB3e
DwAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAICIpOpqUU1Ry6wYHOPIZJtZqOTaaW17T8Y1Tg5yRwO0yXeUUTiqqhZFu9bcvzoJM
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6JEAZjnggyTDt4J5BZaZp5HuJuFkBLtzqDbaoC8szfPzvST6EANbgoI4ubZVP2I9
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`
	awsMilanVlekDER = `
MIIFIzCCAtegAwIBAgIBADBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFl
AwQCAgUAogMCATAwgYAxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEgQ2xhcmEx
CzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZpY2VzMRcwFQYDVQQDDA5TRVYtVkxFSy1NaWxhbjAe
Fw0yNjAzMDkxOTMwMDVaFw0yNzAzMDkxOTMwMDVaMHoxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIG
A1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZpY2VzMREwDwYDVQQD
DAhTRVYtVkxFSzB2MBAGByqGSM49AgEGBSuBBAAiA2IABE/rO0PxEkKVu5SAX9Fv+h1pF0r+wWNmNO+DLcMENz2IOaqYiS6s
wJjXThFjsjIx5mdy42ozh33DIC+b02LmGScVQrREUL0h5KR4Qd5+BTiO+UDBb8Xd/p8rzpTQn+foEKOB8jCB7zAQBgkrBgEE
AZx4AQEEAwIBADAUBgkrBgEEAZx4AQIEBxYFTWlsYW4wEQYKKwYBBAGceAEDAQQDAgEEMBEGCisGAQQBnHgBAwIEAwIBADAR
BgorBgEEAZx4AQMEBAMCAQAwEQYKKwYBBAGceAEDBQQDAgEAMBEGCisGAQQBnHgBAwYEAwIBADARBgorBgEEAZx4AQMHBAMC
AQAwEQYKKwYBBAGceAEDAwQDAgEdMBIGCisGAQQBnHgBAwgEBAICAN4wLAYJKwYBBAGceAEFBB8WHUNOPWNjLXVzLWVhc3Qt
Mi5hbWF6b25hd3MuY29tMEEGCSqGSIb3DQEBCjA0oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUD
BAICBQCiAwIBMAOCAgEAezLRKlKoxDhJ9gGLDoIhruKSWJcwMHPn6E/aJzJvpDaYfb12ACKHyiMsm5htk6+lL9Kse544pmhh
Um/hxlpUNXiF+61obfKcaxp11Q2hzC/hTyLYpse6IXskLq6OH+DXzrcw0X30t3YIiUqzCGszbeTBy4uUOULxz3XbSUYFsKws
k9oMuo7isOUM3INiMiOTq91THlp6ZSVJDLIpW8v17DSL7yfJsvyLKsvtL7YjohFsOJe/qr/ttVSLC9WJmnxMxaxtgLSVGwCN
THsx6646R7SAPRVXpdOd4f+Gfj4Dk1eiELs1L85Qm0tChDLrLLO31X9cwPxg6fjdZ3sgqZrOv9Up2EiiX3uzH9pjuek9KZw8
BvbNmkABURnj2QVKkANKWeVwJ2OI9xmbKnLDQp+t3Q6gTcdPdcjSsAkT0JijpzamEmIPLdBobgVHAcxCxRhBILmJWQcU8V8R
g2+n/Zs8gpuGaCj0j8s8YDq7+sgy0/5CsDgAhU7+4HqzBTPbhOCNAI9uptU6v0xoDLzldXmVJQaGWp6zQ+WB29ZnFrF4UE85
+os3uIwc6uEPBjh3bjmhTwa3I7LWRWldRyoJUuLnBIdTJYVIkgrYJ47LfI3akZxUM0D+FpqawemnHOTT1z8ee1wj7wnE6nS2
X0R7cJNthweU48At2ZfRIuPYvu9av2Y=`
)

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func load(t *testing.T) [2]report {
	t.Helper()
	return [2]report{
		{"GCP Milan VCEK", abi.VcekReportSigner, "SEV-Milan", unb64(t, gcpMilanVcekReport), unb64(t, gcpMilanVcekDER)},
		{"AWS Milan VLEK", abi.VlekReportSigner, "SEV-VLEK-Milan", unb64(t, awsMilanVlekReport), unb64(t, awsMilanVlekDER)},
	}
}

type logGetter struct {
	g    trust.HTTPSGetter
	urls []string
}

func (l *logGetter) Get(url string) ([]byte, error) {
	l.urls = append(l.urls, url)
	return l.g.Get(url)
}

// verifyLeafOnly verifies the report with the leaf alone and certificate
// fetching on (the default), and returns what fillInAttestation put into the
// chain as the intermediate, by its CN.
func verifyLeafOnly(t *testing.T, r report) (err error, fetched []string, intermediateCN string) {
	t.Helper()
	rep, err := abi.ReportToProto(r.report)
	if err != nil {
		t.Fatal(err)
	}
	chain := &spb.CertificateChain{}
	switch r.signer {
	case abi.VcekReportSigner:
		chain.VcekCert = r.leaf
	case abi.VlekReportSigner:
		chain.VlekCert = r.leaf
	}
	att := &spb.Attestation{Report: rep, CertificateChain: chain}
	lg := &logGetter{g: trust.DefaultHTTPSGetter()}
	err = verify.SnpAttestation(att, &verify.Options{Getter: lg, Now: time.Now()})
	if ask := att.CertificateChain.GetAskCert(); len(ask) > 0 {
		if c, e := x509.ParseCertificate(ask); e == nil {
			intermediateCN = c.Subject.CommonName
		}
	}
	return err, lg.urls, intermediateCN
}

// Each report alone, in a fresh cache: the intermediate fetched is the one
// that signs the leaf.
func TestEachReportAlone(t *testing.T) {
	for _, r := range load(t) {
		t.Run(r.name, func(t *testing.T) {
			trust.ClearProductCertCache()
			err, fetched, cn := verifyLeafOnly(t, r)
			t.Logf("verify: err=%v; fetched %v; intermediate filled in: %q", err, fetched, cn)
			if len(fetched) == 0 {
				t.Skip("this version does not fetch the product chain during verification (888c4d1); see TestGetAttestationFromReportCache")
			}
			if cn != r.intermediateCN {
				t.Errorf("intermediate filled in is %q, want %q", cn, r.intermediateCN)
			}
		})
	}
}

// The two reports in one process, in either order: the second gets the
// first's chain from trust.GetProductChainContext's cache, which is keyed by
// product line alone although the KDS path (vcek/v1 or vlek/v1) depends on
// the signer. Nothing is fetched for the second report.
func TestProductChainCacheIgnoresSigner(t *testing.T) {
	reports := load(t)
	for _, order := range [][2]int{{0, 1}, {1, 0}} {
		first, second := reports[order[0]], reports[order[1]]
		t.Run(first.name+", then "+second.name, func(t *testing.T) {
			trust.ClearProductCertCache()
			err, fetched, cn := verifyLeafOnly(t, first)
			t.Logf("first,  %s: err=%v; fetched %v; intermediate filled in: %q", first.name, err, fetched, cn)
			if len(fetched) == 0 {
				t.Skip("this version does not fetch the product chain during verification (888c4d1); see TestGetAttestationFromReportCache")
			}
			err, fetched, cn = verifyLeafOnly(t, second)
			t.Logf("second, %s: err=%v; fetched %v; intermediate filled in: %q", second.name, err, fetched, cn)
			if cn != second.intermediateCN {
				t.Errorf("%s: the intermediate filled in is %q, want %q (served from the cache filled by %s; fetched for it: %v)",
					second.name, cn, second.intermediateCN, first.name, fetched)
			}
		})
	}
}

// GetAttestationFromReport fetches the chain on every version. In one process,
// a VLEK report first (it fails as VLEKs are not served by the KDS, but the
// product chain fetched for it is cached), then a VCEK report of the same
// product line: the attestation returned for the VCEK report carries the
// VLEK chain's intermediate.
func TestGetAttestationFromReportCache(t *testing.T) {
	reports := load(t)
	gcp, aws := reports[0], reports[1]

	intermediate := func(att *spb.Attestation) string {
		if att == nil || len(att.GetCertificateChain().GetAskCert()) == 0 {
			return ""
		}
		c, err := x509.ParseCertificate(att.GetCertificateChain().GetAskCert())
		if err != nil {
			return ""
		}
		return c.Subject.CommonName
	}
	get := func(r report) (*spb.Attestation, error, []string) {
		rep, err := abi.ReportToProto(r.report)
		if err != nil {
			t.Fatal(err)
		}
		lg := &logGetter{g: trust.DefaultHTTPSGetter()}
		att, err := verify.GetAttestationFromReport(rep, &verify.Options{Getter: lg, Now: time.Now()})
		return att, err, lg.urls
	}

	trust.ClearProductCertCache()
	att, err, fetched := get(gcp)
	t.Logf("control, %s alone: err=%v; fetched %v; intermediate: %q", gcp.name, err, fetched, intermediate(att))
	if cn := intermediate(att); cn != gcp.intermediateCN {
		t.Errorf("control: intermediate %q, want %q", cn, gcp.intermediateCN)
	}

	trust.ClearProductCertCache()
	att, err, fetched = get(aws)
	t.Logf("first, %s: err=%v; fetched %v; intermediate: %q", aws.name, err, fetched, intermediate(att))
	att, err, fetched = get(gcp)
	t.Logf("second, %s: err=%v; fetched %v; intermediate: %q", gcp.name, err, fetched, intermediate(att))
	if cn := intermediate(att); cn != gcp.intermediateCN {
		t.Errorf("%s after %s: GetAttestationFromReport returned the intermediate %q, want %q (fetched for it: %v)",
			gcp.name, aws.name, cn, gcp.intermediateCN, fetched)
	}
}
