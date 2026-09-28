// Command payments is Demo Bank's payment service, the workload of the demonstration. It holds no credential of its
// own. In a confidential VM it acquires, through TACRA (the SIG's CAI with the hardware plug-in, the CAAPI and the
// bank's EST server), a client certificate for the ledger database (Enrollment) and the fraud service's API key
// (Retrieval); then it moves money: the fraud service scores the transfer, and the ledger debits one account and
// credits the other in one database transaction, authenticated by that certificate. Demo Bank is fictional.
//
//	payments -config payments.json -from ACC-1001 -to ACC-2002 -amount 125.50 -out receipt.json
//	payments -config payments.json -imposter -out imposter.json     (on an ordinary VM: what it can still do)
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/TWI-Unified-Model/tacra/cai"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type config struct {
	TEE    string `json:"tee"`
	CAAPI  string `json:"caapi"`
	Hint   string `json:"hint"`
	Ledger struct {
		Target      string `json:"target"`
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Database    string `json:"database"`
		User        string `json:"user"`
		ServerCAPEM string `json:"server_ca_pem"`
	} `json:"ledger"`
	Fraud struct {
		Target      string `json:"target"`
		URL         string `json:"url"`
		ServerCAPEM string `json:"server_ca_pem"`
	} `json:"fraud"`
	RelyingParties map[string]string            `json:"relying_parties"`
	VaultOrigins   map[string]map[string]string `json:"vault_origins"`
	LocalEpochHex  string                       `json:"local_epoch_hex"`
}

type step struct {
	Name  string  `json:"step"`
	OK    bool    `json:"ok"`
	Ms    float64 `json:"ms"`
	Note  string  `json:"note,omitempty"`
	Error string  `json:"error,omitempty"`
}

type report struct {
	Mode    string         `json:"mode"`
	TEE     string         `json:"tee"`
	Steps   []step         `json:"steps"`
	Receipt map[string]any `json:"receipt,omitempty"`
}

func (r *report) add(name string, t0 time.Time, note string, err error) bool {
	s := step{Name: name, OK: err == nil, Ms: float64(time.Since(t0).Microseconds()) / 1000, Note: note}
	if err != nil {
		s.Error = err.Error()
	}
	r.Steps = append(r.Steps, s)
	mark := "ok "
	if err != nil {
		mark = "NO "
	}
	log.Printf("%s %-34s %8.1f ms  %s %s", mark, name, s.Ms, note, s.Error)
	return err == nil
}

func pool(pem string) *x509.CertPool {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM([]byte(pem)) {
		log.Fatal("no certificate in a configured CA")
	}
	return p
}

func main() {
	cfgPath := flag.String("config", "payments.json", "configuration")
	from := flag.String("from", "ACC-1001", "debit account")
	to := flag.String("to", "ACC-2002", "credit account")
	amount := flag.String("amount", "125.50", "amount in currency units")
	out := flag.String("out", "receipt.json", "report")
	imposter := flag.Bool("imposter", false, "try what an unattested copy of this service can do")
	flag.Parse()
	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatal(err)
	}
	units, err := strconv.ParseFloat(*amount, 64)
	if err != nil || units <= 0 {
		log.Fatal("amount must be positive")
	}
	cents := int64(math.Round(units * 100))
	rep := &report{Mode: "payment", TEE: cfg.TEE}
	if *imposter {
		rep.Mode = "imposter"
	}
	defer func() {
		b, _ := json.MarshalIndent(rep, "", " ")
		_ = os.WriteFile(*out, b, 0o644)
	}()

	// 1. The hardware plug-in and the CAI. On an ordinary VM this is where an imposter stops.
	t0 := time.Now()
	c, err := newCAI(&cfg)
	if !rep.add("attestation plug-in and CAI", t0, cfg.TEE, err) {
		if *imposter {
			tryWithout(rep, &cfg, *from, *to, cents)
		}
		return
	}

	// 2. A client certificate for the ledger (Enrollment).
	t0 = time.Now()
	certCred, err := c.AcquireCredential(context.Background(), cfg.Ledger.Target, cai.CredentialTypeX509, cfg.Hint)
	var leaf *x509.Certificate
	if err == nil {
		leaf, err = x509.ParseCertificate(certCred.Document)
	}
	note := ""
	if leaf != nil {
		note = fmt.Sprintf("%v serial %s until %s", leaf.DNSNames, hex.EncodeToString(leaf.SerialNumber.Bytes()),
			leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if !rep.add("TACRA: ledger certificate", t0, note, err) {
		return
	}

	// 3. The fraud service's API key (Retrieval).
	t0 = time.Now()
	keyCred, err := c.AcquireCredential(context.Background(), cfg.Fraud.Target, cai.CredentialTypeAPIKey, cfg.Hint)
	if !rep.add("TACRA: fraud-service API key", t0, "sealed to this VM's CEK, opened in the guest", err) {
		return
	}

	// 4. The fraud service scores the transfer.
	t0 = time.Now()
	decision, err := fraudScore(&cfg, keyCred.Document, *from, *to, cents)
	if !rep.add("fraud service: score", t0, fmt.Sprint(decision["decision"], " ", decision["ref"]), err) {
		return
	}
	if decision["decision"] != "approve" {
		rep.add("fraud service: decision", time.Now(), "", fmt.Errorf("decision %v", decision["decision"]))
		return
	}

	// 5. The ledger moves the money, authenticated by the certificate.
	t0 = time.Now()
	tlsCert := tls.Certificate{Certificate: [][]byte{certCred.Document}, PrivateKey: certCred.PrivateKey.(crypto.Signer), Leaf: leaf}
	receipt, err := transfer(&cfg, &tlsCert, *from, *to, cents, fmt.Sprint(decision["ref"]), leaf)
	if rep.add("ledger: transfer", t0, "one transaction, client-certificate login", err) {
		rep.Receipt = receipt
		b, _ := json.MarshalIndent(receipt, "", " ")
		log.Printf("receipt:\n%s", b)
	}
}

func newCAI(cfg *config) (*cai.Client, error) {
	epoch, err := hex.DecodeString(cfg.LocalEpochHex)
	if err != nil {
		return nil, err
	}
	var plugin platform.Plugin
	switch cfg.TEE {
	case "sev-snp":
		plugin, err = platform.NewSEVSNP(platform.WithLocalEpoch(epoch))
	case "tdx":
		plugin, err = platform.NewTDX(platform.WithLocalEpoch(epoch))
	default:
		err = fmt.Errorf("unknown tee %q", cfg.TEE)
	}
	if err != nil {
		return nil, err
	}
	// probe the hardware once: an ordinary VM has no attestation provider
	if _, err := plugin.GenerateEvidence(platform.EvidenceRequest{FreshnessKind: platform.FreshnessKindAbsentNone,
		BoundKey: mustKey(plugin), BoundKeyUse: platform.BoundKeyUseEncrypt, Target: "probe"}); err != nil {
		return nil, fmt.Errorf("no attestation from this machine: %w", err)
	}
	conn, err := grpc.NewClient(cfg.CAAPI, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	opts := []cai.Option{cai.WithCSRNamingHint()}
	for t, rrp := range cfg.RelyingParties {
		opts = append(opts, cai.WithRelyingParty(t, rrp))
	}
	for rrp, keys := range cfg.VaultOrigins {
		for kem, b64 := range keys {
			spki, err := base64.RawURLEncoding.DecodeString(b64)
			if err != nil {
				return nil, err
			}
			opts = append(opts, cai.WithVaultOrigin(rrp, kem, spki))
		}
	}
	return cai.New(plugin, caapiv1.NewCredentialAcquisitionServiceClient(conn), opts...)
}

func mustKey(p platform.Plugin) crypto.PublicKey {
	k, err := p.GenerateCEK(platform.EncryptionAlgorithmECDHP256)
	if err != nil {
		log.Fatal(err)
	}
	return k.Public()
}

func fraudScore(cfg *config, apiKey []byte, from, to string, cents int64) (map[string]any, error) {
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool(cfg.Fraud.ServerCAPEM), MinVersion: tls.VersionTLS12}}}
	body, _ := json.Marshal(map[string]any{"from": from, "to": to, "amount_cents": cents})
	req, _ := http.NewRequest(http.MethodPost, cfg.Fraud.URL+"/v1/score", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req.Header.Set("X-API-Key", string(apiKey))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}
	var out map[string]any
	return out, json.Unmarshal(raw, &out)
}

func ledgerConn(ctx context.Context, cfg *config, cert *tls.Certificate) (*pgx.Conn, error) {
	pc, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s user=%s sslmode=verify-full connect_timeout=15",
		cfg.Ledger.Host, cfg.Ledger.Port, cfg.Ledger.Database, cfg.Ledger.User))
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{RootCAs: pool(cfg.Ledger.ServerCAPEM), ServerName: cfg.Ledger.Host, MinVersion: tls.VersionTLS12}
	if cert != nil {
		tc.Certificates = []tls.Certificate{*cert}
	}
	pc.TLSConfig = tc
	pc.Fallbacks = nil
	return pgx.ConnectConfig(ctx, pc)
}

func transfer(cfg *config, cert *tls.Certificate, from, to string, cents int64, fraudRef string, leaf *x509.Certificate) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := ledgerConn(ctx, cfg, cert)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var dbUser string
	if err := tx.QueryRow(ctx, "SELECT current_user").Scan(&dbUser); err != nil {
		return nil, err
	}
	bal := map[string]int64{}
	first, second := from, to
	if second < first {
		first, second = second, first
	}
	for _, id := range []string{first, second} { // lock both rows in a fixed order
		var b int64
		if err := tx.QueryRow(ctx, "SELECT balance_cents FROM accounts WHERE id = $1 FOR UPDATE", id).Scan(&b); err != nil {
			return nil, fmt.Errorf("account %s: %w", id, err)
		}
		bal[id] = b
	}
	if bal[from] < cents {
		return nil, errors.New("insufficient funds")
	}
	after := map[string]int64{}
	for _, m := range []struct {
		id    string
		delta int64
	}{{from, -cents}, {to, cents}} {
		var b int64
		if err := tx.QueryRow(ctx, "UPDATE accounts SET balance_cents = balance_cents + $1 WHERE id = $2 RETURNING balance_cents",
			m.delta, m.id).Scan(&b); err != nil {
			return nil, err
		}
		after[m.id] = b
	}
	// The ledger, not this service, writes who made the transfer: the columns come from the TLS session
	// (sslinfo), and the service's role may not write them.
	var id int64
	var at time.Time
	var cn, serial, issuer, tlsVersion string
	if err := tx.QueryRow(ctx, `INSERT INTO transfers (from_account, to_account, amount_cents, fraud_ref, tee)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, client_cn, client_cert_serial, client_cert_issuer, ssl_version()`,
		from, to, cents, fraudRef, cfg.TEE).Scan(&id, &at, &cn, &serial, &issuer, &tlsVersion); err != nil {
		return nil, err
	}
	if serial != leaf.SerialNumber.String() || cn != leaf.Subject.CommonName {
		return nil, fmt.Errorf("the ledger recorded %s serial %s, not this service's certificate", cn, serial)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"transfer_id": id, "at": at.UTC().Format(time.RFC3339), "from": from, "to": to,
		"amount": fmt.Sprintf("%.2f", float64(cents)/100), "fraud_ref": fraudRef, "db_user": dbUser,
		"balance_before": map[string]string{from: cur(bal[from]), to: cur(bal[to])},
		"balance_after":  map[string]string{from: cur(after[from]), to: cur(after[to])},
		"recorded_by_ledger": map[string]string{"client_cn": cn, "client_cert_serial": serial, "client_cert_issuer": issuer,
			"tls": tlsVersion},
		"certificate": map[string]string{"serial_hex": hex.EncodeToString(leaf.SerialNumber.Bytes()),
			"not_after": leaf.NotAfter.UTC().Format(time.RFC3339)}}, nil
}

func cur(c int64) string { return fmt.Sprintf("%.2f", float64(c)/100) }

// tryWithout records what a copy of the service without attestation can still reach: nothing that moves money.
func tryWithout(rep *report, cfg *config, from, to string, cents int64) {
	t0 := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := ledgerConn(ctx, cfg, nil)
	if err == nil {
		conn.Close(ctx)
		err = errors.New("the ledger admitted a login without a certificate")
		rep.add("ledger: login without a certificate", t0, "", err)
	} else {
		rep.add("ledger: login without a certificate", t0, "refused as expected: "+err.Error(), nil)
	}
	t0 = time.Now()
	if _, err := fraudScore(cfg, nil, from, to, cents); err != nil {
		rep.add("fraud service: call without the key", t0, "refused as expected: "+err.Error(), nil)
	} else {
		rep.add("fraud service: call without the key", t0, "", errors.New("the fraud service answered without a key"))
	}
}
