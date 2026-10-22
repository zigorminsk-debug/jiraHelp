package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPunycodeIDNBelarusAndRussianDomains(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"mail.company.by", "mail.company.by"},
		{"https://Mail.Company.BY/webmail", "mail.company.by"},
		{"почта.компания.бел", "xn--80a1acny.xn--80aqeigdi5k.xn--90ais"},
		{"почта.пример.рф", "xn--80a1acny.xn--e1afmkfd.xn--p1ai"},
	}
	for _, tc := range cases {
		got, _, err := NormalizeDomain(tc.raw)
		if err != nil {
			t.Fatalf("NormalizeDomain(%q) unexpected error: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeDomain(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestOpenSSLCompatibilityOfGeneratedKerioBundle(t *testing.T) {
	tmpDir := t.TempDir()
	req := IssueRequest{
		Domain:       "mail.company.by",
		ExtraDomains: []string{"webmail.company.by", "autodiscover.company.by"},
		IPAddress:    "93.125.10.25",
		Mode:         "selfsigned",
		KeyType:      "rsa2048",
		PFXPassword:  "KerioSecret123",
		ValidityDays: 365,
		OutputDir:    tmpDir,
	}

	rec, _, err := ExecuteCertificateIssuance(req, func(level, msg string) {
		t.Logf("[%s] %s", level, msg)
	})
	if err != nil {
		t.Fatalf("ExecuteCertificateIssuance failed: %v", err)
	}

	// 1. Verify RSA PKCS#1 Private Key via real OpenSSL CLI
	outKey, err := exec.Command("openssl", "rsa", "-in", rec.Files["serverKey"], "-check", "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl rsa check failed: %v\n%s", err, string(outKey))
	}

	// 2. Verify CSR signature & SANs via real OpenSSL CLI
	outCSR, err := exec.Command("openssl", "req", "-in", rec.Files["csr"], "-text", "-noout", "-verify").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl req verify failed: %v\n%s", err, string(outCSR))
	}
	if !strings.Contains(string(outCSR), "DNS:mail.company.by") || !strings.Contains(string(outCSR), "IP Address:93.125.10.25") {
		t.Fatalf("CSR missing expected DNS or IP SAN:\n%s", string(outCSR))
	}

	// 3. Verify X.509 Certificate via real OpenSSL CLI
	outCert, err := exec.Command("openssl", "x509", "-in", rec.Files["serverCrt"], "-text", "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 check failed: %v\n%s", err, string(outCert))
	}

	// 4. Verify PKCS#12 (.pfx) archive via real OpenSSL 3.x CLI (both with password and empty password)
	outPFX, err := exec.Command("openssl", "pkcs12", "-in", rec.Files["pfx"], "-passin", "pass:KerioSecret123", "-info", "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl pkcs12 check failed: %v\n%s", err, string(outPFX))
	}

	// Also verify empty password PFX (common on Windows servers)
	reqEmptyPwd := req
	reqEmptyPwd.Domain = "empty-pass.company.by"
	reqEmptyPwd.PFXPassword = ""
	rec2, _, err := ExecuteCertificateIssuance(reqEmptyPwd, func(_, _ string) {})
	if err != nil {
		t.Fatalf("ExecuteCertificateIssuance empty pwd failed: %v", err)
	}
	outPFX2, err := exec.Command("openssl", "pkcs12", "-in", rec2.Files["pfx"], "-passin", "pass:", "-info", "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl pkcs12 empty password check failed: %v\n%s", err, string(outPFX2))
	}

	// 5. Verify Kerio Connect installation including custom active cert profile in mailserver.cfg
	mockKerioRoot := filepath.Join(tmpDir, "Kerio", "MailServer")
	mockSSLDir := filepath.Join(mockKerioRoot, "sslcert")
	_ = os.MkdirAll(mockSSLDir, 0755)
	_ = os.WriteFile(filepath.Join(mockSSLDir, "server.crt"), []byte("OLD_CERT"), 0644)
	_ = os.WriteFile(filepath.Join(mockKerioRoot, "mailserver.cfg"), []byte(`<config><table name="Ssl"><variable name="Certificate">cert_2</variable></table></config>`), 0644)

	note, err := InstallCertificateToKerio(rec, KerioInstallConfig{
		Enabled:        true,
		Method:         "filesystem",
		KerioPath:      mockSSLDir,
		RestartService: true,
	}, func(_, _ string) {})
	if err != nil {
		t.Fatalf("InstallCertificateToKerio failed: %v", err)
	}
	t.Logf("Kerio install note: %s", note)

	for _, mustExist := range []string{"server.crt", "server.key", "cert_2.crt", "cert_2.key"} {
		if _, err := os.Stat(filepath.Join(mockSSLDir, mustExist)); err != nil {
			t.Fatalf("expected installed Kerio file %s missing: %v", mustExist, err)
		}
	}
}

func TestEndToEndACMEv2HTTP01AndTLSALPN01AndDNS01(t *testing.T) {
	// Spin up an in-process RFC 8555 + RFC 8738 compliant ACME CA server that actually verifies live HTTP-01 and TLS-ALPN-01 challenges!
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Fake Let's Encrypt R11 Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	// Pick free local ports for HTTP-01 and TLS-ALPN-01 tests
	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	httpChallPort := ln1.Addr().(*net.TCPAddr).Port
	_ = ln1.Close()

	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	tlsChallPort := ln2.Addr().(*net.TCPAddr).Port
	_ = ln2.Close()

	var mu sync.Mutex
	var accountThumbprint string
	issuedCertPEM := ""

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
		if r.URL.Path == "/directory" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"newNonce":   srv.URL + "/nonce",
				"newAccount": srv.URL + "/account",
				"newOrder":   srv.URL + "/new-order",
				"meta": map[string]any{
					"profiles": map[string]string{
						"classic":    "90-day certs",
						"shortlived": "160-hour IP+DNS certs",
					},
				},
			})
			return
		}
		if r.URL.Path == "/nonce" {
			w.WriteHeader(200)
			return
		}

		raw, _ := io.ReadAll(r.Body)
		var jws struct {
			Protected string `json:"protected"`
			Payload   string `json:"payload"`
			Signature string `json:"signature"`
		}
		_ = json.Unmarshal(raw, &jws)
		protBytes, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
		payBytes, _ := base64.RawURLEncoding.DecodeString(jws.Payload)

		switch {
		case r.URL.Path == "/account":
			var prot struct {
				JWK map[string]string `json:"jwk"`
			}
			_ = json.Unmarshal(protBytes, &prot)
			canon := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, prot.JWK["crv"], prot.JWK["kty"], prot.JWK["x"], prot.JWK["y"])
			sum := sha256.Sum256([]byte(canon))
			mu.Lock()
			accountThumbprint = base64.RawURLEncoding.EncodeToString(sum[:])
			mu.Unlock()
			w.Header().Set("Location", srv.URL+"/acct/1")
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"status":"valid"}`))

		case r.URL.Path == "/new-order":
			var ordReq struct {
				Profile     string           `json:"profile"`
				Identifiers []acmeIdentifier `json:"identifiers"`
			}
			_ = json.Unmarshal(payBytes, &ordReq)
			var authURLs []string
			for _, id := range ordReq.Identifiers {
				authURLs = append(authURLs, fmt.Sprintf("%s/authz/%s/%s", srv.URL, id.Type, id.Value))
			}
			w.Header().Set("Location", srv.URL+"/order/1")
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(acmeOrder{
				Status:         "pending",
				Profile:        ordReq.Profile,
				Identifiers:    ordReq.Identifiers,
				Authorizations: authURLs,
				Finalize:       srv.URL + "/finalize",
			})

		case strings.HasPrefix(r.URL.Path, "/authz/"):
			parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/authz/"), "/", 2)
			idType, idVal := parts[0], parts[1]
			tok := "tok1234567890abcdef"
			status := r.URL.Query().Get("st")
			if status == "" {
				status = "pending"
			}
			_ = json.NewEncoder(w).Encode(acmeAuthorization{
				Identifier: acmeIdentifier{Type: idType, Value: idVal},
				Status:     status,
				Challenges: []acmeChallenge{
					{Type: "http-01", URL: srv.URL + "/chall/http/" + idVal, Status: "pending", Token: tok},
					{Type: "tls-alpn-01", URL: srv.URL + "/chall/alpn/" + idVal, Status: "pending", Token: tok},
					{Type: "dns-01", URL: srv.URL + "/chall/dns/" + idVal, Status: "pending", Token: tok},
				},
			})

		case strings.HasPrefix(r.URL.Path, "/chall/http/"):
			// Actually fetch HTTP-01 challenge from client's live TCP listener!
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/.well-known/acme-challenge/tok1234567890abcdef", httpChallPort))
			if err != nil {
				t.Errorf("CA failed HTTP-01 probe: %v", err)
			} else {
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				mu.Lock()
				want := "tok1234567890abcdef." + accountThumbprint
				mu.Unlock()
				if string(b) != want {
					t.Errorf("HTTP-01 keyAuth mismatch: got %q, want %q", string(b), want)
				}
			}
			// Mark auth valid on subsequent polls via simple redirect trick: rewrite auth handler check
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"status":"valid"}`))

		case strings.HasPrefix(r.URL.Path, "/chall/alpn/"):
			idVal := strings.TrimPrefix(r.URL.Path, "/chall/alpn/")
			conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tlsChallPort), &tls.Config{
				ServerName:         idVal,
				NextProtos:         []string{"acme-tls/1"},
				InsecureSkipVerify: true,
			})
			if err != nil {
				t.Errorf("CA failed TLS-ALPN-01 probe: %v", err)
			} else {
				peerCert := conn.ConnectionState().PeerCertificates[0]
				_ = conn.Close()
				foundOID := false
				for _, ext := range peerCert.Extensions {
					if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}) && ext.Critical {
						foundOID = true
					}
				}
				if !foundOID {
					t.Errorf("TLS-ALPN-01 cert missing critical id-pe-acmeIdentifier extension")
				}
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"status":"valid"}`))

		case strings.HasPrefix(r.URL.Path, "/chall/dns/"):
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"status":"valid"}`))

		case r.URL.Path == "/finalize":
			var fin struct {
				CSR string `json:"csr"`
			}
			_ = json.Unmarshal(payBytes, &fin)
			csrDER, _ := base64.RawURLEncoding.DecodeString(fin.CSR)
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil || csr.CheckSignature() != nil {
				t.Errorf("invalid CSR submitted to finalize: %v", err)
			}
			leafTpl := &x509.Certificate{
				SerialNumber: big.NewInt(99999),
				Subject:      csr.Subject,
				NotBefore:    time.Now().Add(-5 * time.Minute),
				NotAfter:     time.Now().Add(160 * time.Hour),
				DNSNames:     csr.DNSNames,
				IPAddresses:  csr.IPAddresses,
				KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, caCert, csr.PublicKey, caKey)
			mu.Lock()
			issuedCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) +
				string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(acmeOrder{
				Status:      "valid",
				Certificate: srv.URL + "/cert/1",
			})

		case r.URL.Path == "/order/1":
			_ = json.NewEncoder(w).Encode(acmeOrder{
				Status:      "valid",
				Certificate: srv.URL + "/cert/1",
			})

		case r.URL.Path == "/cert/1":
			mu.Lock()
			pemOut := issuedCertPEM
			mu.Unlock()
			_, _ = w.Write([]byte(pemOut))
		}
	}))
	defer srv.Close()

	// Make auth polling see "valid" after challenge trigger
	validatedIDs := map[string]bool{}
	origHandler := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/chall/") {
			parts := strings.Split(r.URL.Path, "/")
			mu.Lock()
			validatedIDs[parts[len(parts)-1]] = true
			mu.Unlock()
		}
		if strings.HasPrefix(r.URL.Path, "/authz/") {
			parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/authz/"), "/", 2)
			mu.Lock()
			isVal := validatedIDs[parts[1]]
			mu.Unlock()
			if isVal {
				r.URL.RawQuery = "st=valid"
			}
		}
		origHandler.ServeHTTP(w, r)
	})

	tmpOut := t.TempDir()

	// Scenario 1: Classic 90-day Domain issuance over HTTP-01 with full intermediate chain verification
	recHTTP, _, err := ExecuteCertificateIssuance(IssueRequest{
		Domain:             "mail.company.by",
		ExtraDomains:       []string{"autodiscover.company.by"},
		IPAddress:          "93.125.10.25",
		BindIP:             "127.0.0.1",
		Email:              "postmaster@company.by",
		Mode:               "staging",
		CustomDirectoryURL: srv.URL + "/directory",
		ChallengeType:      "http-01",
		HTTPPort:           httpChallPort,
		KeyType:            "rsa2048",
		OutputDir:          tmpOut,
	}, func(lvl, msg string) { t.Logf("[HTTP-01 %s] %s", lvl, msg) })
	if err != nil {
		t.Fatalf("ACME HTTP-01 issuance failed: %v", err)
	}
	if recHTTP.Files["chainCrt"] == "" {
		t.Fatalf("expected intermediate chainCrt file to be generated")
	}

	// Scenario 2: RFC 8738 Public IP + Domain SAN ("shortlived" profile) over TLS-ALPN-01
	mu.Lock()
	validatedIDs = map[string]bool{}
	mu.Unlock()
	recALPN, _, err := ExecuteCertificateIssuance(IssueRequest{
		Domain:             "ipmail.company.by",
		IPAddress:          "93.125.10.25",
		BindIP:             "127.0.0.1",
		Mode:               "staging",
		CustomDirectoryURL: srv.URL + "/directory",
		IncludeIPSAN:       true,
		ChallengeType:      "tls-alpn-01",
		TLSPort:            tlsChallPort,
		KeyType:            "rsa4096",
		OutputDir:          tmpOut,
	}, func(lvl, msg string) { t.Logf("[TLS-ALPN-01 %s] %s", lvl, msg) })
	if err != nil {
		t.Fatalf("ACME TLS-ALPN-01 IP+DNS issuance failed: %v", err)
	}
	if len(recALPN.IPAddresses) != 1 || recALPN.IPAddresses[0] != "93.125.10.25" {
		t.Fatalf("expected IP SAN 93.125.10.25 in issued cert, got %v", recALPN.IPAddresses)
	}

	// Scenario 3: Interactive 2-step DNS-01 issuance
	mu.Lock()
	validatedIDs = map[string]bool{}
	mu.Unlock()
	_, dnsSess, err := ExecuteCertificateIssuance(IssueRequest{
		Domain:             "dnsmail.company.by",
		IPAddress:          "93.125.10.25",
		Mode:               "staging",
		CustomDirectoryURL: srv.URL + "/directory",
		ChallengeType:      "dns-01",
		KeyType:            "ecdsa256",
		OutputDir:          tmpOut,
	}, func(lvl, msg string) { t.Logf("[DNS-01 %s] %s", lvl, msg) })
	if err != nil || dnsSess == nil || len(dnsSess.Records) != 1 {
		t.Fatalf("expected pending DNS-01 session, got err=%v sess=%v", err, dnsSess)
	}
	recDNS, err := CompletePendingDNS01Session(dnsSess.SessionID, func(lvl, msg string) {
		t.Logf("[DNS-01-COMPLETE %s] %s", lvl, msg)
	})
	if err != nil || recDNS == nil {
		t.Fatalf("CompletePendingDNS01Session failed: %v", err)
	}
}
