package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type KerioInstallConfig struct {
	Enabled        bool   `json:"enabled"`
	Method         string `json:"method"` // "filesystem" | "api"
	KerioPath      string `json:"kerioPath"`
	RestartService bool   `json:"restartService"`
	APIHost        string `json:"apiHost"`
	APIPort        int    `json:"apiPort"`
	APIUser        string `json:"apiUser"`
	APIPassword    string `json:"apiPassword"`
}

type IssueRequest struct {
	Domain             string             `json:"domain"`
	ExtraDomains       []string           `json:"extraDomains"`
	IPAddress          string             `json:"ipAddress"`
	BindIP             string             `json:"bindIp"`
	Email              string             `json:"email"`
	Mode               string             `json:"mode"` // "letsencrypt" | "staging" | "selfsigned"
	CustomDirectoryURL string             `json:"customDirectoryUrl,omitempty"`
	IncludeIPSAN     bool               `json:"includeIpSan"`  // Let's Encrypt "shortlived" profile (DNS + IP SAN)
	ChallengeType    string             `json:"challengeType"` // "http-01" | "http-01-webroot" | "tls-alpn-01" | "dns-01"
	HTTPPort         int                `json:"httpPort"`
	TLSPort          int                `json:"tlsPort"`
	WebrootPath      string             `json:"webrootPath"`
	StopKerioTemp    bool               `json:"stopKerioTemp"`
	KeyType          string             `json:"keyType"` // "rsa2048" | "rsa4096" | "ecdsa256"
	PFXPassword      string             `json:"pfxPassword"`
	ValidityDays     int                `json:"validityDays"`
	OutputDir        string             `json:"outputDir"`
	ReuseExistingKey bool               `json:"reuseExistingKey"`
	KerioInstall     KerioInstallConfig `json:"kerioInstall"`
}

type IssuedCertRecord struct {
	ID                string             `json:"id"`
	Slug              string             `json:"slug"`
	PrimaryDomain     string             `json:"primaryDomain"`
	DisplayDomain     string             `json:"displayDomain"`
	DNSNames          []string           `json:"dnsNames"`
	IPAddresses       []string           `json:"ipAddresses"`
	ConfiguredIP      string             `json:"configuredIp"`
	Issuer            string             `json:"issuer"`
	SubjectCN         string             `json:"subjectCN"`
	SerialHex         string             `json:"serialHex"`
	SHA256Fingerprint string             `json:"sha256Fingerprint"`
	SHA1Fingerprint   string             `json:"sha1Fingerprint"`
	NotBefore         time.Time          `json:"notBefore"`
	NotAfter          time.Time          `json:"notAfter"`
	DaysRemaining     int                `json:"daysRemaining"`
	HoursRemaining    int                `json:"hoursRemaining"`
	KeyType           string             `json:"keyType"`
	KeyFormat         string             `json:"keyFormat"`
	Mode              string             `json:"mode"`
	ACMEProfile       string             `json:"acmeProfile"`
	CreatedAt         time.Time          `json:"createdAt"`
	CertDir           string             `json:"certDir"`
	Files             map[string]string  `json:"files"`
	KerioInstalled    bool               `json:"kerioInstalled"`
	KerioInstallNote  string             `json:"kerioInstallNote"`
	OriginalRequest   IssueRequest       `json:"originalRequest"`
	FullchainPEM      string             `json:"fullchainPem,omitempty"`
	PrivateKeyPEM     string             `json:"privateKeyPem,omitempty"`
	CertOnlyPEM       string             `json:"certOnlyPem,omitempty"`
	ChainOnlyPEM      string             `json:"chainOnlyPem,omitempty"`
	CSRPEM            string             `json:"csrPem,omitempty"`
}

func GeneratePrivateKey(keyType string) (crypto.Signer, []byte, []byte, string, error) {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "", "rsa2048", "rsa-2048":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, nil, "", err
		}
		pkcs1PEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		})
		pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, nil, "", err
		}
		pkcs8PEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8DER,
		})
		return priv, pkcs1PEM, pkcs8PEM, "RSA 2048 бит (PKCS#1 Traditional — совместим со всеми версиями Kerio Connect)", nil

	case "rsa4096", "rsa-4096":
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, nil, "", err
		}
		pkcs1PEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		})
		pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, nil, "", err
		}
		pkcs8PEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8DER,
		})
		return priv, pkcs1PEM, pkcs8PEM, "RSA 4096 бит (PKCS#1 Traditional — совместим с Kerio Connect)", nil

	case "ecdsa256", "ec-256", "p256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, "", err
		}
		sec1DER, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, nil, nil, "", err
		}
		sec1PEM := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: sec1DER,
		})
		pkcs8DER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, nil, "", err
		}
		pkcs8PEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8DER,
		})
		return priv, sec1PEM, pkcs8PEM, "ECDSA P-256 (SEC1 EC PRIVATE KEY)", nil

	default:
		return nil, nil, nil, "", fmt.Errorf("неизвестный тип ключа %q (доступны rsa2048, rsa4096, ecdsa256)", keyType)
	}
}

func ParsePrivateKeyPEM(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM приватного ключа")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ключ не поддерживает подпись")
	}
	return signer, nil
}

// CreateCertificateCSR creates a DER and PEM encoded PKCS#10 CSR properly handling DNS SANs, IP SANs, and ACME profiles.
func CreateCertificateCSR(priv crypto.Signer, dnsNames []string, ips []net.IP, shortlivedProfile bool) ([]byte, []byte, error) {
	subj := pkix.Name{}
	// Per Let's Encrypt "shortlived" profile & CABF rules: omit CommonName for IP certs / shortlived profile.
	if !shortlivedProfile && len(dnsNames) > 0 {
		subj.CommonName = dnsNames[0]
	}
	tpl := &x509.CertificateRequest{
		Subject:     subj,
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка генерации CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	return csrDER, csrPEM, nil
}

// CreateSelfSignedKerioCert issues a local X.509 v3 certificate covering all entered DNS names & IP addresses for testing or LAN mail servers.
func CreateSelfSignedKerioCert(priv crypto.Signer, dnsNames []string, ips []net.IP, days int) ([]byte, error) {
	if days <= 0 {
		days = 365
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	cn := "Kerio Mail Server"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	} else if len(ips) > 0 {
		cn = ips[0].String()
	}

	now := time.Now().Add(-5 * time.Minute)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Kerio Connect Mail Server"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, priv.Public(), priv)
	if err != nil {
		return nil, fmt.Errorf("ошибка выпуска локального X.509 сертификата: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}), nil
}

func SplitCertificateChainPEM(fullPEM []byte) (leafCert *x509.Certificate, leafDER []byte, chainDERs [][]byte, leafPEM, chainPEM, normalizedFullPEM []byte, err error) {
	rest := fullPEM
	var blocks []*pem.Block
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			blocks = append(blocks, blk)
		}
	}
	if len(blocks) == 0 {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("в ответе не найдено ни одного PEM сертификата")
	}

	leafDER = blocks[0].Bytes
	leafCert, err = x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("ошибка чтения X.509 сертификата: %w", err)
	}
	leafPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	var fullBuf, chainBuf bytes.Buffer
	fullBuf.Write(leafPEM)
	for _, b := range blocks[1:] {
		chainDERs = append(chainDERs, b.Bytes)
		encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Bytes})
		chainBuf.Write(encoded)
		fullBuf.Write(encoded)
	}
	return leafCert, leafDER, chainDERs, leafPEM, chainBuf.Bytes(), fullBuf.Bytes(), nil
}

var unsafeSlugRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func MakeCertSlug(primaryDomain string, ipAddr string) string {
	base := strings.TrimSpace(primaryDomain)
	if base == "" {
		base = "ip-" + strings.ReplaceAll(strings.TrimSpace(ipAddr), ":", "-")
	}
	base = strings.TrimPrefix(base, "*.")
	base = unsafeSlugRe.ReplaceAllString(base, "_")
	if base == "" {
		base = "kerio-cert"
	}
	return base
}

func formatFingerprint(b []byte) string {
	hexStr := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(hexStr)/2)
	for i := 0; i+2 <= len(hexStr); i += 2 {
		parts = append(parts, hexStr[i:i+2])
	}
	return strings.Join(parts, ":")
}

// SaveKerioCertificateBundle verifies key-certificate pairing and saves .key, .crt (fullchain), cert-only.crt, chain.crt, .csr, .pfx, install-kerio.bat, and .zip.
func SaveKerioCertificateBundle(
	req IssueRequest,
	displayDomain string,
	acmeProfile string,
	priv crypto.Signer,
	privPEM []byte,
	privPKCS8PEM []byte,
	keyDesc string,
	csrPEM []byte,
	rawChainPEM []byte,
) (*IssuedCertRecord, error) {
	leafCert, leafDER, chainDERs, leafPEM, chainPEM, fullPEM, err := SplitCertificateChainPEM(rawChainPEM)
	if err != nil {
		return nil, err
	}

	// Verify cryptographic key-certificate match!
	if _, err := tls.X509KeyPair(fullPEM, privPEM); err != nil {
		return nil, fmt.Errorf("проверка совместимости ключа и сертификата не пройдена: %w", err)
	}

	outRoot := strings.TrimSpace(req.OutputDir)
	if outRoot == "" {
		outRoot = DefaultCertsRoot()
	}
	slug := MakeCertSlug(req.Domain, req.IPAddress)
	certDir := filepath.Join(outRoot, slug)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("не удалось создать каталог сертификатов %s: %w", certDir, err)
	}

	friendly := displayDomain
	if friendly == "" {
		friendly = slug
	}
	pfxBytes, err := BuildPFX(priv, leafDER, chainDERs, req.PFXPassword, "Kerio Connect - "+friendly)
	if err != nil {
		return nil, fmt.Errorf("ошибка сборки PKCS#12 (.pfx): %w", err)
	}

	files := map[string]string{
		"serverKey":    filepath.Join(certDir, "server.key"),
		"serverCrt":    filepath.Join(certDir, "server.crt"),
		"domainKey":    filepath.Join(certDir, slug+".key"),
		"domainKeyP8":  filepath.Join(certDir, slug+".pkcs8.key"),
		"fullchainCrt": filepath.Join(certDir, slug+"-fullchain.crt"),
		"certOnlyCrt":  filepath.Join(certDir, "cert-only.crt"),
		"chainCrt":     filepath.Join(certDir, "chain.crt"),
		"csr":          filepath.Join(certDir, slug+".csr"),
		"pfx":          filepath.Join(certDir, slug+".pfx"),
		"installBat":   filepath.Join(certDir, "install-kerio.bat"),
		"readme":       filepath.Join(certDir, "README-KERIO.txt"),
		"zip":          filepath.Join(certDir, slug+"-kerio-bundle.zip"),
	}

	installBatContent := buildKerioBatchScript(slug)
	readmeContent := buildKerioReadmeText(slug, friendly, leafCert)

	writeMap := []struct {
		path string
		data []byte
		perm os.FileMode
	}{
		{files["serverKey"], privPEM, 0600},
		{files["domainKey"], privPEM, 0600},
		{files["domainKeyP8"], privPKCS8PEM, 0600},
		{files["serverCrt"], fullPEM, 0644},
		{files["fullchainCrt"], fullPEM, 0644},
		{files["certOnlyCrt"], leafPEM, 0644},
		{files["csr"], csrPEM, 0644},
		{files["pfx"], pfxBytes, 0600},
		{files["installBat"], []byte(installBatContent), 0755},
		{files["readme"], []byte(readmeContent), 0644},
	}
	if len(chainPEM) > 0 {
		writeMap = append(writeMap, struct {
			path string
			data []byte
			perm os.FileMode
		}{files["chainCrt"], chainPEM, 0644})
	} else {
		delete(files, "chainCrt")
	}

	for _, item := range writeMap {
		if err := os.WriteFile(item.path, item.data, item.perm); err != nil {
			return nil, fmt.Errorf("ошибка записи файла %s: %w", item.path, err)
		}
	}

	// Build single-click downloadable ZIP bundle for Kerio Connect
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	zipOrder := []string{"serverCrt", "serverKey", "fullchainCrt", "domainKey", "domainKeyP8", "certOnlyCrt", "chainCrt", "csr", "pfx", "installBat", "readme"}
	for _, k := range zipOrder {
		p, ok := files[k]
		if !ok {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		w, err := zw.Create(filepath.Base(p))
		if err != nil {
			continue
		}
		_, _ = w.Write(raw)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("ошибка упаковки ZIP-архива: %w", err)
	}
	if err := os.WriteFile(files["zip"], zipBuf.Bytes(), 0600); err != nil {
		return nil, fmt.Errorf("ошибка сохранения ZIP-архива: %w", err)
	}

	var ipStrings []string
	for _, ip := range leafCert.IPAddresses {
		ipStrings = append(ipStrings, ip.String())
	}
	fp256 := sha256.Sum256(leafDER)
	fp1 := sha1.Sum(leafDER)
	remHours := int(time.Until(leafCert.NotAfter).Hours())
	remDays := remHours / 24

	rec := &IssuedCertRecord{
		ID:                slug,
		Slug:              slug,
		PrimaryDomain:     req.Domain,
		DisplayDomain:     friendly,
		DNSNames:          leafCert.DNSNames,
		IPAddresses:       ipStrings,
		ConfiguredIP:      req.IPAddress,
		Issuer:            leafCert.Issuer.CommonName,
		SubjectCN:         leafCert.Subject.CommonName,
		SerialHex:         strings.ToUpper(leafCert.SerialNumber.Text(16)),
		SHA256Fingerprint: formatFingerprint(fp256[:]),
		SHA1Fingerprint:   formatFingerprint(fp1[:]),
		NotBefore:         leafCert.NotBefore,
		NotAfter:          leafCert.NotAfter,
		DaysRemaining:     remDays,
		HoursRemaining:    remHours,
		KeyType:           req.KeyType,
		KeyFormat:         keyDesc,
		Mode:              req.Mode,
		ACMEProfile:       acmeProfile,
		CreatedAt:         time.Now(),
		CertDir:           certDir,
		Files:             files,
		OriginalRequest:   req,
	}
	if rec.Issuer == "" && len(leafCert.Issuer.Organization) > 0 {
		rec.Issuer = leafCert.Issuer.Organization[0]
	}

	metaBytes, err := json.MarshalIndent(rec, "", "  ")
	if err == nil {
		_ = os.WriteFile(filepath.Join(certDir, "metadata.json"), metaBytes, 0600)
	}

	// Populate inline text previews for immediate UI inspection
	rec.FullchainPEM = string(fullPEM)
	rec.PrivateKeyPEM = string(privPEM)
	rec.CertOnlyPEM = string(leafPEM)
	rec.ChainOnlyPEM = string(chainPEM)
	rec.CSRPEM = string(csrPEM)
	return rec, nil
}

func LoadAllCertRecords(outRoot string) ([]IssuedCertRecord, error) {
	if strings.TrimSpace(outRoot) == "" {
		outRoot = DefaultCertsRoot()
	}
	entries, err := os.ReadDir(outRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return []IssuedCertRecord{}, nil
		}
		return nil, err
	}
	var list []IssuedCertRecord
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		metaPath := filepath.Join(outRoot, e.Name(), "metadata.json")
		raw, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var rec IssuedCertRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			continue
		}
		rec.HoursRemaining = int(time.Until(rec.NotAfter).Hours())
		rec.DaysRemaining = rec.HoursRemaining / 24
		list = append(list, rec)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	return list, nil
}

func LoadSingleCertRecord(outRoot, id string, includePEM bool) (*IssuedCertRecord, error) {
	if strings.TrimSpace(outRoot) == "" {
		outRoot = DefaultCertsRoot()
	}
	slug := filepath.Base(id)
	metaPath := filepath.Join(outRoot, slug, "metadata.json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var rec IssuedCertRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	rec.HoursRemaining = int(time.Until(rec.NotAfter).Hours())
	rec.DaysRemaining = rec.HoursRemaining / 24
	if includePEM {
		if b, err := os.ReadFile(rec.Files["serverCrt"]); err == nil {
			rec.FullchainPEM = string(b)
		}
		if b, err := os.ReadFile(rec.Files["serverKey"]); err == nil {
			rec.PrivateKeyPEM = string(b)
		}
		if b, err := os.ReadFile(rec.Files["certOnlyCrt"]); err == nil {
			rec.CertOnlyPEM = string(b)
		}
		if p, ok := rec.Files["chainCrt"]; ok {
			if b, err := os.ReadFile(p); err == nil {
				rec.ChainOnlyPEM = string(b)
			}
		}
		if b, err := os.ReadFile(rec.Files["csr"]); err == nil {
			rec.CSRPEM = string(b)
		}
	}
	return &rec, nil
}

func buildKerioBatchScript(slug string) string {
	// Pure ASCII commands inside .bat so ANY Windows codepage (866 / 1251 / 65001) executes it with zero encoding issues!
	lines := []string{
		"@echo off",
		"setlocal EnableDelayedExpansion",
		"title Kerio Connect SSL Certificate Installer (" + slug + ")",
		"echo ============================================================",
		"echo   Kerio Connect SSL Certificate Auto-Installer",
		"echo   Certificate: " + slug,
		"echo ============================================================",
		"net session >nul 2>&1",
		"if %errorLevel% neq 0 (",
		"    echo [ERROR] Please right-click install-kerio.bat and choose 'Run as administrator'!",
		"    pause",
		"    exit /b 1",
		")",
		"",
		"set \"KERIO_SSL=\"",
		"if exist \"C:\\Program Files\\Kerio\\MailServer\\sslcert\" set \"KERIO_SSL=C:\\Program Files\\Kerio\\MailServer\\sslcert\"",
		"if exist \"C:\\Program Files (x86)\\Kerio\\MailServer\\sslcert\" set \"KERIO_SSL=C:\\Program Files (x86)\\Kerio\\MailServer\\sslcert\"",
		"if \"%KERIO_SSL%\"==\"\" (",
		"    set /p KERIO_SSL=\"Enter full path to Kerio sslcert folder (e.g. D:\\Kerio\\MailServer\\sslcert): \"",
		")",
		"if not exist \"%KERIO_SSL%\" (",
		"    echo [ERROR] Folder not found: %KERIO_SSL%",
		"    pause",
		"    exit /b 1",
		")",
		"",
		"set \"STAMP=%DATE:~-4%%DATE:~3,2%%DATE:~0,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%\"",
		"set \"STAMP=%STAMP: =0%\"",
		"set \"BACKUP_DIR=%KERIO_SSL%\\backup_%STAMP%\"",
		"mkdir \"%BACKUP_DIR%\" >nul 2>&1",
		"copy /Y \"%KERIO_SSL%\\*.crt\" \"%BACKUP_DIR%\\\" >nul 2>&1",
		"copy /Y \"%KERIO_SSL%\\*.key\" \"%BACKUP_DIR%\\\" >nul 2>&1",
		"echo [OK] Backup saved to: %BACKUP_DIR%",
		"",
		"echo Stopping KerioMailServer service...",
		"net stop KerioMailServer",
		"",
		"copy /Y \"%~dp0server.crt\" \"%KERIO_SSL%\\server.crt\" >nul",
		"copy /Y \"%~dp0server.key\" \"%KERIO_SSL%\\server.key\" >nul",
		"echo [OK] Installed server.crt and server.key into %KERIO_SSL%",
		"",
		"echo Starting KerioMailServer service...",
		"net start KerioMailServer",
		"echo ============================================================",
		"echo [DONE] SSL certificate installed and KerioMailServer restarted!",
		"echo ============================================================",
		"pause",
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

func buildKerioReadmeText(slug, domain string, cert *x509.Certificate) string {
	lines := []string{
		"======================================================================",
		"  КОМПЛЕКТ SSL-СЕРТИФИКАТА ДЛЯ KERIO CONNECT (KERIO MAILSERVER)",
		"======================================================================",
		fmt.Sprintf("Домен / Сервер : %s", domain),
		fmt.Sprintf("Издатель       : %s", cert.Issuer.CommonName),
		fmt.Sprintf("Действителен с : %s", cert.NotBefore.Format("2006-01-02 15:04:05 MST")),
		fmt.Sprintf("Действителен до: %s", cert.NotAfter.Format("2006-01-02 15:04:05 MST")),
		fmt.Sprintf("DNS SAN        : %s", strings.Join(cert.DNSNames, ", ")),
		"",
		"ФАЙЛЫ В ПАПКЕ / АРХИВЕ:",
		"  1. server.crt (" + slug + "-fullchain.crt)",
		"     -> Сертификат сервера + промежуточная цепочка CA (Fullchain).",
		"        Именно этот файл указывайте в поле 'Сертификат' (Certificate) в Kerio Connect!",
		"  2. server.key (" + slug + ".key)",
		"     -> Незашифрованный приватный ключ RSA (Traditional PKCS#1).",
		"        Указывайте этот файл в поле 'Приватный ключ' (Private Key) в Kerio Connect!",
		"  3. chain.crt     -> Промежуточный сертификат удостоверяющего центра (Intermediate CA).",
		"  4. cert-only.crt -> Только конечный сертификат домена (без промежуточного CA).",
		"  5. " + slug + ".pfx -> Архив PKCS#12 (ключ + сертификат + цепочка) для Windows MMC / IIS.",
		"  6. install-kerio.bat -> Скрипт автоустановки в папку Kerio Connect с авто-бэкапом.",
		"",
		"СПОСОБ 1 — ИМПОРТ ЧЕРЕЗ ВЕБ-АДМИНКУ KERIO CONNECT ADMINISTRATION:",
		"  1. Откройте https://<IP-сервера>:4040/admin",
		"  2. Перейдите в раздел: Конфигурация -> Сертификаты SSL (Configuration -> SSL Certificates)",
		"  3. Нажмите кнопку: Импорт -> Импортировать новый сертификат (Import -> Import New Certificate)",
		"  4. В поле Certificate выберите файл: server.crt (или " + slug + "-fullchain.crt)",
		"  5. В поле Private Key выберите файл: server.key (или " + slug + ".key)",
		"  6. Выделите импортированный сертификат в списке и нажмите 'Использовать' (Set as Active).",
		"",
		"СПОСОБ 2 — АВТОМАТИЧЕСКАЯ УСТАНОВКА НА WINDOWS SERVER:",
		"  Распакуйте архив на сервере с Kerio Connect, нажмите правой кнопкой мыши",
		"  на файл install-kerio.bat -> 'Запуск от имени администратора'.",
		"======================================================================",
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}
