package main

import (
	"bytes"
	"context"
	"crypto"
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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	LEDirectoryProd    = "https://acme-v02.api.letsencrypt.org/directory"
	LEDirectoryStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type LogFunc func(level, message string)

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	Meta       struct {
		TermsOfService string            `json:"termsOfService"`
		Profiles       map[string]string `json:"profiles"`
	} `json:"meta"`
}

type acmeIdentifier struct {
	Type  string `json:"type"` // "dns" or "ip"
	Value string `json:"value"`
}

type acmeOrder struct {
	Status         string           `json:"status"`
	Expires        string           `json:"expires"`
	Profile        string           `json:"profile,omitempty"`
	Identifiers    []acmeIdentifier `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate"`
	Error          *acmeProblem     `json:"error,omitempty"`
}

type acmeAuthorization struct {
	Identifier acmeIdentifier  `json:"identifier"`
	Status     string          `json:"status"`
	Expires    string          `json:"expires"`
	Challenges []acmeChallenge `json:"challenges"`
	Wildcard   bool            `json:"wildcard"`
}

type acmeChallenge struct {
	Type   string       `json:"type"`
	URL    string       `json:"url"`
	Status string       `json:"status"`
	Token  string       `json:"token"`
	Error  *acmeProblem `json:"error,omitempty"`
}

type acmeProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (p *acmeProblem) Error() string {
	if p == nil {
		return "неизвестная ошибка ACME"
	}
	return fmt.Sprintf("%s (%s)", p.Detail, p.Type)
}

type DNS01RecordInstruction struct {
	Domain    string `json:"domain"`
	Record    string `json:"record"`
	Type      string `json:"type"`
	TXTValue  string `json:"txtValue"`
	AuthURL   string `json:"authUrl"`
	ChallURL  string `json:"challUrl"`
}

type PendingDNS01Session struct {
	SessionID      string                   `json:"sessionId"`
	CreatedAt      time.Time                `json:"createdAt"`
	Records        []DNS01RecordInstruction `json:"records"`
	Request        IssueRequest             `json:"request"`
	DisplayDomain  string                   `json:"displayDomain"`
	ACMEProfile    string                   `json:"acmeProfile"`
	OrderURL       string                   `json:"-"`
	FinalizeURL    string                   `json:"-"`
	Client         *ACMEClient              `json:"-"`
	PrivKey        crypto.Signer            `json:"-"`
	PrivPEM        []byte                   `json:"-"`
	PrivPKCS8PEM   []byte                   `json:"-"`
	KeyDesc        string                   `json:"-"`
	CSRDER         []byte                   `json:"-"`
	CSRPEM         []byte                   `json:"-"`
}

var (
	pendingDNS01Mu       sync.Mutex
	pendingDNS01Sessions = map[string]*PendingDNS01Session{}
)

type ACMEClient struct {
	dirURL     string
	dir        acmeDirectory
	accountKey *ecdsa.PrivateKey
	kid        string
	httpClient *http.Client
	nonceMu    sync.Mutex
	nonces     []string
	log        LogFunc
}

type savedAccountData struct {
	AccountURL string `json:"accountUrl"`
	KeyPEM     string `json:"keyPem"`
}

func NewACMEClient(mode, customDirURL, email, storageDir string, log LogFunc) (*ACMEClient, error) {
	dirURL := LEDirectoryProd
	envTag := "prod"
	if mode == "staging" {
		dirURL = LEDirectoryStaging
		envTag = "staging"
	}
	if strings.TrimSpace(customDirURL) != "" {
		dirURL = strings.TrimSpace(customDirURL)
		envTag = "custom"
	}

	c := &ACMEClient{
		dirURL: dirURL,
		httpClient: &http.Client{
			Timeout: 35 * time.Second,
		},
		log: log,
	}

	log("info", fmt.Sprintf("Подключение к ACME-серверу Let's Encrypt (%s)...", dirURL))
	resp, err := c.httpClient.Get(dirURL)
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к серверу Let's Encrypt (%s): %w — проверьте доступ в интернет с этого сервера", dirURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ошибка чтения каталога ACME (%d): %s", resp.StatusCode, string(body))
	}
	if err := json.Unmarshal(body, &c.dir); err != nil {
		return nil, fmt.Errorf("некорректный ответ каталога ACME: %w", err)
	}

	// Load or create ACME account key
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, err
	}
	accFile := filepath.Join(storageDir, fmt.Sprintf("acme-account-%s.json", envTag))
	var saved savedAccountData
	if raw, err := os.ReadFile(accFile); err == nil {
		if json.Unmarshal(raw, &saved) == nil && saved.KeyPEM != "" {
			if blk, _ := pem.Decode([]byte(saved.KeyPEM)); blk != nil {
				if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
					c.accountKey = k
					c.kid = saved.AccountURL
				}
			}
		}
	}

	if c.accountKey == nil {
		log("info", "Генерация нового ключа ACME-аккаунта (ECDSA P-256)...")
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		c.accountKey = k
	}

	// Register or fetch account
	regPayload := map[string]any{
		"termsOfServiceAgreed": true,
	}
	if strings.TrimSpace(email) != "" {
		regPayload["contact"] = []string{"mailto:" + strings.TrimSpace(email)}
	}
	_, hdr, status, err := c.signedPost(c.dir.NewAccount, regPayload, true)
	if err != nil {
		return nil, fmt.Errorf("ошибка регистрации ACME-аккаунта: %w", err)
	}
	if loc := hdr.Get("Location"); loc != "" {
		c.kid = loc
	}
	if c.kid == "" {
		return nil, fmt.Errorf("сервер ACME не вернул URL аккаунта (код %d)", status)
	}

	derBytes, err := x509.MarshalECPrivateKey(c.accountKey)
	if err == nil {
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})
		b, _ := json.MarshalIndent(savedAccountData{
			AccountURL: c.kid,
			KeyPEM:     string(keyPEM),
		}, "", "  ")
		_ = os.WriteFile(accFile, b, 0600)
	}
	log("success", "ACME-аккаунт Let's Encrypt успешно инициализирован")
	return c, nil
}

func (c *ACMEClient) jwkMap() map[string]string {
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	c.accountKey.PublicKey.X.FillBytes(xb)
	c.accountKey.PublicKey.Y.FillBytes(yb)
	return map[string]string{
		"crv": "P-256",
		"kty": "EC",
		"x":   base64.RawURLEncoding.EncodeToString(xb),
		"y":   base64.RawURLEncoding.EncodeToString(yb),
	}
}

func (c *ACMEClient) jwkThumbprint() string {
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	c.accountKey.PublicKey.X.FillBytes(xb)
	c.accountKey.PublicKey.Y.FillBytes(yb)
	// Exact RFC 7638 canonical JSON key order: crv, kty, x, y
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		base64.RawURLEncoding.EncodeToString(xb),
		base64.RawURLEncoding.EncodeToString(yb))
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (c *ACMEClient) keyAuthorization(token string) string {
	return token + "." + c.jwkThumbprint()
}

func (c *ACMEClient) popNonce() (string, error) {
	c.nonceMu.Lock()
	if len(c.nonces) > 0 {
		n := c.nonces[len(c.nonces)-1]
		c.nonces = c.nonces[:len(c.nonces)-1]
		c.nonceMu.Unlock()
		return n, nil
	}
	c.nonceMu.Unlock()

	resp, err := c.httpClient.Head(c.dir.NewNonce)
	if err != nil {
		return "", fmt.Errorf("ошибка получения Replay-Nonce: %w", err)
	}
	resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", fmt.Errorf("пустой Replay-Nonce от ACME-сервера")
	}
	return n, nil
}

func (c *ACMEClient) pushNonce(n string) {
	if n == "" {
		return
	}
	c.nonceMu.Lock()
	c.nonces = append(c.nonces, n)
	c.nonceMu.Unlock()
}

// signedPost executes an RFC 8555 JWS request (pass nil payload for POST-as-GET).
func (c *ACMEClient) signedPost(targetURL string, payload any, useJWK bool) ([]byte, http.Header, int, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		nonce, err := c.popNonce()
		if err != nil {
			return nil, nil, 0, err
		}

		protected := map[string]any{
			"alg":   "ES256",
			"nonce": nonce,
			"url":   targetURL,
		}
		if useJWK {
			protected["jwk"] = c.jwkMap()
		} else {
			protected["kid"] = c.kid
		}
		protJSON, err := json.Marshal(protected)
		if err != nil {
			return nil, nil, 0, err
		}
		protB64 := base64.RawURLEncoding.EncodeToString(protJSON)

		var payB64 string
		if payload != nil {
			payJSON, err := json.Marshal(payload)
			if err != nil {
				return nil, nil, 0, err
			}
			payB64 = base64.RawURLEncoding.EncodeToString(payJSON)
		}

		signingInput := protB64 + "." + payB64
		digest := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, c.accountKey, digest[:])
		if err != nil {
			return nil, nil, 0, err
		}
		sigBytes := make([]byte, 64)
		r.FillBytes(sigBytes[:32])
		s.FillBytes(sigBytes[32:])
		sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

		jwsBody, _ := json.Marshal(map[string]string{
			"protected": protB64,
			"payload":   payB64,
			"signature": sigB64,
		})

		req, err := http.NewRequest("POST", targetURL, bytes.NewReader(jwsBody))
		if err != nil {
			return nil, nil, 0, err
		}
		req.Header.Set("Content-Type", "application/jose+json")
		req.Header.Set("User-Agent", "KerioCertManager-Windows/1.0")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, nil, 0, err
		}
		c.pushNonce(resp.Header.Get("Replay-Nonce"))
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, 0, err
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return respBody, resp.Header, resp.StatusCode, nil
		}

		var prob acmeProblem
		if json.Unmarshal(respBody, &prob) == nil && prob.Type != "" {
			if strings.HasSuffix(prob.Type, ":badNonce") {
				lastErr = &prob
				continue
			}
			return respBody, resp.Header, resp.StatusCode, &prob
		}
		return respBody, resp.Header, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return nil, nil, 0, lastErr
}

// ExecuteCertificateIssuance handles full certificate generation for Self-Signed, Let's Encrypt Staging, and Let's Encrypt Production.
func ExecuteCertificateIssuance(req IssueRequest, log LogFunc) (*IssuedCertRecord, *PendingDNS01Session, error) {
	// 1. Parse & normalize domains and IP
	var asciiDomains []string
	var displayPrimary string
	rawList := []string{}
	if strings.TrimSpace(req.Domain) != "" {
		rawList = append(rawList, req.Domain)
	}
	rawList = append(rawList, req.ExtraDomains...)

	seen := map[string]bool{}
	for _, d := range rawList {
		if strings.TrimSpace(d) == "" {
			continue
		}
		ascii, disp, err := NormalizeDomain(d)
		if err != nil {
			return nil, nil, err
		}
		if !seen[ascii] {
			seen[ascii] = true
			asciiDomains = append(asciiDomains, ascii)
			if displayPrimary == "" {
				displayPrimary = disp
			}
		}
	}
	if len(asciiDomains) > 0 {
		req.Domain = asciiDomains[0]
	}

	parsedIP, ipValid, _, isPrivateIP := ClassifyIP(req.IPAddress)
	if len(asciiDomains) == 0 && !ipValid {
		return nil, nil, fmt.Errorf("укажите хотя бы корректное доменное имя (например, mail.company.by) или IP-адрес")
	}

	// Determine SAN IPs & ACME profile
	var csrIPs []net.IP
	useShortlived := false
	acmeProfile := "classic (90 дней)"

	if req.Mode == "selfsigned" {
		if ipValid {
			csrIPs = []net.IP{parsedIP}
		}
		acmeProfile = "local-selfsigned"
	} else {
		// Let's Encrypt Production or Staging
		if len(asciiDomains) == 0 || req.IncludeIPSAN {
			if !ipValid {
				return nil, nil, fmt.Errorf("для включения IP-адреса в SAN сертификата Let's Encrypt введите корректный публичный IPv4/IPv6 адрес")
			}
			if isPrivateIP {
				return nil, nil, fmt.Errorf("Let's Encrypt не выдаёт публичные IP-сертификаты на внутренние (частные RFC1918) адреса (%s). Отключите галочку «Включить IP в SAN» для выпуска стандартного 90-дневного доменного сертификата, либо выберите режим «Самоподписанный для Kerio»", req.IPAddress)
			}
			csrIPs = []net.IP{parsedIP}
			useShortlived = true
			acmeProfile = "shortlived (160 часов — DNS + IP SAN)"
			if req.ChallengeType == "dns-01" {
				return nil, nil, fmt.Errorf("по стандарту RFC 8738 сертификаты с IP-адресом в SAN проверяются только методами HTTP-01 (порт 80) или TLS-ALPN-01 (порт 443), а не через DNS-01")
			}
		}
	}

	// 2. Generate or reuse private key
	outRoot := strings.TrimSpace(req.OutputDir)
	if outRoot == "" {
		outRoot = DefaultCertsRoot()
	}
	slug := MakeCertSlug(req.Domain, req.IPAddress)
	existingKeyPath := filepath.Join(outRoot, slug, "server.key")

	var priv crypto.Signer
	var privPEM, privPKCS8PEM []byte
	var keyDesc string
	var err error

	if req.ReuseExistingKey {
		if rawKey, rerr := os.ReadFile(existingKeyPath); rerr == nil {
			if parsedSigner, perr := ParsePrivateKeyPEM(rawKey); perr == nil {
				priv = parsedSigner
				privPEM = rawKey
				if d8, merr := x509.MarshalPKCS8PrivateKey(priv); merr == nil {
					privPKCS8PEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: d8})
				}
				keyDesc = "Переиспользованный приватный ключ Kerio Connect"
				log("info", "Используется ранее сгенерированный приватный ключ из "+existingKeyPath)
			}
		}
	}
	if priv == nil {
		log("info", fmt.Sprintf("Генерация приватного ключа (%s) для Kerio Connect...", req.KeyType))
		priv, privPEM, privPKCS8PEM, keyDesc, err = GeneratePrivateKey(req.KeyType)
		if err != nil {
			return nil, nil, err
		}
		log("success", "Приватный ключ успешно сгенерирован: "+keyDesc)
	}

	csrDER, csrPEM, err := CreateCertificateCSR(priv, asciiDomains, csrIPs, useShortlived)
	if err != nil {
		return nil, nil, err
	}
	log("info", fmt.Sprintf("Сформирован запрос CSR (DNS SAN: %v, IP SAN: %v)", asciiDomains, csrIPs))

	// 3. Branch A: Instant local Self-Signed X.509 v3 certificate for Kerio Connect
	if req.Mode == "selfsigned" {
		log("info", "Выпуск локального X.509 v3 сертификата для Kerio Connect...")
		chainPEM, err := CreateSelfSignedKerioCert(priv, asciiDomains, csrIPs, req.ValidityDays)
		if err != nil {
			return nil, nil, err
		}
		rec, err := SaveKerioCertificateBundle(req, displayPrimary, acmeProfile, priv, privPEM, privPKCS8PEM, keyDesc, csrPEM, chainPEM)
		if err != nil {
			return nil, nil, err
		}
		log("success", fmt.Sprintf("Ключ и сертификат успешно сохранены в %s", rec.CertDir))
		if req.KerioInstall.Enabled {
			applyKerioPostInstall(rec, req.KerioInstall, log)
		}
		return rec, nil, nil
	}

	// 4. Branch B: Let's Encrypt ACME v2 (Staging or Production)
	accountStore := filepath.Join(outRoot, "_accounts")
	client, err := NewACMEClient(req.Mode, req.CustomDirectoryURL, req.Email, accountStore, log)
	if err != nil {
		return nil, nil, err
	}

	var identifiers []acmeIdentifier
	for _, d := range asciiDomains {
		identifiers = append(identifiers, acmeIdentifier{Type: "dns", Value: d})
	}
	for _, ip := range csrIPs {
		identifiers = append(identifiers, acmeIdentifier{Type: "ip", Value: ip.String()})
	}

	orderReq := map[string]any{
		"identifiers": identifiers,
	}
	if useShortlived {
		if _, exists := client.dir.Meta.Profiles["shortlived"]; exists || len(client.dir.Meta.Profiles) == 0 {
			orderReq["profile"] = "shortlived"
		}
		log("info", "Запрос ACME-заказа с профилем 'shortlived' (поддержка IP + домена)...")
	} else {
		log("info", fmt.Sprintf("Создание ACME-заказа для %v (привязка к серверу %s)...", asciiDomains, req.IPAddress))
	}

	orderBody, orderHdr, _, err := client.signedPost(client.dir.NewOrder, orderReq, false)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка создания ACME-заказа в Let's Encrypt: %w", err)
	}
	var order acmeOrder
	if err := json.Unmarshal(orderBody, &order); err != nil {
		return nil, nil, err
	}
	orderURL := orderHdr.Get("Location")
	log("info", fmt.Sprintf("ACME-заказ создан (статус: %s, авторизаций: %d)", order.Status, len(order.Authorizations)))

	challType := req.ChallengeType
	if challType == "" {
		challType = "http-01"
	}

	// Interactive 2-step DNS-01 mode
	if challType == "dns-01" {
		sessID := fmt.Sprintf("dns01-%d", time.Now().UnixNano())
		sess := &PendingDNS01Session{
			SessionID:     sessID,
			CreatedAt:     time.Now(),
			Request:       req,
			DisplayDomain: displayPrimary,
			ACMEProfile:   acmeProfile,
			OrderURL:      orderURL,
			FinalizeURL:   order.Finalize,
			Client:        client,
			PrivKey:       priv,
			PrivPEM:       privPEM,
			PrivPKCS8PEM:  privPKCS8PEM,
			KeyDesc:       keyDesc,
			CSRDER:        csrDER,
			CSRPEM:        csrPEM,
		}
		for _, authURL := range order.Authorizations {
			ab, _, _, err := client.signedPost(authURL, nil, false)
			if err != nil {
				return nil, nil, err
			}
			var auth acmeAuthorization
			if err := json.Unmarshal(ab, &auth); err != nil {
				return nil, nil, err
			}
			if auth.Status == "valid" {
				log("success", fmt.Sprintf("Домен %s уже авторизован в кэше Let's Encrypt!", auth.Identifier.Value))
				continue
			}
			var found *acmeChallenge
			for i := range auth.Challenges {
				if auth.Challenges[i].Type == "dns-01" {
					found = &auth.Challenges[i]
					break
				}
			}
			if found == nil {
				return nil, nil, fmt.Errorf("сервер Let's Encrypt не предложил dns-01 для %s", auth.Identifier.Value)
			}
			ka := client.keyAuthorization(found.Token)
			digest := sha256.Sum256([]byte(ka))
			txtVal := base64.RawURLEncoding.EncodeToString(digest[:])
			recName := "_acme-challenge." + strings.TrimPrefix(auth.Identifier.Value, "*.")
			sess.Records = append(sess.Records, DNS01RecordInstruction{
				Domain:   auth.Identifier.Value,
				Record:   recName,
				Type:     "TXT",
				TXTValue: txtVal,
				AuthURL:  authURL,
				ChallURL: found.URL,
			})
		}

		if len(sess.Records) == 0 {
			// All authorizations already cached as valid -> finalize right away!
			rec, err := finalizeAndSaveOrder(client, orderURL, order.Finalize, csrDER, csrPEM, req, displayPrimary, acmeProfile, priv, privPEM, privPKCS8PEM, keyDesc, log)
			return rec, nil, err
		}

		pendingDNS01Mu.Lock()
		pendingDNS01Sessions[sessID] = sess
		pendingDNS01Mu.Unlock()
		log("warning", "Для завершения выпуска добавьте указанные DNS TXT-записи у вашего DNS-провайдера и нажмите «Подтвердить DNS и завершить выпуск».")
		return nil, sess, nil
	}

	// Automated HTTP-01 / HTTP-01-Webroot / TLS-ALPN-01 Challenge Solver
	if err := solveAutomatedChallenges(client, order.Authorizations, req, log); err != nil {
		return nil, nil, err
	}

	rec, err := finalizeAndSaveOrder(client, orderURL, order.Finalize, csrDER, csrPEM, req, displayPrimary, acmeProfile, priv, privPEM, privPKCS8PEM, keyDesc, log)
	if err != nil {
		return nil, nil, err
	}
	return rec, nil, nil
}

func CompletePendingDNS01Session(sessionID string, log LogFunc) (*IssuedCertRecord, error) {
	pendingDNS01Mu.Lock()
	sess, ok := pendingDNS01Sessions[sessionID]
	pendingDNS01Mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("сессия DNS-01 (%s) не найдена или истекла — запустите выпуск заново", sessionID)
	}

	for _, r := range sess.Records {
		log("info", fmt.Sprintf("Отправка запроса проверки TXT-записи %s в Let's Encrypt...", r.Record))
		if _, _, _, err := sess.Client.signedPost(r.ChallURL, map[string]any{}, false); err != nil {
			return nil, fmt.Errorf("ошибка запуска проверки %s: %w", r.Record, err)
		}
		if err := pollAuthorizationValid(sess.Client, r.AuthURL, r.Domain, log); err != nil {
			return nil, err
		}
	}

	pendingDNS01Mu.Lock()
	delete(pendingDNS01Sessions, sessionID)
	pendingDNS01Mu.Unlock()

	return finalizeAndSaveOrder(
		sess.Client,
		sess.OrderURL,
		sess.FinalizeURL,
		sess.CSRDER,
		sess.CSRPEM,
		sess.Request,
		sess.DisplayDomain,
		sess.ACMEProfile,
		sess.PrivKey,
		sess.PrivPEM,
		sess.PrivPKCS8PEM,
		sess.KeyDesc,
		log,
	)
}

func solveAutomatedChallenges(client *ACMEClient, authURLs []string, req IssueRequest, log LogFunc) error {
	challType := req.ChallengeType
	if challType == "" {
		challType = "http-01"
	}

	// Optional automatic pause/resume of KerioMailServer service if port 80/443 is occupied by Kerio
	if req.StopKerioTemp {
		log("warning", "Временная остановка службы KerioMailServer для освобождения порта проверки...")
		if err := PlatformControlKerioService("stop"); err != nil {
			log("warning", fmt.Sprintf("Не удалось остановить KerioMailServer (%v) — продолжаем попытку привязки порта...", err))
		} else {
			log("info", "Служба KerioMailServer временно остановлена (будет автоматически запущена сразу после проверки).")
			defer func() {
				log("info", "Обратный запуск службы KerioMailServer...")
				if rerr := PlatformControlKerioService("start"); rerr != nil {
					log("error", "Внимание: не удалось автоматически запустить KerioMailServer: "+rerr.Error())
				} else {
					log("success", "Служба KerioMailServer успешно запущена обратно!")
				}
			}()
		}
	}

	httpTokens := map[string]string{}
	var httpMu sync.RWMutex
	var httpSrv *http.Server

	tlsCerts := map[string]*tls.Certificate{}
	var tlsMu sync.RWMutex
	var tlsLn net.Listener

	var createdWebrootFiles []string
	defer func() {
		for _, f := range createdWebrootFiles {
			_ = os.Remove(f)
		}
		if httpSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = httpSrv.Shutdown(ctx)
			cancel()
		}
		if tlsLn != nil {
			_ = tlsLn.Close()
		}
	}()

	bindIP, isNAT := ResolveEffectiveBindIP(req.IPAddress, req.BindIP)
	if isNAT {
		log("info", fmt.Sprintf("Режим NAT: внешний IP %s пробрасывается маршрутизатором -> слушаем локально на %s", req.IPAddress, bindIP))
	}

	if challType == "http-01" {
		port := req.HTTPPort
		if port <= 0 {
			port = 80
		}
		addr := net.JoinHostPort(bindIP, fmt.Sprintf("%d", port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("не удалось занять порт %s для HTTP-01 проверки Let's Encrypt: %w (запустите программу от имени Администратора и убедитесь, что порт 80 не занят Kerio/IIS, либо включите опцию временной остановки KerioMailServer)", addr, err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
			tok := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
			httpMu.RLock()
			val, ok := httpTokens[tok]
			httpMu.RUnlock()
			log("info", fmt.Sprintf("Входящий HTTP-01 запрос проверки от %s для токена %s...", r.RemoteAddr, tok[:minInt(len(tok), 12)]))
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(val))
		})
		httpSrv = &http.Server{Handler: mux}
		go func() { _ = httpSrv.Serve(ln) }()
		log("success", fmt.Sprintf("Встроенный HTTP-01 сервер проверки запущен на %s", addr))
	} else if challType == "tls-alpn-01" {
		port := req.TLSPort
		if port <= 0 {
			port = 443
		}
		addr := net.JoinHostPort(bindIP, fmt.Sprintf("%d", port))
		tlsCfg := &tls.Config{
			NextProtos: []string{"acme-tls/1"},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				tlsMu.RLock()
				defer tlsMu.RUnlock()
				key := strings.ToLower(strings.TrimSpace(hello.ServerName))
				if cert, ok := tlsCerts[key]; ok {
					return cert, nil
				}
				// For RFC 8738 IP validation where SNI may be empty, check local addr or single active cert
				for _, cert := range tlsCerts {
					return cert, nil
				}
				return nil, fmt.Errorf("сертификат проверки acme-tls/1 не найден")
			},
		}
		ln, err := tls.Listen("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("не удалось занять порт %s для TLS-ALPN-01 проверки: %w", addr, err)
		}
		tlsLn = ln
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					_ = c.(*tls.Conn).Handshake()
					_ = c.Close()
				}(conn)
			}
		}()
		log("success", fmt.Sprintf("Встроенный TLS-ALPN-01 сервер проверки запущен на %s", addr))
	}

	acmeWantType := challType
	if challType == "http-01-webroot" {
		acmeWantType = "http-01"
	}

	for _, authURL := range authURLs {
		ab, _, _, err := client.signedPost(authURL, nil, false)
		if err != nil {
			return err
		}
		var auth acmeAuthorization
		if err := json.Unmarshal(ab, &auth); err != nil {
			return err
		}
		if auth.Status == "valid" {
			log("success", fmt.Sprintf("Идентификатор %s:%s уже подтверждён!", auth.Identifier.Type, auth.Identifier.Value))
			continue
		}

		var chosen *acmeChallenge
		for i := range auth.Challenges {
			if auth.Challenges[i].Type == acmeWantType {
				chosen = &auth.Challenges[i]
				break
			}
		}
		if chosen == nil {
			return fmt.Errorf("метод %s недоступен для %s:%s", acmeWantType, auth.Identifier.Type, auth.Identifier.Value)
		}

		ka := client.keyAuthorization(chosen.Token)
		switch challType {
		case "http-01":
			httpMu.Lock()
			httpTokens[chosen.Token] = ka
			httpMu.Unlock()

		case "http-01-webroot":
			if strings.TrimSpace(req.WebrootPath) == "" {
				return fmt.Errorf("укажите путь к папке Webroot (например, C:\\inetpub\\wwwroot)")
			}
			challDir := filepath.Join(req.WebrootPath, ".well-known", "acme-challenge")
			if err := os.MkdirAll(challDir, 0755); err != nil {
				return fmt.Errorf("ошибка создания папки %s: %w", challDir, err)
			}
			fp := filepath.Join(challDir, chosen.Token)
			if err := os.WriteFile(fp, []byte(ka), 0644); err != nil {
				return fmt.Errorf("ошибка записи файла проверки %s: %w", fp, err)
			}
			createdWebrootFiles = append(createdWebrootFiles, fp)
			log("info", "Записан токен проверки в Webroot: "+fp)

		case "tls-alpn-01":
			alpnCert, err := buildTLSALPNValidationCert(auth.Identifier, ka)
			if err != nil {
				return err
			}
			tlsMu.Lock()
			tlsCerts[strings.ToLower(auth.Identifier.Value)] = alpnCert
			tlsMu.Unlock()
		}

		log("info", fmt.Sprintf("Запуск проверки владения %s (%s)...", auth.Identifier.Value, acmeWantType))
		if _, _, _, err := client.signedPost(chosen.URL, map[string]any{}, false); err != nil {
			return fmt.Errorf("ошибка активации challenge для %s: %w", auth.Identifier.Value, err)
		}
		if err := pollAuthorizationValid(client, authURL, auth.Identifier.Value, log); err != nil {
			return err
		}
	}
	return nil
}

// buildTLSALPNValidationCert builds an ephemeral RFC 8737 / RFC 8738 validation certificate with critical id-pe-acmeIdentifier (1.3.6.1.5.5.7.1.31).
func buildTLSALPNValidationCert(id acmeIdentifier, keyAuth string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(keyAuth))
	extVal, err := asn1.Marshal(digest[:])
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31},
				Critical: true,
				Value:    extVal,
			},
		},
	}
	if id.Type == "ip" {
		if ip := net.ParseIP(id.Value); ip != nil {
			tpl.IPAddresses = []net.IP{ip}
		}
	} else {
		tpl.DNSNames = []string{id.Value}
		tpl.Subject.CommonName = id.Value
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

func pollAuthorizationValid(client *ACMEClient, authURL, label string, log LogFunc) error {
	deadline := time.Now().Add(95 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		ab, _, _, err := client.signedPost(authURL, nil, false)
		if err != nil {
			return err
		}
		var auth acmeAuthorization
		if err := json.Unmarshal(ab, &auth); err != nil {
			return err
		}
		switch auth.Status {
		case "valid":
			log("success", fmt.Sprintf("Подтверждение %s успешно пройдено!", label))
			return nil
		case "invalid":
			detail := "проверка отклонена сервером Let's Encrypt"
			for _, ch := range auth.Challenges {
				if ch.Error != nil {
					detail = ch.Error.Error()
					break
				}
			}
			return fmt.Errorf("не удалось подтвердить %s: %s (проверьте, что DNS-запись указывает на введённый IP и порт 80 открыт из интернета)", label, detail)
		}
	}
	return fmt.Errorf("превышено время ожидания проверки %s", label)
}

func finalizeAndSaveOrder(
	client *ACMEClient,
	orderURL string,
	finalizeURL string,
	csrDER []byte,
	csrPEM []byte,
	req IssueRequest,
	displayPrimary string,
	acmeProfile string,
	priv crypto.Signer,
	privPEM []byte,
	privPKCS8PEM []byte,
	keyDesc string,
	log LogFunc,
) (*IssuedCertRecord, error) {
	log("info", "Отправка запроса CSR на подпись в удостоверяющий центр Let's Encrypt...")
	finPayload := map[string]string{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	}
	finBody, _, _, err := client.signedPost(finalizeURL, finPayload, false)
	if err != nil {
		return nil, fmt.Errorf("ошибка финализации CSR: %w", err)
	}
	var ord acmeOrder
	_ = json.Unmarshal(finBody, &ord)

	deadline := time.Now().Add(90 * time.Second)
	for ord.Status != "valid" || ord.Certificate == "" {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("превышено время ожидания выпуска сертификата (последний статус: %s)", ord.Status)
		}
		if ord.Status == "invalid" {
			if ord.Error != nil {
				return nil, fmt.Errorf("выпуск отклонён: %w", ord.Error)
			}
			return nil, fmt.Errorf("заказ перешёл в статус invalid")
		}
		time.Sleep(2 * time.Second)
		if orderURL == "" {
			break
		}
		ob, _, _, err := client.signedPost(orderURL, nil, false)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(ob, &ord); err != nil {
			return nil, err
		}
	}

	log("info", "Скачивание подписанного сертификата и промежуточной цепочки CA...")
	certPEMBytes, _, _, err := client.signedPost(ord.Certificate, nil, false)
	if err != nil {
		return nil, fmt.Errorf("ошибка скачивания сертификата: %w", err)
	}

	rec, err := SaveKerioCertificateBundle(req, displayPrimary, acmeProfile, priv, privPEM, privPKCS8PEM, keyDesc, csrPEM, certPEMBytes)
	if err != nil {
		return nil, err
	}
	log("success", fmt.Sprintf("Сертификат Let's Encrypt успешно выпущен и сохранён в %s!", rec.CertDir))

	if req.KerioInstall.Enabled {
		applyKerioPostInstall(rec, req.KerioInstall, log)
	}
	return rec, nil
}

func applyKerioPostInstall(rec *IssuedCertRecord, cfg KerioInstallConfig, log LogFunc) {
	note, err := InstallCertificateToKerio(rec, cfg, log)
	if err != nil {
		log("error", "Ошибка автоустановки в Kerio Connect: "+err.Error())
		rec.KerioInstallNote = "Ошибка: " + err.Error()
	} else {
		rec.KerioInstalled = true
		rec.KerioInstallNote = note
		log("success", note)
	}
	if b, merr := json.MarshalIndent(rec, "", "  "); merr == nil {
		_ = os.WriteFile(filepath.Join(rec.CertDir, "metadata.json"), b, 0600)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
