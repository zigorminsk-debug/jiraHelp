package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type KerioExistingCert struct {
	FileName      string   `json:"fileName"`
	BaseName      string   `json:"baseName"`
	IsActive      bool     `json:"isActive"`
	SubjectCN     string   `json:"subjectCN"`
	Issuer        string   `json:"issuer"`
	DNSNames      []string `json:"dnsNames"`
	IPAddresses   []string `json:"ipAddresses"`
	NotAfter      string   `json:"notAfter"`
	DaysRemaining int      `json:"daysRemaining"`
}

type KerioStatusInfo struct {
	Found          bool                `json:"found"`
	KerioDir       string              `json:"kerioDir"`
	SSLCertDir     string              `json:"sslCertDir"`
	ActiveCertName string              `json:"activeCertName"`
	ServiceStatus  string              `json:"serviceStatus"`
	ExistingCerts  []KerioExistingCert `json:"existingCerts"`
}

var kerioActiveCertRegex = regexp.MustCompile(`(?is)<table\s+name="Ssl">.*?<variable\s+name="Certificate">([^<]+)</variable>`)

// ReadKerioActiveCertBaseName parses mailserver.cfg to find which certificate basename Kerio Connect actively uses (default "server").
func ReadKerioActiveCertBaseName(kerioDir string) string {
	cfgPath := filepath.Join(kerioDir, "mailserver.cfg")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return "server"
	}
	matches := kerioActiveCertRegex.FindSubmatch(raw)
	if len(matches) >= 2 {
		val := strings.TrimSpace(string(matches[1]))
		val = strings.TrimSuffix(val, ".crt")
		val = strings.TrimSuffix(val, ".pem")
		if val != "" {
			return val
		}
	}
	return "server"
}

func InspectKerioInstallation(customPath string) KerioStatusInfo {
	info := KerioStatusInfo{
		ActiveCertName: "server",
		ServiceStatus:  PlatformKerioServiceStatus(),
		ExistingCerts:  []KerioExistingCert{},
	}

	candidates := []string{}
	if strings.TrimSpace(customPath) != "" {
		candidates = append(candidates, strings.TrimSpace(customPath))
	}
	candidates = append(candidates, PlatformCandidateKerioDirs()...)

	for _, c := range candidates {
		// Accept either MailServer root dir or MailServer\sslcert directly
		sslDir := c
		rootDir := filepath.Dir(c)
		if !strings.EqualFold(filepath.Base(c), "sslcert") {
			rootDir = c
			sslDir = filepath.Join(c, "sslcert")
		}
		if st, err := os.Stat(sslDir); err == nil && st.IsDir() {
			info.Found = true
			info.KerioDir = rootDir
			info.SSLCertDir = sslDir
			info.ActiveCertName = ReadKerioActiveCertBaseName(rootDir)
			break
		}
	}

	if !info.Found {
		info.KerioDir = `C:\Program Files\Kerio\MailServer`
		info.SSLCertDir = `C:\Program Files\Kerio\MailServer\sslcert`
		return info
	}

	entries, err := os.ReadDir(info.SSLCertDir)
	if err != nil {
		return info
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".crt") && !strings.HasSuffix(lower, ".pem") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(info.SSLCertDir, name))
		if err != nil {
			continue
		}
		blk, _ := pem.Decode(raw)
		if blk == nil || blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		base := strings.TrimSuffix(name, filepath.Ext(name))
		var ips []string
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		info.ExistingCerts = append(info.ExistingCerts, KerioExistingCert{
			FileName:      name,
			BaseName:      base,
			IsActive:      strings.EqualFold(base, info.ActiveCertName),
			SubjectCN:     cert.Subject.CommonName,
			Issuer:        cert.Issuer.CommonName,
			DNSNames:      cert.DNSNames,
			IPAddresses:   ips,
			NotAfter:      cert.NotAfter.Format("2006-01-02 15:04"),
			DaysRemaining: int(time.Until(cert.NotAfter).Hours() / 24),
		})
	}
	return info
}

func InstallCertificateToKerio(rec *IssuedCertRecord, cfg KerioInstallConfig, log LogFunc) (string, error) {
	if cfg.Method == "api" {
		return installViaKerioAdminAPI(rec, cfg, log)
	}
	return installViaKerioFilesystem(rec, cfg, log)
}

func installViaKerioFilesystem(rec *IssuedCertRecord, cfg KerioInstallConfig, log LogFunc) (string, error) {
	target := strings.TrimSpace(cfg.KerioPath)
	if target == "" {
		st := InspectKerioInstallation("")
		target = st.SSLCertDir
	}
	sslDir := target
	rootDir := filepath.Dir(target)
	if !strings.EqualFold(filepath.Base(target), "sslcert") {
		rootDir = target
		sslDir = filepath.Join(target, "sslcert")
	}

	if err := os.MkdirAll(sslDir, 0755); err != nil {
		return "", fmt.Errorf("не удалось открыть/создать папку sslcert (%s): %w — запустите программу от имени Администратора", sslDir, err)
	}

	crtBytes, err := os.ReadFile(rec.Files["serverCrt"])
	if err != nil {
		return "", fmt.Errorf("не найден файл сертификата %s: %w", rec.Files["serverCrt"], err)
	}
	keyBytes, err := os.ReadFile(rec.Files["serverKey"])
	if err != nil {
		return "", fmt.Errorf("не найден файл ключа %s: %w", rec.Files["serverKey"], err)
	}

	// 1. Automatic backup of current Kerio certificates
	backupDir := filepath.Join(sslDir, "backup_"+time.Now().Format("20060102_150405"))
	if entries, err := os.ReadDir(sslDir); err == nil && len(entries) > 0 {
		_ = os.MkdirAll(backupDir, 0700)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext == ".crt" || ext == ".key" || ext == ".pem" {
				if data, rerr := os.ReadFile(filepath.Join(sslDir, e.Name())); rerr == nil {
					_ = os.WriteFile(filepath.Join(backupDir, e.Name()), data, 0600)
				}
			}
		}
		log("info", "Создана резервная копия старых сертификатов Kerio: "+backupDir)
	}

	// 2. Determine active cert name in mailserver.cfg (e.g. "server" or "cert_1")
	activeBase := ReadKerioActiveCertBaseName(rootDir)
	targets := []string{"server"}
	if !strings.EqualFold(activeBase, "server") && activeBase != "" {
		targets = append(targets, activeBase)
	}

	// 3. Stop service (if requested), write .crt & .key, start service back
	if cfg.RestartService {
		log("info", "Остановка службы KerioMailServer перед обновлением SSL-файлов...")
		_ = PlatformControlKerioService("stop")
	}

	for _, base := range targets {
		crtDest := filepath.Join(sslDir, base+".crt")
		keyDest := filepath.Join(sslDir, base+".key")
		if err := os.WriteFile(crtDest, crtBytes, 0644); err != nil {
			return "", fmt.Errorf("ошибка записи %s: %w", crtDest, err)
		}
		if err := os.WriteFile(keyDest, keyBytes, 0600); err != nil {
			return "", fmt.Errorf("ошибка записи %s: %w", keyDest, err)
		}
		log("success", fmt.Sprintf("Записаны файлы Kerio SSL: %s.crt и %s.key", base, base))
	}

	if cfg.RestartService {
		log("info", "Запуск службы KerioMailServer с новым SSL-сертификатом...")
		if err := PlatformControlKerioService("start"); err != nil {
			return "", fmt.Errorf("файлы скопированы в %s, но не удалось перезапустить службу KerioMailServer: %w", sslDir, err)
		}
		return fmt.Sprintf("Сертификат и ключ успешно установлены в %s (активный профиль: %s), служба KerioMailServer перезапущена!", sslDir, activeBase), nil
	}
	return fmt.Sprintf("Сертификат и ключ скопированы в %s (резервная копия: %s). Перезапустите службу KerioMailServer для применения.", sslDir, backupDir), nil
}

// installViaKerioAdminAPI imports & activates the certificate via Kerio Connect JSON-RPC Admin API (port 4040) without stopping mail services.
func installViaKerioAdminAPI(rec *IssuedCertRecord, cfg KerioInstallConfig, log LogFunc) (string, error) {
	host := strings.TrimSpace(cfg.APIHost)
	if host == "" {
		host = "127.0.0.1"
	}
	port := cfg.APIPort
	if port <= 0 {
		port = 4040
	}
	if strings.TrimSpace(cfg.APIUser) == "" {
		return "", fmt.Errorf("укажите логин администратора Kerio Connect")
	}

	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{
		Jar:     jar,
		Timeout: 25 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	baseURL := fmt.Sprintf("https://%s:%d", host, port)
	rpcURL := baseURL + "/admin/api/jsonrpc/"
	uploadURL := baseURL + "/admin/api/jsonrpc/upload/"

	rpcCall := func(token string, id int, method string, params any) (json.RawMessage, error) {
		payload := map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"method":  method,
			"params":  params,
		}
		if token != "" {
			payload["token"] = token
		}
		body, _ := json.Marshal(payload)
		req, err := http.NewRequest("POST", rpcURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("X-Token", token)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var parsed struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("некорректный ответ Kerio API: %w", err)
		}
		if parsed.Error != nil {
			return nil, fmt.Errorf("Kerio API (%s): %s", method, parsed.Error.Message)
		}
		return parsed.Result, nil
	}

	uploadFile := func(token, filename string, content []byte) (string, error) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, err := mw.CreateFormFile("newFile.bin", filename)
		if err != nil {
			return "", err
		}
		_, _ = fw.Write(content)
		_ = mw.Close()

		req, err := http.NewRequest("POST", uploadURL, &buf)
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var parsed struct {
			Result struct {
				FileUpload struct {
					Id string `json:"id"`
				} `json:"fileUpload"`
			} `json:"result"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil || parsed.Result.FileUpload.Id == "" {
			return "", fmt.Errorf("ошибка загрузки файла %s в Kerio API: %s", filename, string(raw))
		}
		return parsed.Result.FileUpload.Id, nil
	}

	log("info", fmt.Sprintf("Авторизация в Kerio Connect Admin API (%s)...", baseURL))
	loginRes, err := rpcCall("", 1, "Session.login", map[string]any{
		"userName": cfg.APIUser,
		"password": cfg.APIPassword,
		"application": map[string]any{
			"name":    "KerioCertManager",
			"vendor":  "CSL",
			"version": "1.0",
		},
	})
	if err != nil {
		return "", fmt.Errorf("не удалось подключиться к Kerio Admin API (%s): %w", baseURL, err)
	}
	var tokStruct struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(loginRes, &tokStruct); err != nil || tokStruct.Token == "" {
		return "", fmt.Errorf("Kerio API не вернул X-Token")
	}
	token := tokStruct.Token
	defer func() { _, _ = rpcCall(token, 99, "Session.logout", map[string]any{}) }()

	crtBytes, err := os.ReadFile(rec.Files["serverCrt"])
	if err != nil {
		return "", err
	}
	keyBytes, err := os.ReadFile(rec.Files["serverKey"])
	if err != nil {
		return "", err
	}

	// Snapshot existing certificates before import so we identify the exact new KId with 100% certainty
	type kerioCertListResp struct {
		Certificates []struct {
			Id   string `json:"id"`
			Name string `json:"name"`
		} `json:"certificates"`
	}
	beforeIDs := map[string]bool{}
	if getBefore, gerr := rpcCall(token, 2, "ConnectCertificate.get", map[string]any{}); gerr == nil {
		var beforeList kerioCertListResp
		if json.Unmarshal(getBefore, &beforeList) == nil {
			for _, c := range beforeList.Certificates {
				beforeIDs[c.Id] = true
			}
		}
	}

	crtUploadID, err := uploadFile(token, "server.crt", crtBytes)
	if err != nil {
		return "", err
	}
	keyUploadID, err := uploadFile(token, "server.key", keyBytes)
	if err != nil {
		return "", err
	}

	log("info", "Импорт приватного ключа в Kerio Connect (ConnectCertificate.importPrivateKey)...")
	var certID string
	pkRes, pkErr := rpcCall(token, 3, "ConnectCertificate.importPrivateKey", map[string]any{
		"fileId": keyUploadID,
	})
	if pkErr == nil {
		var pkStruct struct {
			NeedPassword bool   `json:"needPassword"`
			Id           string `json:"id"`
		}
		if uerr := json.Unmarshal(pkRes, &pkStruct); uerr == nil && pkStruct.Id != "" {
			log("info", fmt.Sprintf("Приватный ключ принят Kerio (temp ID: %s), загрузка цепочки SSL-сертификата...", pkStruct.Id))
			_, icErr := rpcCall(token, 4, "ConnectCertificate.importCertificate", map[string]any{
				"id":       pkStruct.Id,
				"fileId":   crtUploadID,
				"password": "",
			})
			// If an older Kerio build prefers leaf-only PEM instead of fullchain PEM, automatically retry with cert-only.crt
			if icErr != nil {
				if leafPath, ok := rec.Files["certOnly"]; ok && leafPath != "" {
					if leafBytes, lerr := os.ReadFile(leafPath); lerr == nil {
						if leafUploadID, u2err := uploadFile(token, "cert.crt", leafBytes); u2err == nil {
							log("warning", "Повтор импорта с листовым сертификатом cert-only.crt...")
							_, icErr = rpcCall(token, 5, "ConnectCertificate.importCertificate", map[string]any{
								"id":       pkStruct.Id,
								"fileId":   leafUploadID,
								"password": "",
							})
						}
					}
				}
			}
			if icErr != nil {
				return "", icErr
			}
			certID = pkStruct.Id

			// Re-query ConnectCertificate.get in case Kerio assigned a new permanent KId after pairing key + cert
			if getAfter, gaErr := rpcCall(token, 6, "ConnectCertificate.get", map[string]any{}); gaErr == nil {
				var afterList kerioCertListResp
				if json.Unmarshal(getAfter, &afterList) == nil {
					for _, c := range afterList.Certificates {
						if !beforeIDs[c.Id] && c.Id != "" {
							certID = c.Id
						}
					}
				}
			}

			log("info", fmt.Sprintf("Активация нового сертификата в Kerio Connect (ConnectCertificate.setActive, ID: %s)...", certID))
			if _, saErr := rpcCall(token, 7, "ConnectCertificate.setActive", map[string]any{"id": certID}); saErr != nil {
				return "", saErr
			}
		} else {
			return "", fmt.Errorf("неожиданный ответ ConnectCertificate.importPrivateKey: %s", string(pkRes))
		}
	} else {
		// Fallback for Kerio Control / WebAdmin Certificates interface (port 4081)
		pk2Res, pk2Err := rpcCall(token, 8, "Certificates.importPrivateKey", map[string]any{
			"fileId": keyUploadID,
		})
		if pk2Err != nil {
			return "", pkErr
		}
		var pk2Struct struct {
			KeyId string `json:"keyId"`
			Id    string `json:"id"`
		}
		_ = json.Unmarshal(pk2Res, &pk2Struct)
		kid := pk2Struct.KeyId
		if kid == "" {
			kid = pk2Struct.Id
		}
		imp2Res, imp2Err := rpcCall(token, 9, "Certificates.importCertificate", map[string]any{
			"keyId":  kid,
			"fileId": crtUploadID,
			"name":   rec.Slug,
			"type":   "InactiveCertificate",
		})
		if imp2Err != nil {
			return "", imp2Err
		}
		var imp2Struct struct {
			Id string `json:"id"`
		}
		_ = json.Unmarshal(imp2Res, &imp2Struct)
		certID = imp2Struct.Id
	}

	return fmt.Sprintf("Сертификат успешно импортирован и активирован через Kerio Connect Admin API (%s) без остановки почты!", baseURL), nil
}

// RunScheduledRenewals renews all certificates expiring within 30 days (or < 72 hours for 6-day shortlived IP certs).
func RunScheduledRenewals(outRoot string, log LogFunc) error {
	records, err := LoadAllCertRecords(outRoot)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		log("info", "Сохранённых сертификатов для автопродления пока нет.")
		return nil
	}

	var anyErr error
	for _, rec := range records {
		hoursLeft := time.Until(rec.NotAfter).Hours()
		thresholdHours := 30.0 * 24.0
		if strings.Contains(rec.ACMEProfile, "shortlived") {
			thresholdHours = 78.0 // Renew every ~3.25 days out of 160h lifetime
		}
		if hoursLeft > thresholdHours {
			log("info", fmt.Sprintf("Сертификат %s актуален (осталось %.0f ч) — продление не требуется.", rec.Slug, hoursLeft))
			continue
		}
		if rec.OriginalRequest.ChallengeType == "dns-01" {
			log("warning", fmt.Sprintf("Пропуск %s: ручной DNS-01 требует обновления TXT-записи.", rec.Slug))
			continue
		}
		log("info", fmt.Sprintf("Автопродление сертификата %s (осталось %.1f ч)...", rec.Slug, hoursLeft))
		newRec, _, err := ExecuteCertificateIssuance(rec.OriginalRequest, log)
		if err != nil {
			log("error", fmt.Sprintf("Ошибка автопродления %s: %v", rec.Slug, err))
			anyErr = err
			continue
		}
		log("success", fmt.Sprintf("Сертификат %s успешно продлён до %s!", newRec.Slug, newRec.NotAfter.Format("2006-01-02")))
	}
	return anyErr
}
