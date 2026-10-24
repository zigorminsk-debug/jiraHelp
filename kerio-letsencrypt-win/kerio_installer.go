package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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

// installViaKerioAdminAPI импортирует и активирует сертификат через
// Kerio Connect JSON-RPC Admin API (порт 4040) без остановки почтовых служб.
func installViaKerioAdminAPI(rec *IssuedCertRecord, cfg KerioInstallConfig, log LogFunc) (string, error) {
	host, port := NormalizeKerioHost(cfg.APIHost, cfg.APIPort)
	if strings.TrimSpace(cfg.APIUser) == "" {
		return "", fmt.Errorf("укажите логин администратора Kerio Connect (обычно admin)")
	}
	ep := KerioEndpoint{Host: host, Port: port}
	cli := NewKerioClient(ep)
	cli.Log = log

	log("info", fmt.Sprintf("Авторизация в Kerio Connect Admin API (%s)...", ep.RPCURL()))
	if err := cli.Login(cfg.APIUser, cfg.APIPassword, rec.PrimaryDomain); err != nil {
		log("error", err.Error())
		return "", kerioInstallHint(err)
	}
	defer cli.Logout()
	log("success", "Вход администратора Kerio выполнен: "+cli.User)

	if who, werr := cli.WhoAmI(); werr == nil && !who.IsAdmin {
		return "", kerioInstallHint(&KerioAPIError{
			Kind: "rights", Method: "Session.whoAmI",
			Message: fmt.Sprintf("учётная запись %s вошла, но не является администратором Kerio Connect (роль: %s)", who.LoginName, who.Role),
			Fix: "1) Configuration → Administration → Administrators — добавьте эту учётку в администраторы.\n" +
				"2) Используйте мастер-администратора (обычно admin), а не пользователя домена.\n" +
				"3) Делегированный администратор без прав на SSL-сертификаты импорт выполнить не сможет.",
		})
	}

	crtBytes, err := os.ReadFile(rec.Files["serverCrt"])
	if err != nil {
		return "", fmt.Errorf("не найден файл сертификата %s: %w", rec.Files["serverCrt"], err)
	}
	keyBytes, err := os.ReadFile(rec.Files["serverKey"])
	if err != nil {
		return "", fmt.Errorf("не найден файл ключа %s: %w", rec.Files["serverKey"], err)
	}

	beforeIDs := map[string]bool{}
	if before, _, berr := cli.ListCertificates(); berr == nil {
		for _, c := range before {
			beforeIDs[c.ID] = true
		}
		log("info", fmt.Sprintf("На сервере Kerio уже установлено сертификатов: %d", len(before)))
	} else {
		log("warning", "Не удалось заранее прочитать список сертификатов Kerio: "+berr.Error())
	}

	log("info", "Загрузка сертификата на сервер Kerio (POST /admin/api/jsonrpc/upload/)...")
	crtUploadID, err := cli.UploadFile("server.crt", crtBytes)
	if err != nil {
		return "", kerioInstallHint(err)
	}
	keyUploadID, err := cli.UploadFile("server.key", keyBytes)
	if err != nil {
		return "", kerioInstallHint(err)
	}
	log("success", fmt.Sprintf("Файлы загружены в Kerio (cert fileId: %s, key fileId: %s)", crtUploadID, keyUploadID))

	log("info", "Импорт приватного ключа (ConnectCertificate.importPrivateKey)...")
	pkRaw, pkErr := cli.rpc("ConnectCertificate.importPrivateKey", map[string]any{"fileId": keyUploadID})
	if pkErr != nil {
		if kerioErrKind(pkErr) == "method" {
			log("warning", "Интерфейс ConnectCertificate недоступен — используем Certificates.* (WebAdmin)")
			return installViaKerioWebAdminCerts(cli, rec, crtUploadID, keyUploadID, beforeIDs, log)
		}
		return "", kerioInstallHint(pkErr)
	}

	var pk struct {
		NeedPassword bool   `json:"needPassword"`
		Id           string `json:"id"`
	}
	_ = json.Unmarshal(pkRaw, &pk)
	if strings.TrimSpace(pk.Id) == "" {
		return "", kerioInstallHint(&KerioAPIError{
			Kind: "protocol", Method: "ConnectCertificate.importPrivateKey",
			Message: "Kerio не вернул временный ID ключа: " + truncateText(string(pkRaw), 200),
			Fix:     "Сертификат не импортирован. Проверьте, что на порту 4040 работает Kerio Connect 8.5+ и что учётка — администратор.",
		})
	}
	if pk.NeedPassword {
		return "", kerioInstallHint(&KerioAPIError{
			Kind: "protocol", Method: "ConnectCertificate.importPrivateKey",
			Message: "Kerio считает приватный ключ зашифрованным паролем (needPassword=true).",
			Fix:     "Экспортируйте ключ без пароля (PEM, unencrypted) или выберите другой сертификат из списка.",
		})
	}
	log("success", "Приватный ключ принят Kerio, временный ID: "+pk.Id)

	log("info", "Импорт цепочки SSL-сертификата (ConnectCertificate.importCertificate)...")
	_, icErr := cli.rpc("ConnectCertificate.importCertificate", map[string]any{
		"id":       pk.Id,
		"fileId":   crtUploadID,
		"password": "",
	})
	if icErr != nil {
		// Старые сборки Kerio иногда принимают только листовой сертификат без цепочки.
		if leafPath := strings.TrimSpace(rec.Files["certOnly"]); leafPath != "" {
			if leafBytes, lerr := os.ReadFile(leafPath); lerr == nil {
				if leafID, uerr := cli.UploadFile("cert.crt", leafBytes); uerr == nil {
					log("warning", "Повтор импорта листовым сертификатом cert-only.crt...")
					_, icErr = cli.rpc("ConnectCertificate.importCertificate", map[string]any{
						"id":       pk.Id,
						"fileId":   leafID,
						"password": "",
					})
				}
			}
		}
	}
	if icErr != nil {
		return "", kerioInstallHint(icErr)
	}

	certID := pk.Id
	if after, _, lerr := cli.ListCertificates(); lerr == nil {
		if id := findNewKerioCertID(after, beforeIDs, rec.SHA256Fingerprint); id != "" {
			certID = id
		}
	}

	log("info", fmt.Sprintf("Активация нового сертификата (ConnectCertificate.setActive, ID: %s)...", certID))
	if _, saErr := cli.rpc("ConnectCertificate.setActive", map[string]any{"id": certID}); saErr != nil {
		return "", kerioInstallHint(saErr)
	}

	verifyNote := ""
	if after, _, lerr := cli.ListCertificates(); lerr == nil {
		if active := findActiveKerioCert(after); active != nil {
			if kerioCertMatches(*active, rec, certID) {
				verifyNote = fmt.Sprintf(" Kerio подтвердил активный сертификат «%s» (действует до %s).", active.Name, active.ValidTo)
			} else {
				verifyNote = fmt.Sprintf(" Внимание: Kerio показывает активным «%s» — откройте Configuration → SSL Certificates и проверьте.", active.Name)
			}
		}
	}
	return fmt.Sprintf("Сертификат установлен и активирован через Kerio Connect Admin API (%s) без остановки почты.%s", ep.RPCURL(), verifyNote), nil
}

// installViaKerioWebAdminCerts — резервный путь для сборок Kerio Connect/Control,
// где используется интерфейс Certificates.* (WebAdmin SSL Certificates).
func installViaKerioWebAdminCerts(cli *KerioClient, rec *IssuedCertRecord, crtUploadID, keyUploadID string, beforeIDs map[string]bool, log LogFunc) (string, error) {
	pkRaw, pkErr := cli.rpc("Certificates.importPrivateKey", map[string]any{"fileId": keyUploadID})
	if pkErr != nil {
		return "", kerioInstallHint(pkErr)
	}
	var pk struct {
		KeyId        string `json:"keyId"`
		Id           string `json:"id"`
		NeedPassword bool   `json:"needPassword"`
	}
	_ = json.Unmarshal(pkRaw, &pk)
	keyID := pk.KeyId
	if keyID == "" {
		keyID = pk.Id
	}
	if keyID == "" {
		return "", kerioInstallHint(&KerioAPIError{Kind: "protocol", Method: "Certificates.importPrivateKey",
			Message: "Kerio не вернул keyId приватного ключа: " + truncateText(string(pkRaw), 200)})
	}
	impRaw, impErr := cli.rpc("Certificates.importCertificate", map[string]any{
		"keyId":  keyID,
		"fileId": crtUploadID,
		"name":   rec.PrimaryDomain,
		"type":   "InactiveCertificate",
	})
	if impErr != nil {
		return "", kerioInstallHint(impErr)
	}
	var imp struct {
		Id string `json:"id"`
	}
	_ = json.Unmarshal(impRaw, &imp)
	certID := imp.Id
	if after, _, lerr := cli.ListCertificates(); lerr == nil {
		if id := findNewKerioCertID(after, beforeIDs, rec.SHA256Fingerprint); id != "" {
			certID = id
		}
	}
	if certID == "" {
		return "", kerioInstallHint(&KerioAPIError{Kind: "protocol", Method: "Certificates.importCertificate",
			Message: "сертификат импортирован, но Kerio не сообщил его ID",
			Fix:     "Откройте https://<сервер>:4040/admin/ → Configuration → SSL Certificates и активируйте сертификат вручную кнопкой «Set as Active»."})
	}

	log("info", fmt.Sprintf("Активация сертификата в интерфейсе Certificates (ID: %s)...", certID))
	for _, method := range []string{"ConnectCertificate.setActive", "Certificates.setActive"} {
		if _, aerr := cli.rpc(method, map[string]any{"id": certID}); aerr == nil {
			return fmt.Sprintf("Сертификат импортирован и активирован через Kerio Admin API (%s) методом %s.", cli.Endpoint.RPCURL(), method), nil
		}
	}
	return fmt.Sprintf("Сертификат импортирован в Kerio (ID: %s), но автоматическая активация недоступна. Откройте Configuration → SSL Certificates и нажмите «Set as Active».", certID), nil
}

// findNewKerioCertID ищет сертификат, которого не было до импорта (или совпадающий по отпечатку).
func findNewKerioCertID(certs []KerioRemoteCertInfo, before map[string]bool, fingerprint string) string {
	fp := normalizeFingerprint(fingerprint)
	if fp != "" {
		for _, c := range certs {
			if normalizeFingerprint(c.Fingerprint) == fp && c.Fingerprint != "" {
				return c.ID
			}
		}
	}
	for _, c := range certs {
		if c.ID != "" && !before[c.ID] {
			return c.ID
		}
	}
	return ""
}

func findActiveKerioCert(certs []KerioRemoteCertInfo) *KerioRemoteCertInfo {
	for i := range certs {
		if certs[i].Active {
			return &certs[i]
		}
	}
	return nil
}

func kerioCertMatches(c KerioRemoteCertInfo, rec *IssuedCertRecord, certID string) bool {
	if certID != "" && c.ID == certID {
		return true
	}
	fp := normalizeFingerprint(rec.SHA256Fingerprint)
	if fp != "" && normalizeFingerprint(c.Fingerprint) == fp {
		return true
	}
	for _, h := range c.HostNames {
		if strings.EqualFold(h, rec.PrimaryDomain) {
			return true
		}
	}
	return false
}

func normalizeFingerprint(fp string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(fp)))
}

// kerioInstallHint превращает типизированную ошибку Kerio в подробное сообщение
// с готовыми шагами исправления для интерфейса программы.
func kerioInstallHint(err error) error {
	var ke *KerioAPIError
	if !errors.As(err, &ke) {
		return err
	}
	msg := ke.Message
	if ke.Method != "" {
		msg = fmt.Sprintf("%s: %s", ke.Method, msg)
	}
	if ke.Fix != "" {
		msg += "\n\nКак исправить:\n" + ke.Fix
	}
	if ke.Raw != "" {
		msg += "\n\nОтвет сервера Kerio: " + ke.Raw
	}
	msg += "\n\nПодробная проверка — кнопка «🩺 Диагностика подключения к Kerio»."
	return errors.New(msg)
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
