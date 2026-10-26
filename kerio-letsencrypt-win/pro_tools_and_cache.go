package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 1. HIGH-PERFORMANCE POOLED HTTP/2 CLIENT + IN-MEMORY TTL DNS & WAN IP CACHE
// ============================================================================

var sharedFastHTTPClient = &http.Client{
	Timeout: 2500 * time.Millisecond,
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   1800 * time.Millisecond,
			KeepAlive: 45 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   1800 * time.Millisecond,
		ExpectContinueTimeout: 500 * time.Millisecond,
	},
}

type dohCacheEntry struct {
	ans       []dohAnswer
	status    int
	expiresAt time.Time
}

var (
	dohCacheMu sync.RWMutex
	dohCache   = map[string]dohCacheEntry{}

	wanCacheMu sync.RWMutex
	wanCached  string
	wanExpAt   time.Time
)

func ClearNetworkDiagnosticCache() {
	dohCacheMu.Lock()
	dohCache = map[string]dohCacheEntry{}
	dohCacheMu.Unlock()

	wanCacheMu.Lock()
	wanCached = ""
	wanExpAt = time.Time{}
	wanCacheMu.Unlock()
}

func getCachedDoH(key string) ([]dohAnswer, int, bool) {
	dohCacheMu.RLock()
	e, ok := dohCache[key]
	dohCacheMu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return nil, 0, false
	}
	return e.ans, e.status, true
}

func setCachedDoH(key string, ans []dohAnswer, status int, ttl time.Duration) {
	dohCacheMu.Lock()
	if len(dohCache) > 2048 {
		dohCache = map[string]dohCacheEntry{}
	}
	dohCache[key] = dohCacheEntry{
		ans:       ans,
		status:    status,
		expiresAt: time.Now().Add(ttl),
	}
	dohCacheMu.Unlock()
}

func getCachedWANIP() string {
	wanCacheMu.RLock()
	defer wanCacheMu.RUnlock()
	if wanCached != "" && time.Now().Before(wanExpAt) {
		return wanCached
	}
	return ""
}

func setCachedWANIP(ip string) {
	wanCacheMu.Lock()
	wanCached = ip
	wanExpAt = time.Now().Add(90 * time.Second)
	wanCacheMu.Unlock()
}

// ============================================================================
// 2. PERSISTENT UI PREFERENCES & AUDIT SCORE HISTORY ("БЫЛО -> СТАЛО")
// ============================================================================

type SavedUISettings struct {
	SelectedIconID   int    `json:"selectedIconId,omitempty"`
	LastDomain       string `json:"lastDomain"`
	LastServerIP     string `json:"lastServerIp"`
	LastEmail        string `json:"lastEmail"`
	KerioInstallPath string `json:"kerioInstallPath"`
	KerioAPIHost     string `json:"kerioApiHost"`
	KerioAPIPort     int    `json:"kerioApiPort"`
	KerioAPIUser     string `json:"kerioApiUser"`
	AuditDomain      string `json:"auditDomain"`
	AuditMailHost    string `json:"auditMailHost"`
	AuditTargetIP    string `json:"auditTargetIp"`

	// Автообновление программы (см. updater.go).
	AutoCheckUpdates bool   `json:"autoCheckUpdates"`
	LastUpdateCheck  string `json:"lastUpdateCheck,omitempty"`
	SkippedVersion   string `json:"skippedVersion,omitempty"`

	// Kerio Connect на Linux (удалённое управление по SSH, см. linux_remote.go).
	LinuxHost      string `json:"linuxHost,omitempty"`
	LinuxPort      int    `json:"linuxPort,omitempty"`
	LinuxUser      string `json:"linuxUser,omitempty"`
	LinuxKeyPath   string `json:"linuxKeyPath,omitempty"`
	LinuxKerioDir  string `json:"linuxKerioDir,omitempty"`
	LinuxService   string `json:"linuxService,omitempty"`
	LinuxKnownHost string `json:"linuxKnownHost,omitempty"`
	LinuxSudo      bool   `json:"linuxSudo"`
}

type AuditHistoryItem struct {
	CheckedAt     string `json:"checkedAt"`
	MailDomain    string `json:"mailDomain"`
	MailHost      string `json:"mailHost"`
	ServerIP      string `json:"serverIp"`
	Score         int    `json:"score"`
	Grade         string `json:"grade"`
	CriticalCount int    `json:"criticalCount"`
	WarningCount  int    `json:"warningCount"`
	PassedCount   int    `json:"passedCount"`
}

type AuditDeltaComparison struct {
	HasPrevious       bool   `json:"hasPrevious"`
	PreviousScore     int    `json:"previousScore"`
	PreviousGrade     string `json:"previousGrade"`
	PreviousCheckedAt string `json:"previousCheckedAt"`
	ScoreDiff         int    `json:"scoreDiff"`
	SummaryText       string `json:"summaryText"`
}

var settingsMu sync.Mutex

func LoadSavedUISettings(baseDir string) SavedUISettings {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	// Автопроверка обновлений включена по умолчанию: администратор сервера
	// обычно не следит за релизами, а узнавать о новой версии полезно.
	// Sudo для Linux-операций тоже включён по умолчанию — иначе при входе
	// не от root программа не сможет ни записать файл, ни перезапустить службу.
	s := SavedUISettings{AutoCheckUpdates: true, LinuxSudo: true}
	b, err := os.ReadFile(filepath.Join(baseDir, "ui_settings.json"))
	if err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func SaveUISettings(baseDir string, s SavedUISettings) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	_ = os.MkdirAll(baseDir, 0700)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(baseDir, "ui_settings.json"), b, 0600)
}

func LoadAuditHistory(baseDir string) []AuditHistoryItem {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	var items []AuditHistoryItem
	b, err := os.ReadFile(filepath.Join(baseDir, "audit_history.json"))
	if err == nil {
		_ = json.Unmarshal(b, &items)
	}
	return items
}

func RecordAuditAndComputeDelta(baseDir string, rep *MailAuditReport) AuditDeltaComparison {
	settingsMu.Lock()
	defer settingsMu.Unlock()

	var items []AuditHistoryItem
	histPath := filepath.Join(baseDir, "audit_history.json")
	if b, err := os.ReadFile(histPath); err == nil {
		_ = json.Unmarshal(b, &items)
	}

	var delta AuditDeltaComparison
	for _, it := range items {
		if strings.EqualFold(it.MailDomain, rep.MailDomain) {
			delta.HasPrevious = true
			delta.PreviousScore = it.Score
			delta.PreviousGrade = it.Grade
			delta.PreviousCheckedAt = it.CheckedAt
			delta.ScoreDiff = rep.Score - it.Score
			switch {
			case delta.ScoreDiff > 0:
				delta.SummaryText = fmt.Sprintf("📈 Отличный прогресс! Рейтинг вырос с %d (%s) до %d (%s) [+%d баллов по сравнению с %s]!",
					it.Score, it.Grade, rep.Score, rep.Grade, delta.ScoreDiff, it.CheckedAt)
			case delta.ScoreDiff < 0:
				delta.SummaryText = fmt.Sprintf("📉 Внимание: рейтинг снизился с %d (%s) до %d (%s) [%d баллов по сравнению с %s].",
					it.Score, it.Grade, rep.Score, rep.Grade, delta.ScoreDiff, it.CheckedAt)
			default:
				delta.SummaryText = fmt.Sprintf("Без изменений по сравнению с прошлой проверкой (%s): %d/100 (%s).",
					it.CheckedAt, rep.Score, rep.Grade)
			}
			break
		}
	}

	newEntry := AuditHistoryItem{
		CheckedAt:     rep.CheckedAt,
		MailDomain:    rep.MailDomain,
		MailHost:      rep.MailHost,
		ServerIP:      rep.ServerIP,
		Score:         rep.Score,
		Grade:         rep.Grade,
		CriticalCount: rep.CriticalCount,
		WarningCount:  rep.WarningCount,
		PassedCount:   rep.PassedCount,
	}
	items = append([]AuditHistoryItem{newEntry}, items...)
	if len(items) > 25 {
		items = items[:25]
	}
	_ = os.MkdirAll(baseDir, 0700)
	if raw, err := json.MarshalIndent(items, "", "  "); err == nil {
		_ = os.WriteFile(histPath, raw, 0600)
	}
	return delta
}

// ============================================================================
// 3. LIVE KERIO CONNECT (:4040) ACTIVE SSL CERTIFICATE INSPECTOR
// ============================================================================

// InspectKerioServerCertificates подключается к Kerio Connect Admin API и
// возвращает список сертификатов сервера (используется кнопкой проверки связи).
func InspectKerioServerCertificates(host string, port int, user, pass string) ([]KerioRemoteCertInfo, error) {
	h, p := NormalizeKerioHost(host, port)
	cli := NewKerioClient(KerioEndpoint{Host: h, Port: p})
	if err := cli.Login(user, pass, ""); err != nil {
		return nil, err
	}
	defer cli.Logout()
	if who, err := cli.WhoAmI(); err == nil && !who.IsAdmin && strings.TrimSpace(who.Role) != "" {
		return nil, &KerioAPIError{
			Kind: "rights", Method: "Session.whoAmI",
			Message: fmt.Sprintf("учётка %s не является администратором Kerio Connect (роль: %s)", who.LoginName, who.Role),
			Fix:     "Добавьте учётку в Configuration → Administration → Administrators или используйте мастер-администратора admin.",
		}
	}
	certs, _, err := cli.ListCertificates()
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// ============================================================================
// 4. RFC-822 RAW EMAIL HEADER ANALYZER & HOP-BY-HOP DELAY CALCULATOR
// ============================================================================

type EmailHopInfo struct {
	HopNumber int    `json:"hopNumber"`
	FromHost  string `json:"fromHost"`
	ByHost    string `json:"byHost"`
	WithProto string `json:"withProto"`
	Timestamp string `json:"timestamp"`
	DelaySec  int64  `json:"delaySec"`
	SlowHop   bool   `json:"slowHop"`
}

type HeaderAnalysisResult struct {
	Subject       string         `json:"subject"`
	From          string         `json:"from"`
	To            string         `json:"to"`
	Date          string         `json:"date"`
	MessageID     string         `json:"messageId"`
	ReturnPath    string         `json:"returnPath"`
	SPFStatus     string         `json:"spfStatus"`
	DKIMStatus    string         `json:"dkimStatus"`
	DMARCStatus   string         `json:"dmarcStatus"`
	SpamScoreInfo string         `json:"spamScoreInfo"`
	TotalDelaySec int64          `json:"totalDelaySec"`
	Verdict       string         `json:"verdict"`
	Findings      []string       `json:"findings"`
	Hops          []EmailHopInfo `json:"hops"`
}

var (
	reFrom = regexp.MustCompile(`(?i)\bfrom\s+([^\s;()]+(?:\s+\([^)]*\))?)`)
	reBy   = regexp.MustCompile(`(?i)\bby\s+([^\s;()]+)`)
	reWith = regexp.MustCompile(`(?i)\bwith\s+([A-Za-z0-9_-]+)`)
)

func parseReceivedTime(raw string) (time.Time, bool) {
	idx := strings.LastIndex(raw, ";")
	if idx < 0 {
		return time.Time{}, false
	}
	tsStr := strings.TrimSpace(raw[idx+1:])
	// Remove trailing parenthetical comment like (UTC) or (MSK) if present after numeric tz
	if pIdx := strings.LastIndex(tsStr, "("); pIdx > 15 {
		tsStr = strings.TrimSpace(tsStr[:pIdx])
	}
	if t, err := mail.ParseDate(tsStr); err == nil {
		return t, true
	}
	layouts := []string{
		time.RFC1123Z,
		time.RFC1123,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"2 Jan 2006 15:04:05 -0700",
		"Mon, 02 Jan 2006 15:04:05 -0700",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, tsStr); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func extractAuthToken(authHeader, key string) string {
	low := strings.ToLower(authHeader)
	idx := strings.Index(low, key+"=")
	if idx < 0 {
		return ""
	}
	sub := authHeader[idx+len(key)+1:]
	fields := strings.FieldsFunc(sub, func(r rune) bool {
		return r == ' ' || r == ';' || r == '(' || r == ')' || r == '\r' || r == '\n'
	})
	if len(fields) > 0 {
		return strings.ToUpper(strings.TrimSpace(fields[0]))
	}
	return ""
}

func AnalyzeRawEmailHeaders(rawText string) (*HeaderAnalysisResult, error) {
	cleaned := strings.ReplaceAll(strings.TrimSpace(rawText), "\r\n", "\n")
	if cleaned == "" {
		return nil, fmt.Errorf("вставьте служебные заголовки письма (из «Показать оригинал» в Gmail / Mail.ru / Яндекс или «Свойства сообщения» в Outlook)")
	}
	// Ensure blank line + dummy body so net/mail.ReadMessage parses header-only snippets cleanly!
	msg, err := mail.ReadMessage(strings.NewReader(cleaned + "\n\nbody\n"))
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать RFC-822 заголовки (убедитесь, что скопировали начало письма с первой строки): %w", err)
	}

	h := msg.Header
	out := &HeaderAnalysisResult{
		Subject:    h.Get("Subject"),
		From:       h.Get("From"),
		To:         h.Get("To"),
		Date:       h.Get("Date"),
		MessageID:  h.Get("Message-ID"),
		ReturnPath: h.Get("Return-Path"),
	}

	authAll := strings.Join(append(h["Authentication-Results"], h["ARC-Authentication-Results"]...), " ; ")
	out.SPFStatus = extractAuthToken(authAll, "spf")
	if out.SPFStatus == "" && h.Get("Received-SPF") != "" {
		fields := strings.Fields(h.Get("Received-SPF"))
		if len(fields) > 0 {
			out.SPFStatus = strings.ToUpper(fields[0])
		}
	}
	out.DKIMStatus = extractAuthToken(authAll, "dkim")
	out.DMARCStatus = extractAuthToken(authAll, "dmarc")

	var spamNotes []string
	for _, k := range []string{"X-Spam-Status", "X-Spam-Flag", "X-Spam-Score", "X-Forefront-Antispam-Report", "X-Yandex-Spam"} {
		if v := h.Get(k); v != "" {
			spamNotes = append(spamNotes, k+": "+v)
		}
	}
	out.SpamScoreInfo = strings.Join(spamNotes, " | ")

	// Parse Received headers from bottom (origin sender) to top (final mailbox)!
	recHeaders := h["Received"]
	type parsedRec struct {
		fromHost string
		byHost   string
		proto    string
		ts       time.Time
		hasTS    bool
		rawTS    string
	}
	var revList []parsedRec
	for i := len(recHeaders) - 1; i >= 0; i-- {
		rLine := recHeaders[i]
		var pr parsedRec
		if m := reFrom.FindStringSubmatch(rLine); len(m) > 1 {
			pr.fromHost = m[1]
		}
		if m := reBy.FindStringSubmatch(rLine); len(m) > 1 {
			pr.byHost = m[1]
		}
		if m := reWith.FindStringSubmatch(rLine); len(m) > 1 {
			pr.proto = m[1]
		}
		if t, ok := parseReceivedTime(rLine); ok {
			pr.ts = t
			pr.hasTS = true
			pr.rawTS = t.Local().Format("02.01.2006 15:04:05")
		}
		revList = append(revList, pr)
	}

	var prevTime time.Time
	var firstTime, lastTime time.Time
	for idx, item := range revList {
		var delay int64
		if item.hasTS {
			if firstTime.IsZero() {
				firstTime = item.ts
			}
			lastTime = item.ts
			if !prevTime.IsZero() {
				d := int64(item.ts.Sub(prevTime).Seconds())
				if d > 0 {
					delay = d
				}
			}
			prevTime = item.ts
		}
		out.Hops = append(out.Hops, EmailHopInfo{
			HopNumber: idx + 1,
			FromHost:  nonEmptyOr(item.fromHost, "отправитель"),
			ByHost:    nonEmptyOr(item.byHost, "узел"),
			WithProto: item.proto,
			Timestamp: nonEmptyOr(item.rawTS, "—"),
			DelaySec:  delay,
			SlowHop:   delay >= 30,
		})
	}
	if !firstTime.IsZero() && !lastTime.IsZero() && lastTime.After(firstTime) {
		out.TotalDelaySec = int64(lastTime.Sub(firstTime).Seconds())
	}

	// Build smart Russian diagnostic conclusions
	if out.SPFStatus != "" && out.SPFStatus != "PASS" {
		out.Findings = append(out.Findings, fmt.Sprintf("🔴 Провалена проверка SPF (%s)! Сервер отправки не включён в TXT-запись v=spf1 домена отправителя.", out.SPFStatus))
	} else if out.SPFStatus == "PASS" {
		out.Findings = append(out.Findings, "✅ Проверка SPF пройдена успешно (PASS).")
	}

	if out.DKIMStatus == "" {
		out.Findings = append(out.Findings, "🟠 В письме ОТСУТСТВУЕТ цифровая подпись DKIM! Включите подпись DKIM в Kerio Connect (Конфигурация → Домены → Общие → DomainKeys).")
	} else if out.DKIMStatus != "PASS" {
		out.Findings = append(out.Findings, fmt.Sprintf("🔴 Ошибка цифровой подписи DKIM (%s)! Либо ключ в DNS не совпадает с ключом Kerio, либо шлюз/антивирус изменил тело письма в пути.", out.DKIMStatus))
	} else {
		out.Findings = append(out.Findings, "✅ Цифровая криптоподпись DKIM пройдена успешно (PASS).")
	}

	if out.DMARCStatus != "" && out.DMARCStatus != "PASS" {
		out.Findings = append(out.Findings, fmt.Sprintf("🔴 Политика DMARC не пройдена (%s) — высокая вероятность попадания в папку «Спам»!", out.DMARCStatus))
	} else if out.DMARCStatus == "PASS" {
		out.Findings = append(out.Findings, "✅ Политика DMARC пройдена успешно (PASS).")
	}

	if out.TotalDelaySec > 120 {
		out.Findings = append(out.Findings, fmt.Sprintf("⏱️ Обнаружена задержка доставки %d сек. (%.1f мин.) — чаще всего вызвана грейлистингом (Greylisting) на стороне получателя при отсутствии PTR или прогрева IP!", out.TotalDelaySec, float64(out.TotalDelaySec)/60.0))
	}

	if out.SPFStatus == "PASS" && out.DKIMStatus == "PASS" && (out.DMARCStatus == "PASS" || out.DMARCStatus == "") {
		out.Verdict = fmt.Sprintf("Все криптографические подписи письма идеальны (SPF=PASS, DKIM=PASS)! Время в пути: %d сек. Если письмо всё равно попало в Спам — проверьте репутацию IP/ссылок или текст письма.", out.TotalDelaySec)
	} else {
		out.Verdict = "Обнаружены конкретные технические причины фильтрации в заголовках письма! Смотрите детальный разбор ниже."
	}

	return out, nil
}
