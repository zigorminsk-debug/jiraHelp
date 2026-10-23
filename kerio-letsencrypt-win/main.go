package main

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed ui/index.html
var embeddedIndexHTML []byte

//go:embed ui/icon.ico
var embeddedIconICO []byte

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

type LogBroadcaster struct {
	mu      sync.Mutex
	history []LogEntry
	clients map[chan LogEntry]struct{}
}

func NewLogBroadcaster() *LogBroadcaster {
	return &LogBroadcaster{
		clients: make(map[chan LogEntry]struct{}),
	}
}

func (b *LogBroadcaster) Emit(level, message string) {
	entry := LogEntry{
		Timestamp: time.Now().Format("15:04:05"),
		Level:     level,
		Message:   message,
	}
	b.mu.Lock()
	b.history = append(b.history, entry)
	if len(b.history) > 300 {
		b.history = b.history[len(b.history)-300:]
	}
	for ch := range b.clients {
		select {
		case ch <- entry:
		default:
		}
	}
	b.mu.Unlock()
}

func (b *LogBroadcaster) Subscribe() (chan LogEntry, []LogEntry, func()) {
	ch := make(chan LogEntry, 64)
	b.mu.Lock()
	histCopy := make([]LogEntry, len(b.history))
	copy(histCopy, b.history)
	b.clients[ch] = struct{}{}
	b.mu.Unlock()

	unsubscribe := func() {
		b.mu.Lock()
		delete(b.clients, ch)
		close(ch)
		b.mu.Unlock()
	}
	return ch, histCopy, unsubscribe
}

func (b *LogBroadcaster) ClientCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.clients)
}

var (
	logHub            = NewLogBroadcaster()
	serverCancel      context.CancelFunc
	windowsExeMu      sync.RWMutex
	windowsExeFP      string
	lastActivityUnixN atomic.Int64
	everHadClient     atomic.Bool
)

func touchActivity() {
	lastActivityUnixN.Store(time.Now().UnixNano())
}

func locateWindowsExe() string {
	windowsExeMu.RLock()
	cached := windowsExeFP
	windowsExeMu.RUnlock()
	if cached != "" {
		if _, err := os.Stat(cached); err == nil {
			return cached
		}
	}
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		if strings.HasSuffix(strings.ToLower(exe), ".exe") {
			candidates = append(candidates, exe)
		}
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "KerioCertManager.exe"))
	}
	candidates = append(candidates,
		"KerioCertManager.exe",
		filepath.Join("..", "KerioCertManager.exe"),
		filepath.Join("kerio-letsencrypt-win", "KerioCertManager.exe"),
	)
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			abs, _ := filepath.Abs(c)
			windowsExeMu.Lock()
			windowsExeFP = abs
			windowsExeMu.Unlock()
			return abs
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]any{
		"ok":    false,
		"error": err.Error(),
	})
}

func buildRouter() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(embeddedIndexHTML)
	})

	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(embeddedIconICO)
	})

	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("client") == "ui" {
			everHadClient.Store(true)
			touchActivity()
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/app-shutdown", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
		go func() {
			CloseDesktopWindow()
			time.Sleep(150 * time.Millisecond)
			if serverCancel != nil {
				serverCancel()
			}
			os.Exit(0)
		}()
	})

	// SSE stream for real-time ACME / Crypto / Kerio progress logs
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		everHadClient.Store(true)
		touchActivity()
		defer touchActivity()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		ch, hist, unsub := logHub.Subscribe()
		defer unsub()

		for _, item := range hist {
			b, _ := json.Marshal(item)
			fmt.Fprintf(w, "data: %s\n\n", b)
		}
		flusher.Flush()

		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case item, ok := <-ch:
				if !ok {
					return
				}
				b, _ := json.Marshal(item)
				fmt.Fprintf(w, "data: %s\n\n", b)
				flusher.Flush()
			case <-ticker.C:
				fmt.Fprintf(w, ": ping\n\n")
				flusher.Flush()
			}
		}
	})

	mux.HandleFunc("/api/system-info", func(w http.ResponseWriter, r *http.Request) {
		exePath := locateWindowsExe()
		var exeSizeMB float64
		if exePath != "" {
			if st, err := os.Stat(exePath); err == nil {
				exeSizeMB = float64(st.Size()) / (1024.0 * 1024.0)
			}
		}
		defDir := DefaultCertsRoot()
		writeJSON(w, 200, map[string]any{
			"ok":                  true,
			"os":                  runtime.GOOS,
			"arch":                runtime.GOARCH,
			"isWindows":           runtime.GOOS == "windows",
			"isAdmin":             IsRunningAsAdmin(),
			"defaultCertsDir":     defDir,
			"localIps":            ListLocalIPs(),
			"externalIp":          DetectPublicIPFast(),
			"kerio":               InspectKerioInstallation(""),
			"autoRenewScheduled":  PlatformQueryAutoRenewTask(),
			"windowsExeAvailable": exePath != "",
			"windowsExeSizeMB":    fmt.Sprintf("%.1f МБ", exeSizeMB),
			"uiSettings":          LoadSavedUISettings(defDir),
			"auditHistory":        LoadAuditHistory(defDir),
		})
	})

	mux.HandleFunc("/api/preflight", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var req IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, 400, err)
			return
		}
		res := RunPreflightCheck(req)
		writeJSON(w, 200, map[string]any{
			"ok":        true,
			"preflight": res,
		})
	})

	// Parallel DNS probe for common mail subdomains (webmail, autodiscover, smtp, imap, pop3, mail)
	mux.HandleFunc("/api/discover-subdomains", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Domain    string `json:"domain"`
			IPAddress string `json:"ipAddress"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		ascii, _, err := NormalizeDomain(body.Domain)
		if err != nil || ascii == "" {
			writeErr(w, 400, fmt.Errorf("введите корректное основное доменное имя"))
			return
		}
		parts := strings.Split(ascii, ".")
		baseDom := ascii
		if len(parts) >= 3 {
			first := parts[0]
			if first == "mail" || first == "mx" || first == "smtp" || first == "imap" || first == "pop" || first == "pop3" || first == "webmail" {
				baseDom = strings.Join(parts[1:], ".")
			}
		}
		parsedInputIP, _, _, _ := ClassifyIP(body.IPAddress)
		prefixes := []string{"webmail", "autodiscover", "smtp", "imap", "pop3", "mail"}

		type probeItem struct {
			Prefix  string   `json:"prefix"`
			Domain  string   `json:"domain"`
			Exists  bool     `json:"exists"`
			Matches bool     `json:"matches"`
			IPs     []string `json:"ips"`
		}
		results := make([]probeItem, len(prefixes))
		var wg sync.WaitGroup
		for i, pfx := range prefixes {
			wg.Add(1)
			go func(idx int, p string) {
				defer wg.Done()
				cand := p + "." + baseDom
				ips, lerr := LookupDomainIPsMultiResolver(cand)
				item := probeItem{Prefix: p, Domain: cand}
				if lerr == nil && len(ips) > 0 {
					item.Exists = true
					item.IPs = ips
					for _, rip := range ips {
						if parsedInputIP == nil || (net.ParseIP(rip) != nil && net.ParseIP(rip).Equal(parsedInputIP)) {
							item.Matches = true
						}
					}
				}
				results[idx] = item
			}(i, pfx)
		}
		wg.Wait()
		writeJSON(w, 200, map[string]any{
			"ok":         true,
			"primary":    ascii,
			"baseDomain": baseDom,
			"results":    results,
		})
	})

	mux.HandleFunc("/api/check-dns-txt", func(w http.ResponseWriter, r *http.Request) {
		fqdn := strings.TrimSpace(r.URL.Query().Get("record"))
		expected := strings.TrimSpace(r.URL.Query().Get("expected"))
		if fqdn == "" {
			writeErr(w, 400, fmt.Errorf("не указано имя TXT-записи"))
			return
		}
		records, err := LookupDNSTXTRecords(fqdn)
		if err != nil {
			// Check common control panel mistake: accidental doubled domain zone e.g. _acme-challenge.mail.leend.by.leend.by
			parts := strings.Split(fqdn, ".")
			if len(parts) >= 3 {
				zone := strings.Join(parts[len(parts)-2:], ".")
				shortHost := strings.Join(parts[:len(parts)-2], ".")
				doubled := fqdn + "." + zone
				if dupRecs, derr := LookupDNSTXTRecords(doubled); derr == nil && len(dupRecs) > 0 {
					writeJSON(w, 200, map[string]any{
						"ok":          true,
						"found":       false,
						"matched":     false,
						"doubledZone": doubled,
						"shortHost":   shortHost,
						"records":     dupRecs,
						"message":     fmt.Sprintf("Запись создалась с задвоенным доменом (%s)! В вашей панели DNS (hoster.by / Cloudflare) укажите в поле Имя только короткую часть: %s", doubled, shortHost),
					})
					return
				}
			}
			writeJSON(w, 200, map[string]any{
				"ok":      true,
				"found":   false,
				"matched": false,
				"records": []string{},
				"message": err.Error(),
			})
			return
		}
		matched := false
		for _, rec := range records {
			if expected != "" && strings.TrimSpace(rec) == expected {
				matched = true
			}
		}
		writeJSON(w, 200, map[string]any{
			"ok":      true,
			"found":   true,
			"matched": matched,
			"records": records,
		})
	})

	mux.HandleFunc("/api/ui-settings", func(w http.ResponseWriter, r *http.Request) {
		defDir := DefaultCertsRoot()
		if r.Method == http.MethodGet {
			writeJSON(w, 200, map[string]any{
				"ok":           true,
				"uiSettings":   LoadSavedUISettings(defDir),
				"auditHistory": LoadAuditHistory(defDir),
			})
			return
		}
		var s SavedUISettings
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			writeErr(w, 400, err)
			return
		}
		_ = SaveUISettings(defDir, s)
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/kerio/remote-certs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var body struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			User     string `json:"user"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		certs, err := InspectKerioServerCertificates(body.Host, body.Port, body.User, body.Password)
		if err != nil {
			logHub.Emit("error", err.Error())
			writeErr(w, 400, err)
			return
		}
		logHub.Emit("success", fmt.Sprintf("Подключение к Kerio Connect (%s:%d) успешно! Найдено сертификатов на сервере: %d", body.Host, body.Port, len(certs)))
		writeJSON(w, 200, map[string]any{
			"ok":    true,
			"certs": certs,
		})
	})

	mux.HandleFunc("/api/analyze-headers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var body struct {
			Headers string `json:"headers"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		res, err := AnalyzeRawEmailHeaders(body.Headers)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"ok":     true,
			"result": res,
		})
	})

	mux.HandleFunc("/api/detect-public-ip", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("force") == "1" {
			ClearNetworkDiagnosticCache()
		}
		ip := DetectPublicIPFast()
		writeJSON(w, 200, map[string]any{
			"ok":       ip != "",
			"publicIp": ip,
		})
	})

	mux.HandleFunc("/api/decode-bounce", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var req BounceDecodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, 400, err)
			return
		}
		out := DecodeSMTPBounceAndBuildLetter(req)
		writeJSON(w, 200, map[string]any{
			"ok":     true,
			"result": out,
		})
	})

	mux.HandleFunc("/api/mail-send-test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var req TestEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, 400, err)
			return
		}
		res, err := SendDiagnosticTestEmail(req)
		if err != nil {
			logHub.Emit("error", "Тестовая отправка SMTP: "+err.Error())
			writeErr(w, 400, err)
			return
		}
		logHub.Emit("success", fmt.Sprintf("Тестовое диагностическое письмо успешно отправлено на %s за %d мс!", req.ToEmail, res.DurationMs))
		writeJSON(w, 200, map[string]any{
			"ok":     true,
			"result": res,
		})
	})

	mux.HandleFunc("/api/mail-audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var req MailAuditRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, 400, err)
			return
		}
		ClearNetworkDiagnosticCache()
		rep, err := RunMailDeliverabilityAudit(req, logHub.Emit)
		if err != nil {
			logHub.Emit("error", err.Error())
			writeErr(w, 400, err)
			return
		}
		defDir := DefaultCertsRoot()
		rep.Delta = RecordAuditAndComputeDelta(defDir, rep)
		writeJSON(w, 200, map[string]any{
			"ok":           true,
			"report":       rep,
			"auditHistory": LoadAuditHistory(defDir),
		})
	})

	mux.HandleFunc("/api/issue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var req IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, 400, err)
			return
		}
		logHub.Emit("info", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logHub.Emit("info", fmt.Sprintf("Начат процесс генерации ключа и выпуска сертификата (Домен: %s, IP: %s, Режим: %s)", req.Domain, req.IPAddress, req.Mode))

		rec, dnsSess, err := ExecuteCertificateIssuance(req, logHub.Emit)
		if err != nil {
			logHub.Emit("error", err.Error())
			writeErr(w, 400, err)
			return
		}
		if dnsSess != nil {
			writeJSON(w, 200, map[string]any{
				"ok":           true,
				"pendingDns01": true,
				"session":      dnsSess,
			})
			return
		}
		writeJSON(w, 200, map[string]any{
			"ok":          true,
			"certificate": rec,
		})
	})

	mux.HandleFunc("/api/dns01/complete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var body struct {
			SessionID string `json:"sessionId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		rec, err := CompletePendingDNS01Session(body.SessionID, logHub.Emit)
		if err != nil {
			logHub.Emit("error", err.Error())
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"ok":          true,
			"certificate": rec,
		})
	})

	mux.HandleFunc("/api/certs", func(w http.ResponseWriter, r *http.Request) {
		dir := r.URL.Query().Get("dir")
		list, err := LoadAllCertRecords(dir)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"ok":           true,
			"certificates": list,
		})
	})

	mux.HandleFunc("/api/certs/detail", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		dir := r.URL.Query().Get("dir")
		rec, err := LoadSingleCertRecord(dir, id, true)
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"ok":          true,
			"certificate": rec,
		})
	})

	mux.HandleFunc("/api/certs/delete", func(w http.ResponseWriter, r *http.Request) {
		id := filepath.Base(r.URL.Query().Get("id"))
		dir := strings.TrimSpace(r.URL.Query().Get("dir"))
		if dir == "" {
			dir = DefaultCertsRoot()
		}
		if id == "" || id == "." || id == ".." {
			writeErr(w, 400, fmt.Errorf("некорректный идентификатор"))
			return
		}
		if err := os.RemoveAll(filepath.Join(dir, id)); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/certs/download", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		fileKey := r.URL.Query().Get("file")
		dir := r.URL.Query().Get("dir")
		rec, err := LoadSingleCertRecord(dir, id, false)
		if err != nil {
			http.Error(w, "сертификат не найден", http.StatusNotFound)
			return
		}
		fp, ok := rec.Files[fileKey]
		if !ok || fp == "" {
			http.Error(w, "запрошенный файл не найден", http.StatusNotFound)
			return
		}
		data, err := os.ReadFile(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		filename := filepath.Base(fp)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	// Direct 1-click download of standalone Windows GUI executable KerioCertManager.exe
	mux.HandleFunc("/api/download-windows-exe", func(w http.ResponseWriter, r *http.Request) {
		exePath := locateWindowsExe()
		if exePath == "" {
			http.Error(w, "KerioCertManager.exe не найден", http.StatusNotFound)
			return
		}
		http.Header.Set(w.Header(), "Content-Type", "application/vnd.microsoft.portable-executable")
		http.Header.Set(w.Header(), "Content-Disposition", `attachment; filename="KerioCertManager.exe"`)
		http.ServeFile(w, r, exePath)
	})

	mux.HandleFunc("/api/download-windows-zip", func(w http.ResponseWriter, r *http.Request) {
		exePath := locateWindowsExe()
		if exePath == "" {
			http.Error(w, "KerioCertManager.exe не найден", http.StatusNotFound)
			return
		}
		exeBytes, err := os.ReadFile(exePath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		fw, _ := zw.Create("KerioCertManager.exe")
		_, _ = fw.Write(exeBytes)
		rw, _ := zw.Create("ПРОЧТИ_МЕНЯ_WINDOWS.txt")
		_, _ = rw.Write([]byte(strings.Join([]string{
			"======================================================================",
			"  Kerio SSL & Let's Encrypt Manager (Windows x64 Desktop GUI)",
			"======================================================================",
			"ЗАПУСК НА WINDOWS / WINDOWS SERVER:",
			"  1. Скопируйте файл KerioCertManager.exe в любую удобную папку",
			"     на сервере с Kerio Connect (например, C:\\KerioCertManager\\).",
			"  2. Нажмите правой кнопкой мыши -> «Запуск от имени администратора».",
			"     (Установка Python, OpenSSL, Certbot или .NET НЕ ТРЕБУЕТСЯ — всё уже внутри!).",
			"  3. В открывшемся окне введите Доменное имя (например, mail.company.by)",
			"     и IP-адрес сервера, затем нажмите «Сгенерировать ключ и выпустить сертификат».",
			"  4. Программа создаст приватный ключ (server.key / RSA 2048) и полный сертификат",
			"     с цепочкой (server.crt / fullchain), а также предложит в 1 клик",
			"     автоматически установить их в Kerio Connect!",
			"",
			"КОМАНДНАЯ СТРОКА (ДЛЯ АВТОПРОДЛЕНИЯ):",
			"  KerioCertManager.exe --renew          -> тихое продление истекающих сертификатов",
			"  KerioCertManager.exe --listen 0.0.0.0:8899 --server-only -> режим веб-панели",
			"======================================================================",
		}, "\r\n") + "\r\n"))
		_ = zw.Close()

		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="KerioCertManager-Windows-x64.zip"`)
		_, _ = w.Write(buf.Bytes())
	})

	mux.HandleFunc("/api/kerio/inspect", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path string `json:"path"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		writeJSON(w, 200, map[string]any{
			"ok":    true,
			"kerio": InspectKerioInstallation(body.Path),
		})
	})

	mux.HandleFunc("/api/kerio/install", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var body struct {
			CertID string             `json:"certId"`
			Dir    string             `json:"dir"`
			Config KerioInstallConfig `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		rec, err := LoadSingleCertRecord(body.Dir, body.CertID, false)
		if err != nil {
			writeErr(w, 404, fmt.Errorf("сертификат %s не найден: %w", body.CertID, err))
			return
		}
		note, err := InstallCertificateToKerio(rec, body.Config, logHub.Emit)
		if err != nil {
			logHub.Emit("error", err.Error())
			writeErr(w, 400, err)
			return
		}
		rec.KerioInstalled = true
		rec.KerioInstallNote = note
		if b, merr := json.MarshalIndent(rec, "", "  "); merr == nil {
			_ = os.WriteFile(filepath.Join(rec.CertDir, "metadata.json"), b, 0600)
		}
		logHub.Emit("success", note)
		writeJSON(w, 200, map[string]any{
			"ok":      true,
			"message": note,
			"kerio":   InspectKerioInstallation(body.Config.KerioPath),
		})
	})

	mux.HandleFunc("/api/kerio/service", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := PlatformControlKerioService(body.Action); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"ok":            true,
			"serviceStatus": PlatformKerioServiceStatus(),
		})
	})

	mux.HandleFunc("/api/windows/elevate", func(w http.ResponseWriter, r *http.Request) {
		if err := RelaunchAsAdmin(nil); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
		go func() {
			CloseDesktopWindow()
			time.Sleep(200 * time.Millisecond)
			if serverCancel != nil {
				serverCancel()
			}
			os.Exit(0)
		}()
	})

	mux.HandleFunc("/api/windows/browse-folder", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Prompt string `json:"prompt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		path, err := PlatformBrowseFolderDialog(body.Prompt)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "path": path})
	})

	mux.HandleFunc("/api/windows/open-folder", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Path string `json:"path"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if err := PlatformOpenFolderInExplorer(body.Path); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/autorenew", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Action        string `json:"action"` // "enable" | "disable" | "run-now"
			IntervalHours int    `json:"intervalHours"`
			Dir           string `json:"dir"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		switch body.Action {
		case "enable":
			msg, err := PlatformInstallAutoRenewTask(body.IntervalHours)
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			logHub.Emit("success", msg)
			writeJSON(w, 200, map[string]any{"ok": true, "message": msg, "scheduled": PlatformQueryAutoRenewTask()})
		case "disable":
			msg, err := PlatformRemoveAutoRenewTask()
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			logHub.Emit("info", msg)
			writeJSON(w, 200, map[string]any{"ok": true, "message": msg, "scheduled": PlatformQueryAutoRenewTask()})
		case "run-now":
			err := RunScheduledRenewals(body.Dir, logHub.Emit)
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			writeJSON(w, 200, map[string]any{"ok": true, "message": "Проверка и автопродление сертификатов успешно выполнены!"})
		default:
			writeErr(w, 400, fmt.Errorf("неизвестное действие автопродления"))
		}
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ping" {
			touchActivity()
		}
		mux.ServeHTTP(w, r)
	})
}

func waitForLocalHTTPReady(pingURL string) {
	noProxyClient := &http.Client{
		Timeout:   500 * time.Millisecond,
		Transport: &http.Transport{Proxy: nil},
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := noProxyClient.Get(pingURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
}

func main() {
	renewFlag := flag.Bool("renew", false, "Тихая проверка и автопродление истекающих сертификатов Let's Encrypt")
	listenAddr := flag.String("listen", "", "Адрес и порт для веб-интерфейса (по умолчанию 127.0.0.1:0 для Desktop GUI)")
	serverOnly := flag.Bool("server-only", false, "Не открывать окно браузера автоматически")
	certsDirFlag := flag.String("certs-dir", "", "Папка хранения сертификатов")
	flag.Parse()

	if *renewFlag {
		err := RunScheduledRenewals(*certsDirFlag, func(level, msg string) {
			fmt.Printf("[%s] %s\n", strings.ToUpper(level), msg)
		})
		if err != nil {
			os.Exit(1)
		}
		return
	}

	bind := strings.TrimSpace(*listenAddr)
	if bind == "" {
		// Try consistent port 17840 on localhost so single-instance reuses clean origin, fallback to random free port
		bind = "127.0.0.1:17840"
	}

	ln, err := net.Listen("tcp", bind)
	if err != nil && *listenAddr == "" {
		// Replace any older running background instance cleanly so updated .exe always runs latest version!
		localClient := &http.Client{
			Timeout:   900 * time.Millisecond,
			Transport: &http.Transport{Proxy: nil},
		}
		if reqOff, rerr := http.NewRequest("POST", "http://127.0.0.1:17840/api/app-shutdown", nil); rerr == nil {
			if resp, herr := localClient.Do(reqOff); herr == nil {
				resp.Body.Close()
				time.Sleep(450 * time.Millisecond)
			}
		}
		ln, err = net.Listen("tcp", "127.0.0.1:17840")
		if err != nil {
			ln, err = net.Listen("tcp", "127.0.0.1:0")
		}
	}
	if err != nil {
		ShowWindowsMessageBox("Kerio SSL Manager — Ошибка запуска", err.Error())
		fmt.Fprintf(os.Stderr, "Failed to bind %s: %v\n", bind, err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverCancel = cancel
	touchActivity()

	actualAddr := ln.Addr().String()
	appURL := "http://" + actualAddr + "/"
	logHub.Emit("info", "Программа Kerio Connect Let's Encrypt SSL Manager готова к работе.")

	srv := &http.Server{
		Handler: buildRouter(),
	}
	go func() {
		_ = srv.Serve(ln)
	}()

	// Ensure HTTP listener is 100% live and responding before launching Edge/Browser window
	waitForLocalHTTPReady(appURL + "api/ping")

	if !*serverOnly && runtime.GOOS == "windows" {
		// Native Win32 WebView2 window blocks on main OS thread until closed via [X], Alt+F4, or Exit button!
		usedNative := RunDesktopWindow(appURL)
		if usedNative {
			cancel()
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 1*time.Second)
			_ = srv.Shutdown(shutCtx)
			shutCancel()
			os.Exit(0)
		}
		// Fallback idle monitor only when running in external fallback browser on legacy Server 2012/2016
		go func() {
			bootTime := time.Now()
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if logHub.ClientCount() > 0 {
						touchActivity()
						continue
					}
					idle := time.Since(time.Unix(0, lastActivityUnixN.Load()))
					if !everHadClient.Load() {
						if time.Since(bootTime) > 3*time.Minute {
							cancel()
							return
						}
						continue
					}
					if idle > 30*time.Second {
						cancel()
						return
					}
				}
			}
		}()
	} else {
		fmt.Printf("Kerio SSL & Let's Encrypt GUI listening on %s\n", appURL)
	}

	<-ctx.Done()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
}
