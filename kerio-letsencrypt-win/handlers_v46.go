package main

// handlers_v46.go — HTTP-обвязка новых возможностей v4.6.0:
//   • автообновление программы (проверка, скачивание, «пропустить версию»);
//   • работа с Kerio Connect на Linux по SSH (диагностика, установка базы,
//     установка сертификата, перезапуск службы, готовый shell-скрипт).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func registerV46Routes(mux *http.ServeMux) {
	registerUpdateRoutes(mux)
	registerLinuxRoutes(mux)
	registerAndroidApkRoutes(mux)
}

// ---------------------------------------------------------------------------
// Автообновление программы
// ---------------------------------------------------------------------------

func registerUpdateRoutes(mux *http.ServeMux) {
	// GET /api/update/check[?force=1] — узнать про новую версию.
	mux.HandleFunc("/api/update/check", func(w http.ResponseWriter, r *http.Request) {
		certsDir := DefaultCertsRoot()
		force := r.URL.Query().Get("force") != ""
		settings := LoadSavedUISettings(certsDir)
		if !force && !settings.AutoCheckUpdates {
			writeJSON(w, 200, map[string]any{
				"ok":        true,
				"autoCheck": false,
				"info": UpdateInfo{
					Current:   appVersion,
					AutoCheck: false,
				},
				"message": "Автопроверка обновлений выключена в настройках.",
			})
			return
		}
		if !force && !ShouldAutoCheck(certsDir) {
			// Не дёргаем GitHub чаще, чем раз в 6 часов.
			writeJSON(w, 200, map[string]any{
				"ok":        true,
				"cached":    true,
				"autoCheck": true,
				"info": UpdateInfo{
					Current:   appVersion,
					Available: false,
					AutoCheck: true,
					Skipped:   settings.SkippedVersion != "",
				},
				"lastCheck": settings.LastUpdateCheck,
			})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		info, err := CheckForUpdate(ctx, certsDir)
		resp := map[string]any{"ok": err == nil, "info": info}
		if err != nil {
			// Ошибка сети — не повод ругаться: UI просто не покажет баннер.
			resp["error"] = err.Error()
		} else if info.Available {
			resp["notes"] = releaseNotesForUI(info.Notes)
			resp["skipped"] = info.Skipped
			logHub.Emit("info", fmt.Sprintf("Доступна новая версия KerioCertManager: %s (у вас %s).", info.Latest, appVersion))
		}
		writeJSON(w, 200, resp)
	})

	// POST /api/update/apply — скачать, проверить SHA-256, подменить .exe и перезапуститься.
	mux.HandleFunc("/api/update/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var info UpdateInfo
		if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
			writeErr(w, 400, err)
			return
		}
		if strings.TrimSpace(info.ExeURL) == "" {
			writeErr(w, 400, fmt.Errorf("не указана ссылка на файл обновления (exeUrl)"))
			return
		}
		certsDir := DefaultCertsRoot()
		logHub.Emit("info", "Загрузка обновления KerioCertManager "+info.Latest+"…")
		lastMsg := ""
		progress := func(msg string) {
			if msg == "" || msg == lastMsg {
				return
			}
			lastMsg = msg
			logHub.Emit("info", msg)
		}
		path, err := ApplyUpdate(info, progress)
		if err != nil {
			logHub.Emit("error", "Обновление не применено: "+err.Error())
			writeErr(w, 400, err)
			return
		}
		markUpdateChecked(certsDir, "")
		logHub.Emit("success", "Обновление "+info.Latest+" установлено, программа перезапускается.")
		// Новая копия уже запущена. Закрываем текущее окно, чтобы не висели
		// два интерфейса: новый процесс сам займёт порт 17840.
		go func() {
			time.Sleep(1200 * time.Millisecond)
			CloseDesktopWindow()
		}()
		writeJSON(w, 200, map[string]any{
			"ok":      true,
			"version": info.Latest,
			"path":    path,
			"restart": true,
			"message": "Обновление установлено. Программа перезапускается автоматически.",
		})
	})

	// POST /api/update/skip — «пропустить эту версию».
	mux.HandleFunc("/api/update/skip", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var body struct {
			Version string `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		certsDir := DefaultCertsRoot()
		markUpdateChecked(certsDir, strings.TrimSpace(body.Version))
		logHub.Emit("info", "Версия "+body.Version+" пропущена — баннер больше не показывается.")
		writeJSON(w, 200, map[string]any{"ok": true, "skipped": body.Version})
	})

	// GET/POST /api/update/settings — переключатель автопроверки.
	mux.HandleFunc("/api/update/settings", func(w http.ResponseWriter, r *http.Request) {
		certsDir := DefaultCertsRoot()
		settings := LoadSavedUISettings(certsDir)
		if r.Method == http.MethodGet {
			writeJSON(w, 200, map[string]any{
				"ok":        true,
				"autoCheck": settings.AutoCheckUpdates,
				"lastCheck": settings.LastUpdateCheck,
				"skipped":   settings.SkippedVersion,
				"current":   appVersion,
			})
			return
		}
		var body struct {
			AutoCheck *bool `json:"autoCheck"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		if body.AutoCheck != nil {
			settings.AutoCheckUpdates = *body.AutoCheck
			if err := SaveUISettings(certsDir, settings); err != nil {
				writeErr(w, 500, err)
				return
			}
		}
		writeJSON(w, 200, map[string]any{"ok": true, "autoCheck": settings.AutoCheckUpdates})
	})

	// POST /api/update/cleanup — удалить <exe>.old и папку update-tmp.
	mux.HandleFunc("/api/update/cleanup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		CleanupOldBinaries()
		writeJSON(w, 200, map[string]any{"ok": true})
	})
}

// ---------------------------------------------------------------------------
// Kerio на Linux по SSH
// ---------------------------------------------------------------------------

// decodeLinuxTarget читает параметры подключения из тела запроса.
func decodeLinuxTarget(r *http.Request) (LinuxTarget, error) {
	var t LinuxTarget
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		return t, err
	}
	t.Host = strings.TrimSpace(t.Host)
	t.User = strings.TrimSpace(t.User)
	if t.Host == "" {
		return t, fmt.Errorf("укажите адрес сервера (IP или имя), например 10.0.0.5")
	}
	if t.User == "" {
		t.User = "root"
	}
	if t.Port <= 0 {
		t.Port = 22
	}
	// Дополняем пустые поля значениями из сохранённых настроек, чтобы админ
	// не вводил их заново при каждой операции.
	settings := LoadSavedUISettings(DefaultCertsRoot())
	if settings.LinuxKerioDir != "" && t.KerioDir == "" {
		t.KerioDir = settings.LinuxKerioDir
	}
	if settings.LinuxService != "" && t.Service == "" {
		t.Service = settings.LinuxService
	}
	return t, nil
}

// rememberLinuxTarget сохраняет общие параметры (без пароля!) в настройки.
func rememberLinuxTarget(t LinuxTarget, res LinuxProbeResult) {
	certsDir := DefaultCertsRoot()
	settings := LoadSavedUISettings(certsDir)
	settings.LinuxHost = t.Host
	settings.LinuxPort = t.Port
	settings.LinuxUser = t.User
	settings.LinuxKeyPath = t.KeyPath
	if res.KerioDir != "" {
		settings.LinuxKerioDir = res.KerioDir
	}
	if res.ServiceName != "" {
		settings.LinuxService = res.ServiceName
	}
	if res.HostFingerprint != "" {
		settings.LinuxKnownHost = res.HostFingerprint
	}
	_ = SaveUISettings(certsDir, settings)
}

func registerLinuxRoutes(mux *http.ServeMux) {
	// POST /api/linux/probe — подключиться и рассказать, что на сервере.
	mux.HandleFunc("/api/linux/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		t, err := decodeLinuxTarget(r)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		res := ProbeLinuxKerio(ctx, t)
		if res.Connected {
			rememberLinuxTarget(t, res)
			if saved := LoadSavedUISettings(DefaultCertsRoot()).LinuxKnownHost; saved != "" && res.HostFingerprint != "" && saved != res.HostFingerprint {
				res.Steps = append(res.Steps, "⚠️ Отпечаток ключа сервера изменился! Было: "+saved+", стало: "+res.HostFingerprint+
					". Если сервер не переустанавливали — это повод проверить, тот ли это хост.")
			}
		}
		if res.OK {
			logHub.Emit("success", fmt.Sprintf("Linux %s: Kerio Connect найден (%s), служба %s — %s.",
				t.Host, res.KerioDir, res.ServiceName, res.ServiceActive))
		} else {
			logHub.Emit("warning", "Проверка Linux-сервера: "+firstNonEmpty(res.Error, "см. шаги диагностики"))
		}
		writeJSON(w, 200, res)
	})

	// POST /api/linux/antispam-install — залить базу в Kerio на Linux.
	mux.HandleFunc("/api/linux/antispam-install", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var body struct {
			LinuxTarget
			RuleURL string `json:"ruleUrl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		t := body.LinuxTarget
		if strings.TrimSpace(t.Host) == "" {
			writeErr(w, 400, fmt.Errorf("укажите адрес сервера"))
			return
		}
		if t.Port <= 0 {
			t.Port = 22
		}
		if strings.TrimSpace(t.User) == "" {
			t.User = "root"
		}

		// Куда класть: поле из формы → результаты диагностики → стандарт.
		remoteDir := strings.TrimSpace(t.KerioDir)
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()

		client, _, err := sshDial(t)
		if err != nil {
			logHub.Emit("error", "SSH: "+err.Error())
			writeErr(w, 400, err)
			return
		}
		defer client.Close()

		if remoteDir == "" {
			out, _, _ := sshRun(client, linuxProbeScript)
			kv := parseKV(out)
			remoteDir = firstNonEmpty(kv["KCM_RULES"], kv["KCM_KERIO"])
			if remoteDir != "" && !strings.HasSuffix(remoteDir, "/rules") {
				if p := remoteDir + "/plugins/spamassassin/rules"; p != "" {
					remoteDir = p
				}
			}
		}
		if remoteDir == "" {
			writeErr(w, 400, fmt.Errorf("не удалось определить каталог правил SpamAssassin на сервере — укажите его вручную, например /opt/kerio/mailserver/plugins/spamassassin/rules"))
			return
		}
		remoteDir = strings.TrimSuffix(remoteDir, "/")

		data, err := antiSpamRuleBytes(DefaultCertsRoot())
		if err != nil {
			writeErr(w, 502, err)
			return
		}
		res := deployToLinuxClient(ctx, client, t, remoteDir, antiSpamRuleFileName, data, t.Restart)
		if res.OK {
			logHub.Emit("success", "База антиспама загружена на "+t.Host+": "+res.RemotePath)
		} else {
			logHub.Emit("error", "Загрузка базы на "+t.Host+" не удалась: "+strings.Join(res.Steps, " | "))
		}
		writeJSON(w, 200, res)
	})

	// POST /api/linux/antispam-status — есть ли база и какая версия.
	mux.HandleFunc("/api/linux/antispam-status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		t, err := decodeLinuxTarget(r)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		res := ProbeLinuxKerio(ctx, t)
		writeJSON(w, 200, res)
	})

	// POST /api/linux/cert-install — положить выданный сертификат в sslcert.
	mux.HandleFunc("/api/linux/cert-install", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		var body struct {
			LinuxTarget
			CertID  string `json:"certId"`
			CertDir string `json:"certDir"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, err)
			return
		}
		t := body.LinuxTarget
		if t.Port <= 0 {
			t.Port = 22
		}
		if t.User == "" {
			t.User = "root"
		}
		if strings.TrimSpace(body.CertID) == "" {
			writeErr(w, 400, fmt.Errorf("не выбран сертификат (certId)"))
			return
		}
		rec, err := LoadSingleCertRecord(body.CertDir, body.CertID, false)
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		crtPath := rec.Files["serverCrt"]
		keyPath := rec.Files["serverKey"]
		crt, err := os.ReadFile(crtPath)
		if err != nil {
			writeErr(w, 500, fmt.Errorf("не удалось прочитать сертификат %s: %w", crtPath, err))
			return
		}
		key, err := os.ReadFile(keyPath)
		if err != nil {
			writeErr(w, 500, fmt.Errorf("не удалось прочитать ключ %s: %w", keyPath, err))
			return
		}
		remoteRoot := firstNonEmpty(strings.TrimSpace(t.KerioDir), "/opt/kerio/mailserver")
		sslDir := remoteRoot
		if !strings.HasSuffix(sslDir, "/sslcert") {
			sslDir = strings.TrimSuffix(sslDir, "/") + "/sslcert"
		}

		client, _, err := sshDial(t)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		defer client.Close()

		steps := []string{}
		warn := []string{}
		ok := true
		for _, f := range []struct {
			name string
			data []byte
			mode string
		}{{"server.crt", crt, "644"}, {"server.key", key, "600"}} {
			sum, uerr := uploadFileRemote(client, sslDir+"/"+f.name, f.data, t.Sudo || !probeIsRoot(client))
			if uerr != nil {
				steps = append(steps, "ошибка загрузки "+f.name+": "+uerr.Error())
				ok = false
				break
			}
			steps = append(steps, fmt.Sprintf("%s загружен (%d байт, SHA-256 %s…)", f.name, len(f.data), safePrefix(sum, 12)))
			// Права: ключ только для владельца.
			_ = f.mode
		}
		if ok {
			chmodCmd := ""
			if t.Sudo || !probeIsRoot(client) {
				chmodCmd = "sudo -n "
			}
			chmodCmd += "sh -c " + shellQuote("chmod 644 "+shellQuote(sslDir+"/server.crt")+" && chmod 600 "+shellQuote(sslDir+"/server.key")+
				" && chown kerio:kerio "+shellQuote(sslDir+"/server.crt")+" "+shellQuote(sslDir+"/server.key")+" 2>/dev/null; true")
			if out, code, cerr := sshRun(client, chmodCmd); cerr == nil && code != 0 {
				warn = append(warn, "не удалось выставить права/владельца: "+strings.TrimSpace(lastLines(out, 2)))
			}
			if t.Restart {
				svc := firstNonEmpty(strings.TrimSpace(t.Service), "kerio-connect")
				pfx := ""
				if t.Sudo || !probeIsRoot(client) {
					pfx = "sudo -n "
				}
				if out, code, cerr := sshRun(client, pfx+"systemctl restart "+shellQuote(svc)); cerr != nil || code != 0 {
					warn = append(warn, "служба не перезапущена: "+strings.TrimSpace(lastLines(out, 2))+" — выполните: sudo systemctl restart "+svc)
				} else {
					steps = append(steps, "Служба "+svc+" перезапущена — новый сертификат активен.")
				}
			} else {
				steps = append(steps, "Перезапустите Kerio вручную, чтобы подхватить сертификат: sudo systemctl restart kerio-connect")
			}
			logHub.Emit("success", "Сертификат "+rec.PrimaryDomain+" установлен на "+t.Host+" в "+sslDir)
		}
		writeJSON(w, 200, map[string]any{
			"ok":         ok,
			"sslDir":     sslDir,
			"steps":      steps,
			"warnings":   warn,
			"primaryDom": rec.PrimaryDomain,
		})
	})

	// POST /api/linux/restart — перезапустить службу Kerio на Linux.
	mux.HandleFunc("/api/linux/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, fmt.Errorf("method not allowed"))
			return
		}
		t, err := decodeLinuxTarget(r)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		client, _, err := sshDial(t)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		defer client.Close()
		svc := firstNonEmpty(strings.TrimSpace(t.Service), "kerio-connect")
		pfx := ""
		if t.Sudo || !probeIsRoot(client) {
			pfx = "sudo -n "
		}
		cmd := pfx + "sh -c " + shellQuote("systemctl restart "+shellQuote(svc)+" 2>/dev/null || service "+shellQuote(svc)+" restart")
		out, code, rerr := sshRun(client, cmd)
		if rerr != nil || code != 0 {
			msg := strings.TrimSpace(lastLines(out, 5))
			if msg == "" && rerr != nil {
				msg = rerr.Error()
			}
			logHub.Emit("error", "Перезапуск "+svc+" на "+t.Host+": "+msg)
			writeErr(w, 400, fmt.Errorf("не удалось перезапустить %s: %s", svc, msg))
			return
		}
		logHub.Emit("success", "Служба "+svc+" перезапущена на "+t.Host+".")
		writeJSON(w, 200, map[string]any{"ok": true, "service": svc, "output": strings.TrimSpace(lastLines(out, 5))})
	})

	// GET /api/linux/script — готовый shell-скрипт установки базы.
	mux.HandleFunc("/api/linux/script", func(w http.ResponseWriter, r *http.Request) {
		script := LinuxInstallScript(strings.TrimSpace(r.URL.Query().Get("url")))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="install-kcm-antispam.sh"`)
		_, _ = w.Write([]byte(script))
	})
}

// deployToLinuxClient — общая часть установки файла на Linux при уже открытом
// SSH-соединении (используется обработчиками базы и сертификатов).
func deployToLinuxClient(ctx context.Context, client *ssh.Client, t LinuxTarget, remoteDir, fileName string, content []byte, restart bool) LinuxDeployResult {
	_ = ctx
	res := LinuxDeployResult{Steps: []string{}, Warnings: []string{}}
	sudo := t.Sudo || !probeIsRoot(client)
	target := strings.TrimSuffix(remoteDir, "/") + "/" + fileName
	sum, err := uploadFileRemote(client, target, content, sudo)
	if err != nil {
		res.Steps = append(res.Steps, "ошибка загрузки: "+err.Error())
		return res
	}
	res.RemotePath = target
	res.SHA256 = sum
	res.Size = int64(len(content))
	res.Steps = append(res.Steps,
		fmt.Sprintf("SSH-подключение к %s:%d установлено.", t.Host, portOr22(t.Port)),
		fmt.Sprintf("Файл загружен: %s (%d байт), SHA-256 подтверждён на сервере.", target, len(content)))
	if restart {
		svc := firstNonEmpty(strings.TrimSpace(t.Service), "kerio-connect")
		pfx := ""
		if sudo {
			pfx = "sudo -n "
		}
		cmd := pfx + "sh -c " + shellQuote("systemctl restart "+shellQuote(svc)+" 2>/dev/null || service "+shellQuote(svc)+" restart")
		out, code, err := sshRun(client, cmd)
		if err != nil || code != 0 {
			res.RestartErr = strings.TrimSpace(lastLines(out, 4))
			res.Warnings = append(res.Warnings, "Служба не перезапущена автоматически — выполните: sudo systemctl restart "+svc)
			res.OK = true
			return res
		}
		res.Restarted = true
		res.Steps = append(res.Steps, "Служба "+svc+" перезапущена — правила применены.")
	} else {
		res.Steps = append(res.Steps, "Перезапуск не запрашивался: правила начнут действовать после рестарта Kerio.")
	}
	res.OK = true
	return res
}

// antiSpamRuleBytes — берёт файл правил так же, как «Скачать .cf»:
// установленный → самая свежая резервная копия → GitHub.
func antiSpamRuleBytes(certsDir string) ([]byte, error) {
	st := LoadAntiSpamState(certsDir)
	if p := strings.TrimSpace(st.RulePath); p != "" {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	if backups, err := filepath.Glob(filepath.Join(antiSpamBackupDir(certsDir), "*.cf")); err == nil && len(backups) > 0 {
		sortStrings(backups)
		if b, err := os.ReadFile(backups[len(backups)-1]); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	remote, err := fetchAntiSpamManifest()
	if err != nil {
		return nil, fmt.Errorf("нет локальной копии базы и не удалось скачать её с GitHub: %w", err)
	}
	return verifyAndDownload(remote.BaseURL, antiSpamRuleFileName, remote.Manifest.RuleSHA())
}

// sortStrings — маленькая обёртка, чтобы не тянуть sort в этот файл ради одного вызова.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// safePrefix — первые n символов строки (для логов).
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// sha256HexBytes — SHA-256 в hex (хелпер для тестов и логов).
func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
