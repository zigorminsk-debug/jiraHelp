package main

// v46_test.go — тесты новых возможностей v4.6.0:
//   • автообновление программы (разбор версий, выбор релиза, SHA-256, «пропустить»);
//   • управление Kerio Connect на Linux (разбор ответов SSH, shell-скрипт, UI).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- версии -----------------------------------------------------------------

func TestParseVersionV46(t *testing.T) {
	cases := []struct {
		in      string
		major   int
		minor   int
		patch   int
		wantOK  bool
	}{
		{"v4.6.0", 4, 6, 0, true},
		{"4.6.0", 4, 6, 0, true},
		{"v10.0.12", 10, 0, 12, true},
		{"antispam-db-latest", 0, 0, 0, false},
		{"v4.6", 0, 0, 0, false},
		{"", 0, 0, 0, false},
		{"v4.6.0-beta", 0, 0, 0, false},
	}
	for _, c := range cases {
		major, minor, patch, ok := parseVersion(c.in)
		if ok != c.wantOK {
			t.Errorf("parseVersion(%q): ok=%v, ожидалось %v", c.in, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if major != c.major || minor != c.minor || patch != c.patch {
			t.Errorf("parseVersion(%q) = %d.%d.%d, ожидалось %d.%d.%d", c.in, major, minor, patch, c.major, c.minor, c.patch)
		}
	}
}

func TestCompareVersionsV46(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v4.6.0", "v4.5.2", 1},
		{"v4.5.2", "v4.6.0", -1},
		{"v4.6.0", "4.6.0", 0},
		{"v4.10.0", "v4.9.9", 1},
		{"v4.6.0", "мусор", 1},
	}
	for _, c := range cases {
		got := compareVersions(c.a, c.b)
		if (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("compareVersions(%q,%q) = %d, ожидался знак %d", c.a, c.b, got, c.want)
		}
	}
}

// TestPickNewestReleaseSkipsJunk — релиз базы антиспама (тег
// antispam-db-latest) и черновики не должны восприниматься как обновление
// программы, иначе программа предлагала бы «обновиться» на базу правил.
func TestPickNewestReleaseSkipsJunk(t *testing.T) {
	rels := []githubRelease{
		{TagName: "antispam-db-latest", Name: "AntiSpam DB"},
		{TagName: "v9.9.9", Draft: true},
		{TagName: "v9.9.8", Prerelease: true},
		{TagName: "v4.5.2"},
		{TagName: "v4.6.0"},
	}
	best := pickNewestRelease(rels)
	if best == nil {
		t.Fatal("pickNewestRelease вернул nil")
	}
	if best.TagName != "v4.6.0" {
		t.Fatalf("выбран релиз %q, ожидался v4.6.0", best.TagName)
	}
}

func TestReleaseToUpdateInfoAssetsV46(t *testing.T) {
	rel := &githubRelease{
		TagName:     "v4.6.0",
		HTMLURL:     "https://github.com/zigorminsk-debug/jiraHelp/releases/tag/v4.6.0",
		Body:        "## Что нового\n- установщик\n- Linux",
		PublishedAt: "2026-10-24T10:00:00Z",
		Assets: []githubAsset{
			{Name: "KerioCertManager-Setup-4.6.0.exe", Size: 9000000, URL: "https://x/setup.exe", Digest: "sha256:" + strings.Repeat("a", 64)},
			{Name: "KerioCertManager.exe", Size: 11000000, URL: "https://x/KerioCertManager.exe", Digest: "sha256:" + strings.Repeat("b", 64)},
			{Name: "KerioCertManager-Windows-x64.zip", Size: 6000000, URL: "https://x/zip"},
		},
	}
	info := releaseToUpdateInfo(rel, "4.5.2", false)
	if info.Latest != "4.6.0" {
		t.Errorf("Latest = %q", info.Latest)
	}
	if !info.Available {
		t.Error("Available должно быть true для 4.6.0 при текущей 4.5.2")
	}
	if info.ExeURL != "https://x/KerioCertManager.exe" {
		t.Errorf("ExeURL = %q", info.ExeURL)
	}
	if info.ExeSHA256 != strings.Repeat("b", 64) {
		t.Errorf("ExeSHA256 = %q, ожидалось 64 hex-символа из digest", info.ExeSHA256)
	}
	if info.SetupURL != "https://x/setup.exe" {
		t.Errorf("SetupURL = %q", info.SetupURL)
	}
	if info.ZipURL != "https://x/zip" {
		t.Errorf("ZipURL = %q", info.ZipURL)
	}
}

func TestReleaseToUpdateInfoNoUpdate(t *testing.T) {
	rel := &githubRelease{TagName: "v4.5.2"}
	info := releaseToUpdateInfo(rel, "4.5.2", false)
	if info.Available {
		t.Error("для той же версии Available должно быть false")
	}
}

func TestReleaseNotesForUIV46(t *testing.T) {
	notes := "## Что нового\n\n- Первое\n- Второе\n\nТехнические детали: `go build` и прочее.\n"
	lines := releaseNotesForUI(notes)
	if len(lines) == 0 {
		t.Fatal("releaseNotesForUI вернул пустой список")
	}
	joined := strings.Join(lines, " ")
	if strings.Contains(joined, "##") {
		t.Errorf("в заметках остался markdown-заголовок: %q", joined)
	}
	if !strings.Contains(joined, "Первое") {
		t.Errorf("потерялся пункт списка: %q", joined)
	}
	for _, l := range lines {
		if len(l) > 240 {
			t.Errorf("слишком длинная строка заметок (%d символов)", len(l))
		}
	}
}

// TestUpdateSkipAndInterval — «пропустить версию» и интервал автопроверки.
func TestUpdateSkipAndInterval(t *testing.T) {
	dir := t.TempDir()
	if !ShouldAutoCheck(dir) {
		t.Fatal("первая проверка должна быть разрешена (нет отметки о времени)")
	}
	markUpdateChecked(dir, "v4.6.0")
	s := LoadSavedUISettings(dir)
	if s.LastUpdateCheck == "" {
		t.Error("markUpdateChecked не сохранил время проверки")
	}
	if s.SkippedVersion != "v4.6.0" {
		t.Errorf("SkippedVersion = %q, ожидалось v4.6.0", s.SkippedVersion)
	}
	if ShouldAutoCheck(dir) {
		t.Error("сразу после проверки новый запрос к GitHub не нужен (интервал 6 часов)")
	}

	// Частичное сохранение из UI не должно стирать служебные поля.
	var partial SavedUISettings
	if err := json.Unmarshal([]byte(`{"lastDomain":"mail.company.by"}`), &partial); err != nil {
		t.Fatal(err)
	}
	merged := LoadSavedUISettings(dir)
	if err := json.Unmarshal([]byte(`{"lastDomain":"mail.company.by"}`), &merged); err != nil {
		t.Fatal(err)
	}
	if err := SaveUISettings(dir, merged); err != nil {
		t.Fatal(err)
	}
	after := LoadSavedUISettings(dir)
	if after.SkippedVersion != "v4.6.0" {
		t.Errorf("частичное сохранение стёрло SkippedVersion: %q", after.SkippedVersion)
	}
	if !after.AutoCheckUpdates {
		t.Error("частичное сохранение выключило автопроверку обновлений")
	}
	if after.LastDomain != "mail.company.by" {
		t.Errorf("LastDomain = %q", after.LastDomain)
	}
}

// TestUpdateCheckAgainstMockAPI — сквозная проверка с подменой GitHub API.
func TestUpdateCheckAgainstMockAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"tag_name":"antispam-db-latest","name":"DB","draft":false,"prerelease":false,
			 "assets":[]},
			{"tag_name":"v99.0.0","name":"v99","draft":false,"prerelease":false,
			 "html_url":"https://example/v99","body":"- Новая версия",
			 "published_at":"2026-10-24T10:00:00Z",
			 "assets":[{"name":"KerioCertManager.exe","size":123,"browser_download_url":"https://example/exe","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]}
		]`))
	}))
	defer srv.Close()

	old := os.Getenv("KCM_UPDATE_API")
	t.Setenv("KCM_UPDATE_API", srv.URL)
	defer func() {
		if old == "" {
			_ = os.Unsetenv("KCM_UPDATE_API")
		}
	}()

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	info, err := CheckForUpdate(ctx, dir)
	if err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}
	if !info.Available {
		t.Fatalf("обновление не найдено: %+v", info)
	}
	if info.Latest != "99.0.0" {
		t.Errorf("Latest = %q", info.Latest)
	}
	if info.ExeSHA256 != strings.Repeat("d", 64) {
		t.Errorf("ExeSHA256 = %q", info.ExeSHA256)
	}
}

// --- Linux ------------------------------------------------------------------

func TestParseKVLinuxProbe(t *testing.T) {
	out := "KCM_OS=Linux\nKCM_KERNEL=5.15.0\nшум\nKCM_KERIO=/opt/kerio/mailserver\nKCM_SERVICE=kerio-connect\nKCM_CF_SIZE=12345\n\n"
	kv := parseKV(out)
	if kv["KCM_OS"] != "Linux" {
		t.Errorf("KCM_OS = %q", kv["KCM_OS"])
	}
	if kv["KCM_KERIO"] != "/opt/kerio/mailserver" {
		t.Errorf("KCM_KERIO = %q", kv["KCM_KERIO"])
	}
	if kv["KCM_SERVICE"] != "kerio-connect" {
		t.Errorf("KCM_SERVICE = %q", kv["KCM_SERVICE"])
	}
	if kv["KCM_CF_SIZE"] != "12345" {
		t.Errorf("KCM_CF_SIZE = %q", kv["KCM_CF_SIZE"])
	}
	if _, ok := kv["шум"]; ok {
		t.Error("в разбор попала строка без префикса KCM_")
	}
}

func TestParseKVEmptyLinuxProbe(t *testing.T) {
	kv := parseKV("")
	if len(kv) != 0 {
		t.Errorf("ожидался пустой набор, получено %v", kv)
	}
}

func TestShellQuoteLinux(t *testing.T) {
	if got := shellQuote("/opt/kerio/mailserver"); got != "'/opt/kerio/mailserver'" {
		t.Errorf("shellQuote = %q", got)
	}
	got := shellQuote("a'b")
	if got != `'a'\''b'` {
		t.Errorf("shellQuote с апострофом = %q", got)
	}
}

func TestLinuxProbeScriptCoversStandardPaths(t *testing.T) {
	for _, want := range []string{
		"/opt/kerio/mailserver",
		"/usr/local/kerio/mailserver",
		"plugins/spamassassin/rules",
		"plugins/spamserver/spamassassin/rules",
		"kerio-connect",
		"systemctl is-active",
		"sslcert",
	} {
		if !strings.Contains(linuxProbeScript, want) {
			t.Errorf("в скрипте диагностики нет %q", want)
		}
	}
}

func TestLinuxInstallScript(t *testing.T) {
	script := LinuxInstallScript("https://example/kerio-antispam.cf")
	for _, want := range []string{
		"#!/bin/sh",
		"/opt/kerio/mailserver",
		"plugins/spamassassin/rules",
		"kerio-antispam.cf",
		"sha256sum",
		"systemctl restart",
		"backup-",
		"https://example/kerio-antispam.cf",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("в shell-скрипте нет %q", want)
		}
	}
	// Скрипт не должен требовать bash-специфики: Kerio часто ставят на минимальный дистрибутив.
	if strings.Contains(script, "[[") {
		t.Error("в скрипте используется bash-синтаксис [[ — нужен чистый sh")
	}
	if !strings.Contains(script, "от root") && !strings.Contains(script, "id -u") {
		t.Error("скрипт не проверяет права root")
	}
}

func TestExpandHomeLinux(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("домашний каталог не определён")
	}
	if got := expandHome("~/id_rsa"); got != filepath.Join(home, "id_rsa") && got != home+"/id_rsa" {
		t.Errorf("expandHome(~/id_rsa) = %q", got)
	}
	if got := expandHome("/abs/key"); got != "/abs/key" {
		t.Errorf("expandHome(/abs/key) = %q", got)
	}
}

func TestLinuxSSHConfigValidation(t *testing.T) {
	if _, _, err := buildSSHClientConfig(LinuxTarget{}); err == nil {
		t.Error("ожидалась ошибка: не указан сервер")
	}
	if _, _, err := buildSSHClientConfig(LinuxTarget{Host: "10.0.0.5"}); err == nil {
		t.Error("ожидалась ошибка: не указан пользователь")
	}
	if _, _, err := buildSSHClientConfig(LinuxTarget{Host: "10.0.0.5", User: "root"}); err == nil {
		t.Error("ожидалась ошибка: нет ни пароля, ни ключа")
	}
	if _, _, err := buildSSHClientConfig(LinuxTarget{Host: "10.0.0.5", User: "root", Password: "x"}); err != nil {
		t.Errorf("с паролем конфиг должен собираться: %v", err)
	}
}

// --- UI ---------------------------------------------------------------------

// TestUIV46UpdateBannerAndLinuxCard — разметка и обработчики новых карточек.
func TestUIV46UpdateBannerAndLinuxCard(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	for _, want := range []string{
		`id="updateBanner"`,
		`id="ubVersion"`,
		`id="ubInstallBtn"`,
		`id="ubSkipBtn"`,
		`function installUpdateNow(`,
		`function skipUpdateVersion(`,
		`function runUpdateCheck(`,
		`/api/update/check`,
		`/api/update/apply`,
		`/api/update/skip`,
		`id="updateSettingsCard"`,
		`id="autoUpdateCheck"`,
		// Linux
		`id="linuxKerioCard"`,
		`id="linuxHostInput"`,
		`id="linuxKeyInput"`,
		`id="linuxProbeBtn"`,
		`id="linuxInstallDbBtn"`,
		`id="linuxCertInstallBtn"`,
		`id="linuxScriptBtn"`,
		`/api/linux/probe`,
		`/api/linux/antispam-install`,
		`/api/linux/cert-install`,
		`/api/linux/script`,
		`function linuxProbe(`,
		`function linuxInstallDb(`,
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui/index.html: нет %q — карточка v4.6.0 развалилась", want)
		}
	}

	// Пароль SSH не должен сохраняться в настройках UI.
	if strings.Contains(ui, "linuxPassword:") || strings.Contains(ui, "linuxPass:") {
		t.Error("UI отправляет пароль SSH в /api/ui-settings — пароль не должен сохраняться")
	}
	// Ссылка «подробнее» должна вести на реальный раздел инструкции.
	anchors := map[string]bool{}
	for _, h := range HelpDocument().Headings {
		anchors[h.Anchor] = true
	}
	if !anchors["20-kerio-connect-на-linux"] {
		t.Error("в FAQ нет раздела 20 «Kerio Connect на Linux»")
	}
	if !anchors["918-куда-именно-класть-антиспам-базу-на-linux"] {
		t.Error("в FAQ нет раздела 9.18 «Куда именно класть антиспам-базу на Linux»")
	}
	if !anchors["21-установщик-и-автообновление-программы"] {
		t.Error("в FAQ нет раздела 21 «Установщик и автообновление программы»")
	}
}

// TestUIHasNoDuplicateIDs — дубли id ломают getElementById: половина
// обработчиков цепляется не к тому элементу (так «пропадала» карточка DNS-01).
func TestUIHasNoDuplicateIDs(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")
	seen := map[string]int{}
	for _, part := range strings.Split(ui, `id="`)[1:] {
		end := strings.IndexByte(part, '"')
		if end <= 0 {
			continue
		}
		seen[part[:end]]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("в ui/index.html id=%q встречается %d раза", id, n)
		}
	}
}

// --- установщик -------------------------------------------------------------

// TestInstallerVersionMatchesApp — версия в installer/KerioCertManager-Setup.iss
// обязана совпадать с appVersion, иначе Setup.exe будет называть одну версию,
// а внутри лежать другую (и автообновление «не увидит» новую сборку).
func TestInstallerVersionMatchesApp(t *testing.T) {
	iss := readRepoFile(t, "../installer/KerioCertManager-Setup.iss")
	if !strings.Contains(iss, `#define MyAppVersion "`+appVersion+`"`) {
		t.Errorf("installer/KerioCertManager-Setup.iss: MyAppVersion не равна appVersion %q", appVersion)
	}
	if !strings.Contains(iss, "PrivilegesRequired=admin") {
		t.Error("установщик должен требовать права администратора (PrivilegesRequired=admin)")
	}
	if !strings.Contains(iss, "DisableDirPage=auto") {
		t.Error("в установщике пропал DisableDirPage=auto (страница выбора папки для опытных)")
	}
	for _, want := range []string{
		`AppId={{BE09222C-7D93-4DBC-AAC0-FA7C07609B8B}`,
		`KerioLetsEncryptAutoRenew`,
		`KerioCertManager_AntiSpamDB`,
		`uninsneveruninstall`, // папка certs не должна удаляться
		`desktopicon`,
		`{group}\{#MyAppName}`,
	} {
		if !strings.Contains(iss, want) {
			t.Errorf("installer/KerioCertManager-Setup.iss: нет %q", want)
		}
	}
}

// TestCIBuildsInstaller — установщик собирается в CI (в песочнице Inno Setup
// недоступен, поэтому проверяем сам workflow).
func TestCIBuildsInstaller(t *testing.T) {
	wf := readRepoFile(t, "../.github/workflows/build-windows.yml")
	for _, want := range []string{
		"innosetup",
		"ISCC.exe",
		"KerioCertManager-Setup.iss",
		"KerioCertManager-Setup-",
		"windows-latest",
	} {
		if !strings.Contains(wf, want) {
			t.Errorf(".github/workflows/build-windows.yml: нет %q — установщик не попадёт в релиз", want)
		}
	}
}
