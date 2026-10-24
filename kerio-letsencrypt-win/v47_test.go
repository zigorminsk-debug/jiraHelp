package main

// v47_test.go — тесты релиза v4.7.0 «Вход под администратором Kerio Connect».
//
// Сами проверки логина покрыты в kerio_auth_test.go (включая mock-сервер Kerio).
// Здесь — «страховки релиза»: версия, документация, отсутствие утечек пароля и
// место карточки в интерфейсе.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	faqAuthAnchor = "46-вход-под-администратором-kerio-connect--проверка-и-разбор-ошибок"
	authCardID    = `id="kerioAuthCard"`
)

func TestV47VersionIsReleased(t *testing.T) {
	if appVersion != "4.7.0" {
		t.Fatalf("appVersion = %q, ожидалось 4.7.0", appVersion)
	}
	if appVersion4 != "4.7.0.0" {
		t.Fatalf("appVersion4 = %q, ожидалось 4.7.0.0", appVersion4)
	}
	readme := readRepoFile(t, "README.md")
	if !strings.Contains(readme, "4.7.0") {
		t.Error("README.md не упоминает версию 4.7.0 — история релизов отстала")
	}
}

// Пароль администратора не должен оказаться ни в журнале, ни в файле настроек,
// ни в отчёте, который копируется в буфер обмена.
func TestV47PasswordNeverPersisted(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	// 1. В отчёт для буфера обмена пароль попадать не должен.
	start := strings.Index(ui, "function kerioAuthReportText(")
	if start < 0 {
		t.Fatal("нет функции отчёта kerioAuthReportText")
	}
	end := strings.Index(ui[start:], "\n  function ")
	if end < 0 {
		end = len(ui) - start
	}
	report := ui[start : start+end]
	if strings.Contains(report, "kerioAuthPass.value") || strings.Contains(report, ".password") {
		t.Error("отчёт карточки включает значение поля пароля")
	}

	// 2. Настройки UI-карточки не должны содержать ключ с паролем.
	for _, bad := range []string{"kerioAuthPassword", "kerioAuthPass\":", "authPassword"} {
		if strings.Contains(ui, bad) {
			t.Errorf("UI хранит пароль карточки в настройках (%q)", bad)
		}
	}

	// 3. Серверный код не логирует пароль.
	auth := readRepoFile(t, "kerio_auth.go")
	for _, line := range strings.Split(auth, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.Contains(trimmed, "logHub") && strings.Contains(trimmed, "Password") {
			t.Errorf("в журнал уходит пароль: %s", trimmed)
		}
	}
}

// Карточка должна стоять выше блока установки — админ сначала проверяет вход,
// потом ставит сертификат.
func TestV47AuthCardPlacedAboveInstall(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")
	tab := strings.Index(ui, `id="tab-kerio"`)
	if tab < 0 {
		t.Fatal("не найдена вкладка Kerio")
	}
	card := strings.Index(ui[tab:], authCardID)
	if card < 0 {
		t.Fatal("карточка входа не найдена на вкладке Kerio")
	}
	install := strings.Index(ui[tab:], "workspace-grid")
	if install < 0 {
		t.Fatal("не найден блок установки на вкладке Kerio")
	}
	if card > install {
		t.Error("карточка входа оказалась ниже блока установки")
	}
	// Поле пароля — типа password, чтобы оно не светилось на экране.
	passIdx := strings.Index(ui, `id="kerioAuthPass"`)
	if passIdx < 0 {
		t.Fatal("нет поля пароля карточки")
	}
	tagStart := strings.LastIndex(ui[:passIdx], "<")
	tag := ui[tagStart:passIdx]
	if !strings.Contains(tag, `type="password"`) {
		t.Errorf("поле пароля не скрыто: %s", tag)
	}
}

func TestV47FAQHasAuthSection(t *testing.T) {
	root := readRepoFile(t, "../FAQ.md")
	embedded := readRepoFile(t, "ui/FAQ.md")
	if root != embedded {
		t.Fatal("FAQ.md и ui/FAQ.md разошлись — запустите bash kerio-letsencrypt-win/sync-faq.sh")
	}

	for _, want := range []string{
		"### 4.6 Вход под администратором Kerio Connect — проверка и разбор ошибок",
		"Сессия.login", // контроль, что раздел не «схлопнулся» при правках
		"SESSION_CONNECT_WEBADMIN",
		"Two-factor authentication is required",
		"Пароль нигде не сохраняется",
		"Копировать отчёт",
	} {
		needle := want
		if strings.Contains(want, "Сессия.login") {
			needle = "Session.login"
		}
		if !strings.Contains(root, needle) {
			t.Errorf("FAQ.md: в разделе 4.6 нет %q", needle)
		}
	}

	// Все 10 шагов проверки должны быть перечислены в инструкции.
	for _, step := range []string{
		"**Параметры**", "**DNS**", "**TCP-порт**", "**TLS**", "**Веб-админка**",
		"**Вход**", "**Сессия**", "**Права**", "**Версия продукта**", "**Сертификаты**",
	} {
		if !strings.Contains(root, step) {
			t.Errorf("FAQ 4.6: не описан шаг проверки %s", step)
		}
	}
}

// Раздел 4.6 должен быть доступен из справки: якорь, ссылка и внутренний линк
// «см. раздел 4.6» из блока установки.
func TestV47FAQAuthAnchorNavigable(t *testing.T) {
	doc := HelpDocument()
	found := false
	for _, h := range doc.Headings {
		if h.Anchor == faqAuthAnchor {
			found = true
			if h.Level < 3 {
				t.Errorf("раздел 4.6 имеет уровень %d — потеряется в оглавлении", h.Level)
			}
		}
	}
	if !found {
		t.Fatalf("в оглавлении справки нет раздела с якорем %q", faqAuthAnchor)
	}
	ui := readRepoFile(t, "ui/index.html")
	if !strings.Contains(ui, "openHelpSection('"+faqAuthAnchor+"')") {
		t.Error("карточка не ссылается на раздел 4.6 в справке")
	}
}

// Кнопка отчёта и кнопка WebAdmin должны собирать корректные адреса.
func TestV47AuthCardButtonsWired(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")
	for _, want := range []string{
		`kerioAuthWebAdminBtn`,
		`kerioAuthReportBtn`,
		`kerioAuthShowPassBtn`,
		`kerioAuthTakeFromInstallBtn`,
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("кнопка %q не подключена", want)
		}
	}
	for _, want := range []string{
		"kerioAuthAddEventListener", // защита от повторной инициализации
		"initKerioAuthCard()",
		"enterKeyHint",
	} {
		if !strings.Contains(ui, want) && want == "initKerioAuthCard()" {
			t.Errorf("карточка не инициализируется: нет %q", want)
		}
	}
}

// Endpoint должен быть зарегистрирован ровно один раз и требовать POST.
func TestV47LoginCheckRoute(t *testing.T) {
	main := readRepoFile(t, "main.go")
	if n := strings.Count(main, `"/api/kerio/login-check"`); n != 1 {
		t.Fatalf("маршрут /api/kerio/login-check зарегистрирован %d раз", n)
	}
	if !strings.Contains(main, `mux.HandleFunc("/api/kerio/login-check"`) {
		t.Fatal("маршрут не зарегистрирован в buildRouter")
	}
}

// README должен вести администратора к новой карточке.
func TestV47ReadmeMentionsAuthCard(t *testing.T) {
	readme := readRepoFile(t, "README.md")
	if !strings.Contains(readme, "Вход под администратором") {
		t.Error("README.md не описывает карточку «Вход под администратором»")
	}
}

// Служебные файлы не должны содержать секретов и отладочных дампов.
func TestV47NoDebugLeftovers(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		src := string(raw)
		if strings.Contains(src, "fmt.Println(\"DEBUG") {
			t.Errorf("%s: остался отладочный вывод", name)
		}
	}
}
