package main

// v471_test.go — тесты релиза v4.7.1 «понятное устранение отказа в правах на SSL».
//
// История: в v4.7.0 причина «нет доступа к SSL-сертификатам» отправляла
// администратора в несуществующий раздел «Configuration → Administration →
// Administrators → свойства → полный доступ». По факту в Kerio Connect права
// живут в карточке пользователя (Accounts → Users → вкладка Rights), а для
// автоматизации есть встроенная учётка Admin (Configuration → Administration
// Settings). Эти тесты фиксируют правильные пути и то, что подсказка не
// «схлопнется» обратно в одну невнятную строку.

import (
	"strings"
	"testing"
)

const certsHelpAnchor = "461-вход-есть-а-ssl-сертификаты-не-читаются"

func causeByCode(t *testing.T, code string) KerioAuthCause {
	t.Helper()
	c := kerioAuthCause(code)
	if c.Code != code {
		t.Fatalf("kerioAuthCause(%q).Code = %q", code, c.Code)
	}
	return c
}

func joinedSteps(c KerioAuthCause) string { return strings.Join(c.Steps, "\n") }

// Главный тест релиза: инструкция по «нет прав на сертификаты» должна
// содержать реальные пути Kerio Connect, а не абстрактное «выдайте права».
func TestV471CertsCauseIsActionable(t *testing.T) {
	c := causeByCode(t, "certs")

	if c.Severity != "block" {
		t.Errorf("certs: severity = %q, ожидалось block", c.Severity)
	}
	if len(c.Steps) < 5 {
		t.Fatalf("certs: шагов %d, ожидалось не меньше 5 (полный разбор)", len(c.Steps))
	}
	for _, want := range []string{
		// Простое объяснение, почему отказ пришёл ПОСЛЕ успешного входа.
		"Пароль верный",
		"ниже «весь сервер, чтение и запись»",
		// Способ 1 — встроенная учётка.
		"Configuration → Administration Settings",
		"Enable built-in administrator account",
		"Admin",
		// Способ 2 — права на существующую учётку.
		"Accounts → Users",
		"Rights",
		"Whole server read/write",
		"Whole server read only",
		// Проверка результата.
		"Configuration → SSL Certificates",
		// Запасной путь и границы применимости.
		"sslcert",
		"Kerio Control",
	} {
		if !strings.Contains(joinedSteps(c), want) {
			t.Errorf("certs: в шагах нет %q", want)
		}
	}
	if !strings.Contains(c.Explanation, "Kerio пустил") && !strings.Contains(c.Explanation, "пустил вас в админку") {
		t.Errorf("certs: объяснение не говорит, что вход прошёл, а отказ — по правам: %q", c.Explanation)
	}
	if !strings.Contains(c.CheckWhere, "Accounts → Users") || !strings.Contains(c.CheckWhere, "Rights") {
		t.Errorf("certs: «где проверить» не указывает реальный путь: %q", c.CheckWhere)
	}
	if c.Anchor != certsHelpAnchor {
		t.Errorf("certs: anchor = %q, ожидался %q", c.Anchor, certsHelpAnchor)
	}
}

// Старый текст отправлял в «Configuration → Administration → Administrators».
// В Kerio Connect 9.x такого пути для прав нет — не даём вернуться.
func TestV471NoPhantomAdminPath(t *testing.T) {
	for _, code := range []string{"certs", "rights", "otp"} {
		c := causeByCode(t, code)
		all := c.Explanation + "\n" + joinedSteps(c) + "\n" + c.CheckWhere
		if strings.Contains(all, "Administration → Administrators") {
			t.Errorf("%s: снова неверный путь «Administration → Administrators»", code)
		}
		if !strings.Contains(all, "Accounts → Users") {
			t.Errorf("%s: нет реального пути «Accounts → Users»", code)
		}
	}
	// Встроенная учётка — отдельный, самый короткий путь.
	if !strings.Contains(joinedSteps(causeByCode(t, "certs")), "Administration Settings") {
		t.Error("certs: потерян способ с встроенной учёткой Admin")
	}
}

// Подсказка не должна врать про «read only»: Kerio пустит в админку,
// но API-команды вернут отказ, поэтому нужен именно read/write.
func TestV471ReadOnlyIsExplained(t *testing.T) {
	c := causeByCode(t, "certs")
	if !strings.Contains(joinedSteps(c), "Whole server read only") {
		t.Error("certs: не сказано, что режим «только чтение» не подходит")
	}
	if !strings.Contains(joinedSteps(c), "не «<домен> accounts»") {
		t.Error("certs: не сказано, что прав администратора домена недостаточно")
	}
}

// Кнопка «Как исправить по шагам» ведёт в раздел, который реально есть в справке.
func TestV471CertsHelpAnchorExists(t *testing.T) {
	anchors := map[string]bool{}
	for _, h := range HelpDocument().Headings {
		anchors[h.Anchor] = true
	}
	if !anchors[certsHelpAnchor] {
		t.Fatalf("в справке нет раздела с якорем %q", certsHelpAnchor)
	}
	for _, code := range []string{"certs", "rights", "otp"} {
		if a := causeByCode(t, code).Anchor; a != "" && !anchors[a] {
			t.Errorf("%s: якорь %q не найден в справке", code, a)
		}
	}
}

// Раздел §4.6.1 должен содержать таблицу уровней доступа и оба способа.
func TestV471FAQSectionContent(t *testing.T) {
	faq := readRepoFile(t, "../FAQ.md")
	for _, want := range []string{
		"#### 4.6.1 Вход есть, а SSL-сертификаты не читаются",
		"| **Whole server read/write** |",
		"Enable built-in administrator account",
		"Accounts → Users",
		"Configuration → Administration Settings",
		"Configuration → SSL Certificates",
		"Как убедиться, что получилось",
		"файловым методом",
	} {
		if !strings.Contains(faq, want) {
			t.Errorf("FAQ.md: в §4.6.1 нет %q", want)
		}
	}
	// Ссылка из таблицы причин должна вести на новый подраздел.
	if !strings.Contains(faq, "§4.6.1") {
		t.Error("FAQ.md: таблица §4.6 не ссылается на §4.6.1")
	}
}

// Интерфейс: под причиной есть точный ответ Kerio и кнопка справки.
func TestV471UIShowsKerioAnswerAndHelpButton(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")
	for _, want := range []string{
		"Ответ Kerio: ",
		"Ответ Kerio (сертификаты): ",
		"data-help-anchor",
		"Как исправить по шагам",
		"openHelpSection(b.getAttribute('data-help-anchor'))",
		"res.certsError",
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui/index.html: нет %q", want)
		}
	}
}

// Тест-контроль: отказ по сертификатам всё ещё превращается в понятную причину
// с шагами (а не в голую ошибку транспорта).
func TestV471CertFailureProducesRichCause(t *testing.T) {
	m := &mockKerio{user: "admin", password: "Secret123", isAdmin: true, role: "admin", certError: true}
	host, port := startMockKerio(t, m)

	res := CheckKerioAdminLogin(KerioLoginCheckRequest{
		Host: host, Port: port, User: "admin", Password: "Secret123", ProbeCerts: true,
	})
	if res.CertsChecked && res.CanManageCerts {
		t.Fatal("права на сертификаты не должны подтверждаться")
	}
	var got *KerioAuthCause
	for i := range res.Causes {
		if res.Causes[i].Code == "certs" {
			got = &res.Causes[i]
		}
	}
	if got == nil {
		t.Fatalf("нет причины certs: %v", authCauseCodes(res))
	}
	if len(got.Steps) < 5 {
		t.Errorf("шагов в причине certs: %d", len(got.Steps))
	}
	if got.Anchor != certsHelpAnchor {
		t.Errorf("anchor = %q", got.Anchor)
	}
	if res.CertsError == "" {
		t.Error("не сохранён ответ Kerio для показа в интерфейсе")
	}
}
