package main

// v48_test.go — тесты релиза v4.8.0:
//   1. кнопка «🔄 Проверить обновления» в шапке (видна с любой вкладки);
//   2. закреплённые шапка и полоса вкладок при прокрутке.
//
// Проверяем не «есть ли строка», а связность: кнопка привязана к обработчику,
// обработчик реально дергает форс-проверку обновлений, состояние кнопки
// синхронизировано с результатом, а «липкость» не сломается при переносе
// шапки на вторую строку (высота измеряется, а не задана числом).

import (
	"strings"
	"testing"
)

func TestV48HeaderUpdateButtonExists(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	// Кнопка должна быть в шапке (до панели вкладок), а не в теле страницы.
	topbar := strings.Index(ui, `<header class="topbar">`)
	navTabs := strings.Index(ui, `<nav class="nav-tabs">`)
	btn := strings.Index(ui, `id="topCheckUpdateBtn"`)
	if topbar < 0 || navTabs < 0 {
		t.Fatal("не найдены шапка или панель вкладок")
	}
	if btn < 0 {
		t.Fatal("нет кнопки #topCheckUpdateBtn")
	}
	if !(topbar < btn && btn < navTabs) {
		t.Errorf("кнопка обновлений не в шапке: topbar=%d btn=%d nav=%d", topbar, btn, navTabs)
	}

	for _, want := range []string{
		`Проверить обновления`,
		`id="topUpdateDot"`,
		`kcm-update-dot`,
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui/index.html: нет %q", want)
		}
	}

	// Подпись должна скрываться на узких экранах (остаётся иконка + точка).
	if !strings.Contains(ui, ".topbar .btn-lbl { display: none; }") {
		t.Error("нет правила, скрывающего подписи кнопок шапки на узких экранах")
	}
}

func TestV48HeaderUpdateButtonWired(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	if !strings.Contains(ui, "async function checkUpdatesFromHeader()") {
		t.Fatal("нет обработчика checkUpdatesFromHeader")
	}
	if !strings.Contains(ui, "on('topCheckUpdateBtn', 'click', checkUpdatesFromHeader)") {
		t.Error("кнопка не привязана к обработчику")
	}
	// Обработчик обязан делать именно проверку (force), а не открывать вкладку.
	start := strings.Index(ui, "async function checkUpdatesFromHeader()")
	end := strings.Index(ui[start:], "\n  function pulseUpdateBanner")
	if end < 0 {
		t.Fatal("не найден конец обработчика")
	}
	body := ui[start : start+end]
	if !strings.Contains(body, "runUpdateCheck(true)") {
		t.Error("обработчик не запускает проверку с force=1")
	}
	for _, want := range []string{
		"Обновлений нет: у вас последняя версия",
		"Доступна версия ",
		"window.scrollTo(",
		"pulseUpdateBanner()",
		"btn.disabled = false",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("обработчик не содержит %q", want)
		}
	}
}

func TestV48UpdateButtonStateSync(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	if !strings.Contains(ui, "function updateHeaderUpdateButton(info)") {
		t.Fatal("нет updateHeaderUpdateButton")
	}
	// Состояние должно обновляться при каждом ответе баннера — в том числе
	// когда баннер скрывается (нет обновления / версия пропущена).
	start := strings.Index(ui, "function renderUpdateBanner(payload)")
	end := strings.Index(ui[start:], "\n  function updateStatusLine")
	if start < 0 || end < 0 {
		t.Fatal("не найден renderUpdateBanner")
	}
	body := ui[start : start+end]
	call := strings.Index(body, "updateHeaderUpdateButton(info)")
	hide := strings.Index(body, "banner.style.display = 'none'")
	if call < 0 {
		t.Fatal("renderUpdateBanner не обновляет кнопку в шапке")
	}
	if hide >= 0 && call > hide {
		t.Error("кнопка обновляется только когда баннер виден — точка останется гореть после пропуска версии")
	}
}

func TestV48StickyHeaderCss(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	// Шапка.
	topbarStart := strings.Index(ui, ".topbar {")
	if topbarStart < 0 {
		t.Fatal("нет .topbar")
	}
	topbarBlock := ui[topbarStart : topbarStart+700]
	if !strings.Contains(topbarBlock, "position: sticky") || !strings.Contains(topbarBlock, "top: 0") {
		t.Error(".topbar не закреплена сверху")
	}

	// Полоса вкладок — главное требование пользователя.
	navStart := strings.Index(ui, ".nav-tabs {")
	if navStart < 0 {
		t.Fatal("нет .nav-tabs")
	}
	navBlock := ui[navStart : navStart+700]
	if !strings.Contains(navBlock, "position: sticky") {
		t.Error(".nav-tabs не закреплена — меню будет уезжать при прокрутке")
	}
	if !strings.Contains(navBlock, "top: var(--kcm-topbar-h") {
		t.Error(".nav-tabs не учитывает высоту шапки — на узком окне меню наедет на шапку")
	}
	if !strings.Contains(navBlock, "z-index: 45") {
		t.Error("у полосы вкладок нет z-index ниже шапки, но выше контента")
	}

	// Высота измеряется, а не задана константой.
	if !strings.Contains(ui, "function initStickyHeader()") {
		t.Fatal("нет initStickyHeader")
	}
	if !strings.Contains(ui, "setProperty('--kcm-topbar-h'") || !strings.Contains(ui, "setProperty('--kcm-sticky-h'") {
		t.Error("высота шапки не измеряется в CSS-переменные")
	}
	if !strings.Contains(ui, "ResizeObserver") {
		t.Error("нет ResizeObserver — высота не обновится при переносе шапки на две строки")
	}
	if !strings.Contains(ui, "initStickyHeader();") {
		t.Error("initStickyHeader не вызывается при загрузке")
	}
}

func TestV48StickyDoesNotBreakAnchors(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")
	// Переходы по оглавлению не должны прятать заголовки под шапкой.
	if !strings.Contains(ui, "scroll-padding-top: calc(var(--kcm-sticky-h") {
		t.Error("нет scroll-padding-top — заголовок уедет под закреплённое меню")
	}
	if !strings.Contains(ui, ".faq-doc .md-h { scroll-margin-top: calc(var(--kcm-sticky-h") {
		t.Error("scroll-margin-top заголовков инструкции не учитывает высоту шапки")
	}
	// Оглавление ФАК тоже должно начинаться ниже закреплённой области.
	tocStart := strings.Index(ui, ".faq-toc {")
	if tocStart < 0 {
		t.Fatal("нет .faq-toc")
	}
	tocBlock := ui[tocStart : tocStart+400]
	if !strings.Contains(tocBlock, "top: calc(var(--kcm-sticky-h") {
		t.Error("оглавление ФАК перекрывается закреплённой шапкой")
	}
}

func TestV48FAQDocumentsNewButton(t *testing.T) {
	root := readRepoFile(t, "../FAQ.md")
	embedded := readRepoFile(t, "ui/FAQ.md")
	if root != embedded {
		t.Fatal("FAQ.md и ui/FAQ.md разошлись — запустите sync-faq.sh")
	}
	for _, want := range []string{
		"🔄 Проверить обновления",
		"### 2.8 Шапка и меню всегда сверху",
		"остаются на месте",
	} {
		if !strings.Contains(root, want) {
			t.Errorf("FAQ.md: нет %q", want)
		}
	}
	// Раздел про обновления обязан ссылаться на кнопку в шапке.
	if !strings.Contains(root, "кнопка **🔄 Проверить обновления** в правом верхнем углу") {
		t.Error("FAQ §21.3 не описывает кнопку в шапке")
	}
}

// Кнопка не должна дублировать уже существующую проверку в «Инструментах»:
// обе живут в одном окне, но с разными id (иначе getElementById вернёт не ту).
func TestV48NoDuplicateUpdateControls(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")
	for _, id := range []string{"topCheckUpdateBtn", "checkUpdateNowBtn", "topUpdateDot"} {
		if n := strings.Count(ui, `id="`+id+`"`); n != 1 {
			t.Errorf("id=%q встречается %d раз, ожидался 1", id, n)
		}
	}
}
