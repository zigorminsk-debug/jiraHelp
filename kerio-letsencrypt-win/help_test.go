package main

// help_test.go — «сторож» встроенной инструкции (вкладка «ФАК»).
//
// Что защищаем:
//  1. Встроенный текст (ui/FAQ.md) обязан быть ПОБАЙТОВО равен корневому FAQ.md.
//     Иначе программа показывала бы старую инструкцию, а в ZIP уезжала новая
//     (именно так и рождаются «в инструкции написано одно, а в программе другое»).
//  2. Все ссылки из «Содержания» FAQ должны находить свой заголовок — иначе
//     оглавление внутри программы «не работает» молча.
//  3. Разметка вкладки «ФАК» и её обработчики не должны исчезнуть при рефакторинге.
//  4. Рендерер Markdown должен быть безопасным: HTML из документа не исполняется.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestRenderMarkdownHeadingsAndAnchors(t *testing.T) {
	doc := RenderMarkdown("# Заголовок\n\n## 3. Вкладка 1 — Выпуск сертификата\n\n### 3.1 Что заполнять (сверху вниз)\n")

	if len(doc.Headings) != 3 {
		t.Fatalf("заголовков найдено %d, ожидалось 3", len(doc.Headings))
	}
	if doc.Headings[1].Anchor != "3-вкладка-1--выпуск-сертификата" {
		t.Errorf("якорь = %q, ожидался %q (правила GitHub)", doc.Headings[1].Anchor, "3-вкладка-1--выпуск-сертификата")
	}
	if doc.Headings[2].Anchor != "31-что-заполнять-сверху-вниз" {
		t.Errorf("якорь подраздела = %q", doc.Headings[2].Anchor)
	}
	if !strings.Contains(doc.HTML, `<h2 id="3-вкладка-1--выпуск-сертификата"`) {
		t.Errorf("в HTML нет h2 с якорем: %s", doc.HTML)
	}
	if doc.Title != "Заголовок" {
		t.Errorf("Title = %q", doc.Title)
	}
}

func TestRenderMarkdownTable(t *testing.T) {
	src := "| Знак | Значит |\n|---|---|\n| ✅ | так правильно |\n| ⚠️ | внимание |\n"
	doc := RenderMarkdown(src)

	for _, want := range []string{`<table class="md-table">`, "<th>Знак</th>", "<td>✅</td>", "<td>внимание</td>", `class="table-scroll"`} {
		if !strings.Contains(doc.HTML, want) {
			t.Errorf("в таблице нет %q\nHTML: %s", want, doc.HTML)
		}
	}
	if n := strings.Count(doc.HTML, "<tr>"); n != 3 {
		t.Errorf("строк в таблице %d, ожидалось 3 (1 заголовок + 2 данные)", n)
	}
}

func TestRenderMarkdownListsAndNesting(t *testing.T) {
	src := "- первый\n  - вложенный\n- второй\n\n1. раз\n2. два\n"
	doc := RenderMarkdown(src)

	if !strings.Contains(doc.HTML, "<ul class=\"md-list\"><li>первый<ul class=\"md-list\"><li>вложенный") {
		t.Errorf("вложенный список собран неверно: %s", doc.HTML)
	}
	if !strings.Contains(doc.HTML, "<ol class=\"md-list\"><li>раз</li><li>два</li></ol>") {
		t.Errorf("нумерованный список собран неверно: %s", doc.HTML)
	}
}

func TestRenderMarkdownInline(t *testing.T) {
	doc := RenderMarkdown("Это **жирный**, `код | с палкой` и [ссылка](#5-вкладка-3--проверка-почты-и-антиспам).\n")

	for _, want := range []string{
		"<strong>жирный</strong>",
		"<code>код | с палкой</code>",
		`<a href="#5-вкладка-3--проверка-почты-и-антиспам">ссылка</a>`,
	} {
		if !strings.Contains(doc.HTML, want) {
			t.Errorf("нет %q\nHTML: %s", want, doc.HTML)
		}
	}
}

func TestRenderMarkdownCodeFence(t *testing.T) {
	doc := RenderMarkdown("```bat\nschtasks /Create ^\n  /TR \"\\\"C:\\App.exe\\\" --renew\"\n```\n")

	if !strings.Contains(doc.HTML, `<pre class="md-code"><code class="lang-bat">`) {
		t.Errorf("нет блока кода: %s", doc.HTML)
	}
	if !strings.Contains(doc.HTML, "&lt;") && strings.Contains(doc.HTML, "<script") {
		t.Errorf("неожиданный HTML в блоке кода: %s", doc.HTML)
	}
	if !strings.Contains(doc.HTML, "/TR") {
		t.Errorf("текст команды потерян: %s", doc.HTML)
	}
}

// Самый важный тест безопасности: HTML из документа не должен исполняться.
func TestRenderMarkdownEscapesRawHTML(t *testing.T) {
	doc := RenderMarkdown("Обычный текст <script>alert('xss')</script> и <img src=x onerror=alert(1)>.\n\n[опасно](javascript:alert(1))\n")

	if strings.Contains(doc.HTML, "<script") || strings.Contains(doc.HTML, "<img") {
		t.Fatalf("HTML из документа попал в вывод без экранирования: %s", doc.HTML)
	}
	if strings.Contains(doc.HTML, "javascript:") {
		t.Fatalf("опасная ссылка javascript: не отфильтрована: %s", doc.HTML)
	}
	if !strings.Contains(doc.HTML, "&lt;script&gt;") {
		t.Errorf("текст <script> должен отображаться как текст: %s", doc.HTML)
	}
}

func TestRenderMarkdownBlockquote(t *testing.T) {
	doc := RenderMarkdown("> ⚠️ **Важно.** Не забудьте про PTR.\n")
	if !strings.Contains(doc.HTML, `<blockquote class="md-quote">`) ||
		!strings.Contains(doc.HTML, "<strong>Важно.</strong>") {
		t.Errorf("цитата собрана неверно: %s", doc.HTML)
	}
}

// TestEmbeddedFAQMatchesRoot — главный «замок»: встроенная инструкция обязана
// совпадать с FAQ.md в корне репозитория (её же кладут в ZIP к .exe).
func TestEmbeddedFAQMatchesRoot(t *testing.T) {
	root, err := os.ReadFile("../FAQ.md")
	if err != nil {
		t.Fatalf("не удалось прочитать ../FAQ.md: %v", err)
	}
	embedded, err := os.ReadFile("ui/FAQ.md")
	if err != nil {
		t.Fatalf("не удалось прочитать ui/FAQ.md: %v", err)
	}
	if !bytes.Equal(root, embedded) {
		t.Fatalf("ui/FAQ.md разошёлся с корневым FAQ.md (корень %d Б, встроенная %d Б).\n"+
			"Выполните:  bash kerio-letsencrypt-win/sync-faq.sh", len(root), len(embedded))
	}
	if !bytes.Equal(root, embeddedFAQMD) {
		t.Fatalf("вкомпилированная инструкция (%d Б) не совпадает с FAQ.md (%d Б)", len(embeddedFAQMD), len(root))
	}
}

// TestFAQAnchorsResolve — все внутренние ссылки «Содержания» находят заголовок.
func TestFAQAnchorsResolve(t *testing.T) {
	doc := HelpDocument()

	anchors := map[string]bool{}
	for _, h := range doc.Headings {
		anchors[h.Anchor] = true
	}

	linkRe := regexp.MustCompile(`\]\(#([^)\s]+)\)`)
	matches := linkRe.FindAllStringSubmatch(string(embeddedFAQMD), -1)
	if len(matches) < 15 {
		t.Fatalf("в FAQ.md найдено всего %d внутренних ссылок — похоже, оглавление сломано", len(matches))
	}
	for _, m := range matches {
		if !anchors[m[1]] {
			t.Errorf("ссылка #%s не находит заголовок (якоря нет среди %d заголовков)", m[1], len(anchors))
		}
	}
}

func TestFAQDocumentSanity(t *testing.T) {
	doc := HelpDocument()

	if len(doc.Sections) < 18 {
		t.Errorf("разделов в инструкции %d, ожидалось не меньше 18", len(doc.Sections))
	}
	if doc.Bytes < 40000 {
		t.Errorf("инструкция подозрительно короткая: %d Б", doc.Bytes)
	}
	if doc.SHA256 == "" || len(doc.SHA256) != 64 {
		t.Errorf("SHA-256 документа неверный: %q", doc.SHA256)
	}
	for _, s := range doc.Sections {
		if strings.TrimSpace(s.Title) == "" {
			t.Errorf("раздел без заголовка (anchor=%q)", s.Anchor)
		}
		if strings.TrimSpace(s.HTML) == "" {
			t.Errorf("раздел «%s» без текста", s.Title)
		}
		if strings.Contains(s.HTML, "<script") {
			t.Errorf("раздел «%s» содержит неэкранированный <script>", s.Title)
		}
	}

	// Ключевые разделы должны быть на месте — по ним переходят вкладки программы.
	for _, anchor := range []string{
		"3-вкладка-1--выпуск-сертификата",
		"4-вкладка-2--установка-в-kerio-connect",
		"9-вкладка-7--антиспам-база-kcm",
		"14-частые-проблемы-и-решения",
		"19-встроенная-инструкция-эта-вкладка",
	} {
		found := false
		for _, h := range doc.Headings {
			if h.Anchor == anchor {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("в инструкции нет раздела #%s", anchor)
		}
	}
}

// TestHelpRoutesServeFAQ — эндпоинты вкладки «ФАК» отдают документ и файл.
func TestHelpRoutesServeFAQ(t *testing.T) {
	mux := http.NewServeMux()
	registerHelpRoutes(mux)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/help/doc")
	if err != nil {
		t.Fatalf("GET /api/help/doc: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/api/help/doc вернул %d", resp.StatusCode)
	}
	var payload struct {
		OK       bool              `json:"ok"`
		Version  string            `json:"version"`
		Sections []MarkdownSection `json:"sections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("ответ /api/help/doc не JSON: %v", err)
	}
	if !payload.OK || payload.Version != appVersion || len(payload.Sections) < 18 {
		t.Fatalf("неожиданный ответ /api/help/doc: ok=%v version=%q разделов=%d",
			payload.OK, payload.Version, len(payload.Sections))
	}

	resp2, err := http.Get(srv.URL + "/api/help/download")
	if err != nil {
		t.Fatalf("GET /api/help/download: %v", err)
	}
	defer resp2.Body.Close()
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp2.Body)
	if !bytes.Equal(body.Bytes(), embeddedFAQMD) {
		t.Errorf("скачанный .md (%d Б) не совпадает с встроенным (%d Б)", body.Len(), len(embeddedFAQMD))
	}
	if cd := resp2.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, "FAQ") {
		t.Errorf("Content-Disposition = %q, ожидалось вложение с именем FAQ…", cd)
	}

	resp3, err := http.Get(srv.URL + "/api/help/print")
	if err != nil {
		t.Fatalf("GET /api/help/print: %v", err)
	}
	defer resp3.Body.Close()
	printed := new(bytes.Buffer)
	_, _ = printed.ReadFrom(resp3.Body)
	if !strings.Contains(printed.String(), "<!DOCTYPE html>") || !strings.Contains(printed.String(), appVersion) {
		t.Errorf("печатная версия собрана неверно (%d Б)", printed.Len())
	}
}

// TestUIHelpTabWiring — вкладка «ФАК» есть в разметке, связана с обработчиками,
// а все «перейти в инструкцию» из вкладок ведут на существующие разделы.
func TestUIHelpTabWiring(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	for _, want := range []string{
		`data-tab="help"`,
		`id="tab-help"`,
		`/api/help/doc`,
		`function openHelpSection(`,
		`function loadHelpDoc(`,
		`id="faqToc"`,
		`id="faqDoc"`,
		`id="faqSearchInput"`,
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui/index.html: нет %q — вкладка «ФАК» развалилась", want)
		}
	}

	anchors := map[string]bool{}
	for _, h := range HelpDocument().Headings {
		anchors[h.Anchor] = true
	}
	callRe := regexp.MustCompile(`openHelpSection\('([^']+)'`)
	calls := callRe.FindAllStringSubmatch(ui, -1)
	if len(calls) < 8 {
		t.Fatalf("в UI найдено %d кнопок «подробнее в инструкции», ожидалось не меньше 8", len(calls))
	}
	for _, c := range calls {
		if !anchors[c[1]] {
			t.Errorf("кнопка ведёт на #%s, но такого раздела в инструкции нет", c[1])
		}
	}
}
