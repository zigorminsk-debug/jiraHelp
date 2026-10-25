package main

// v49_test.go — тесты релиза v4.9.0 «интерфейс на больших экранах».
//
// Предыстория: на вкладке «Выпуск сертификата» правая колонка была оформлена
// ДВУМЯ соседними <div>, то есть третьим элементом grid'а. На широком окне
// третий элемент уезжал во вторую строку — справа оставалась пустая половина
// экрана, а журнал и результаты оказывались под формой. Эти тесты не дают
// вернуть такую разметку и фиксируют «заполнение» больших экранов.

import (
	"regexp"
	"strings"
	"testing"
)

// issueGridBody вырезает HTML-фрагмент вкладки «Выпуск сертификата» от начала
// grid'а до конца секции — по нему считаем колонки, не разбирая весь документ.
func issueGridBody(t *testing.T, ui string) string {
	t.Helper()
	tab := strings.Index(ui, `id="tab-issue"`)
	if tab < 0 {
		t.Fatal("не найдена вкладка tab-issue")
	}
	grid := strings.Index(ui[tab:], `<div class="workspace-grid">`)
	if grid < 0 {
		t.Fatal("не найден workspace-grid на вкладке «Выпуск»")
	}
	start := tab + grid
	end := strings.Index(ui[start:], `id="tab-kerio"`)
	if end < 0 {
		t.Fatal("не найден конец вкладки «Выпуск»")
	}
	return ui[start : start+end]
}

// countTopLevelDivs считает открывающие <div …> первого уровня вложенности
// относительно переданного фрагмента (фрагмент начинается с открывающего тега
// самого grid'а). Строки внутри <script> игнорируются: в шаблонах там тоже
// встречаются <div>, и они не являются разметкой.
func countTopLevelDivs(t *testing.T, frag string) int {
	t.Helper()
	// отбрасываем скрипты — они идут после секции, но подстрахуемся
	if i := strings.Index(frag, "<script"); i >= 0 {
		frag = frag[:i]
	}
	// и комментарии: в них тоже встречается литерал <div> (например, в
	// пояснении, почему правая колонка должна быть одна).
	for {
		a := strings.Index(frag, "<!--")
		if a < 0 {
			break
		}
		b := strings.Index(frag[a:], "-->")
		if b < 0 {
			frag = frag[:a]
			break
		}
		frag = frag[:a] + frag[a+b+3:]
	}
	re := regexp.MustCompile(`<div\b[^>]*>|</div>`)
	depth := 0
	top := 0
	started := false
	for _, m := range re.FindAllString(frag, -1) {
		if m == "</div>" {
			depth--
			if depth <= 0 {
				break
			}
			continue
		}
		if !started {
			// первый <div …> — сам grid
			started = true
			depth = 1
			continue
		}
		if depth == 1 {
			top++
		}
		depth++
	}
	return top
}

func TestV49IssueTabHasExactlyTwoColumns(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	if n := countTopLevelDivs(t, issueGridBody(t, ui)); n != 2 {
		t.Fatalf("на вкладке «Выпуск» в grid %d колонок, ожидалось 2 — правая колонка снова "+
			"развалилась на несколько элементов и уедет на вторую строку", n)
	}

	// Правая колонка обязана быть одним контейнером с классом workspace-side,
	// внутри которого лежат все правые карточки.
	tab := ui[strings.Index(ui, `id="tab-issue"`):]
	if !strings.Contains(tab, `<div class="workspace-side">`) {
		t.Fatal("нет контейнера .workspace-side")
	}
	sideStart := strings.Index(tab, `<div class="workspace-side">`)
	side := tab[sideStart : sideStart+strings.Index(tab[sideStart:], `id="consoleLog"`)+200]
	for _, id := range []string{"issueQuickCard", "portInterceptCard", "dns01WizardCard", "preflightCard", "resultCard"} {
		if !strings.Contains(side, `id="`+id+`"`) {
			t.Errorf("карточка %q не в правой колонке", id)
		}
	}
	// И вкладка не должна содержать второй заголовок «RIGHT COLUMN» с новым <div>.
	if n := strings.Count(tab[:strings.Index(tab, `id="tab-kerio"`)], "<!-- RIGHT COLUMN"); n > 1 {
		t.Errorf("остались %d комментария RIGHT COLUMN — вероятно, снова два соседних <div>", n)
	}
}

func TestV49WideScreenCss(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	// Контейнер: растёт вместе с окном, но не бесконечно.
	if !regexp.MustCompile(`max-width:\s*min\(1880px,\s*96vw\)`).MatchString(ui) {
		t.Error("контейнер не расширяется на больших экранах (ожидалось min(1880px, 96vw))")
	}
	// Сетка: без жёстких минимумов 430/420 px и с minmax(0, …).
	grid := regexp.MustCompile(`\.workspace-grid \{[^}]*\}`).FindString(ui)
	if grid == "" {
		t.Fatal("не найдено правило .workspace-grid")
	}
	if strings.Contains(grid, "430px") || strings.Contains(grid, "420px") {
		t.Errorf(".workspace-grid всё ещё с жёсткими минимумами:\n%s", grid)
	}
	if !strings.Contains(grid, "minmax(0,") {
		t.Errorf(".workspace-grid не использует minmax(0, …):\n%s", grid)
	}
	for _, want := range []string{"min-width: 1600px", "min-width: 2000px"} {
		if !strings.Contains(ui, want) {
			t.Errorf("нет брейкпоинта @media (%s)", want)
		}
	}
}

func TestV49QuickStartCard(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	for _, want := range []string{
		`id="issueQuickCard"`,
		`id="qsReady"`,
		`id="qsDomain"`,
		`id="qsIp"`,
		`id="qsMode"`,
		`id="qsChallenge"`,
		`id="qsPreflightBtn"`,
		"🧭 Быстрый старт",
		"function initIssueQuickCard()",
		"initIssueQuickCard();",
		"qs-steps",
		"qs-grid",
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui/index.html: нет %q", want)
		}
	}

	// Кнопка «Проверить готовность» должна запускать настоящую проверку,
	// а не показывать заглушку.
	start := strings.Index(ui, "function initIssueQuickCard()")
	end := strings.Index(ui[start:], "initIssueQuickCard();")
	if start < 0 || end < 0 {
		t.Fatal("не найдена initIssueQuickCard")
	}
	body := ui[start : start+end]
	if !strings.Contains(body, "getElementById('preflightBtn')") {
		t.Error("кнопка быстрого старта не вызывает реальную предпроверку")
	}
	// Сводка обязана обновляться на ввод и на выбор режима.
	for _, ev := range []string{"'input'", "'change'", "modeCards"} {
		if !strings.Contains(body, ev) {
			t.Errorf("сводка не обновляется по событию %s", ev)
		}
	}
}

// После выпуска сертификата подсказка убирается, чтобы не отодвигать файлы.
func TestV49QuickStartHidesOnResult(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")
	start := strings.Index(ui, "function displayCertificateResult(cert)")
	if start < 0 {
		t.Fatal("нет displayCertificateResult")
	}
	body := ui[start : start+1200]
	if !strings.Contains(body, "issueQuickCard") {
		t.Error("после показа результата карточка «Быстрый старт» не скрывается")
	}
}

func TestV49FAQDescribesWideScreens(t *testing.T) {
	root := readRepoFile(t, "../FAQ.md")
	embedded := readRepoFile(t, "ui/FAQ.md")
	if root != embedded {
		t.Fatal("FAQ.md и ui/FAQ.md разошлись — запустите sync-faq.sh")
	}
	for _, want := range []string{
		"### 2.10 Большие экраны: 2K, 4K и ultrawide",
		"🧭 Быстрый старт",
		"1880 px",
	} {
		if !strings.Contains(root, want) {
			t.Errorf("FAQ.md: нет %q", want)
		}
	}
}

// Рядовой контроль версии (дубли id проверяет TestUIHasNoDuplicateIDs).
func TestV49VersionReleased(t *testing.T) {
	if cmp := compareVersions(appVersion, "4.9.0"); cmp < 0 {
		t.Errorf("appVersion = %q, ожидалось не ниже 4.9.0", appVersion)
	}
	if !strings.Contains(readRepoFile(t, "README.md"), "4.9.") {
		t.Error("README.md не упоминает релиз 4.9")
	}
}
