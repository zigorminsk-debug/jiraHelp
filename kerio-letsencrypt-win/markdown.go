package main

// markdown.go — встроенный рендерер Markdown → HTML для «Встроенной инструкции».
//
// Зачем свой, а не библиотека: программа принципиально собирается БЕЗ внешних
// зависимостей (один .exe, без DLL, без интернета при установке). Поэтому здесь
// компактный, но аккуратный парсер ровно того подмножества Markdown, которое
// используется в FAQ.md:
//
//	заголовки #…####, абзацы, жирный **текст**, `код`, ссылки [текст](адрес),
//	маркированные и нумерованные списки с вложенностью, таблицы с выравниванием,
//	блоки кода ```lang … ```, цитаты >, горизонтальные линии ---.
//
// Особенности, важные для инструкции:
//   - заголовкам присваивается «якорь» в стиле GitHub
//     (#3-вкладка-1--выпуск-сертификата), поэтому «Содержание» самого FAQ.md
//     работает ВНУТРИ программы — ссылки прокручивают документ, а не ведут
//     на github;
//   - весь текст экранируется: если в FAQ попадёт <script>, он будет показан
//     как текст, а не выполнен (инструкция — данные, а не код);
//   - документ режется на «разделы» по заголовкам 1–2 уровня: из них строится
//     боковое оглавление, поиск и быстрые переходы из вкладок программы.

import (
	"crypto/sha256"
	"encoding/hex"
	"html"
	"regexp"
	"strings"
	"unicode"
)

// MarkdownHeading — заголовок документа (для оглавления и ссылок-якорей).
type MarkdownHeading struct {
	Level  int    `json:"level"`
	Text   string `json:"text"`
	Anchor string `json:"anchor"`
}

// MarkdownSection — логический раздел документа (заголовок 1–2 уровня и всё,
// что до следующего такого заголовка). Именно по разделам работают оглавление
// и поиск в интерфейсе.
type MarkdownSection struct {
	Anchor string            `json:"anchor"`
	Title  string            `json:"title"`
	Level  int               `json:"level"`
	HTML   string            `json:"html"`
	Plain  string            `json:"plain"`
	Subs   []MarkdownHeading `json:"subs"`
}

// MarkdownDoc — готовый к отдаче в UI документ.
type MarkdownDoc struct {
	Title    string            `json:"title"`
	HTML     string            `json:"html"`
	Headings []MarkdownHeading `json:"headings"`
	Sections []MarkdownSection `json:"sections"`
	SHA256   string            `json:"sha256"`
	Bytes    int               `json:"bytes"`
}

var (
	mdHeadingRe  = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
	mdListRe     = regexp.MustCompile(`^(\s*)([-*+]|\d+[.)])\s+(.*)$`)
	mdTableDelim = regexp.MustCompile(`^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?$`)
	mdHTagRe     = regexp.MustCompile(`<[^>]*>`)
	mdCodeSpanRe = regexp.MustCompile("`([^`]+)`")
	mdBoldRe     = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdLinkRe     = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)
	mdMultiSpace = regexp.MustCompile(`[ \t]{2,}`)
	mdCodePlaceh = regexp.MustCompile("\x00(\\d+)\x00")
)

// escapeHTML экранирует всё, что браузер может принять за разметку.
func escapeHTML(s string) string {
	return html.EscapeString(s)
}

// stripInlineMarkup убирает markdown-разметку — нужно для якорей заголовков
// и для «плоского» текста, по которому ищет поиск.
func stripInlineMarkup(s string) string {
	s = mdLinkRe.ReplaceAllString(s, "$1")
	s = mdBoldRe.ReplaceAllString(s, "$1")
	s = mdCodeSpanRe.ReplaceAllString(s, "$1")
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "`", "")
	return strings.TrimSpace(s)
}

// slugifyHeading повторяет правила якорей GitHub: нижний регистр, пробелы → «-»,
// пунктуация выбрасывается, буквы (включая кириллицу) и цифры сохраняются.
// Благодаря этому ссылки из «Содержания» FAQ работают без правок документа.
func slugifyHeading(text string) string {
	t := strings.ToLower(stripInlineMarkup(text))
	var b strings.Builder
	for _, r := range t {
		switch {
		case r == ' ' || r == '\t':
			b.WriteRune('-')
		case r == '-' || r == '_':
			b.WriteRune(r)
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// renderInline превращает строчную разметку в HTML. Порядок важен:
// сначала «прячем» `код` в плейсхолдеры, затем экранируем ВСЁ остальное,
// и только потом разбираем жирный текст и ссылки — так невозможно «выполнить»
// случайный HTML из документа.
func renderInline(s string) string {
	var codes []string
	s = mdCodeSpanRe.ReplaceAllStringFunc(s, func(m string) string {
		codes = append(codes, m[1:len(m)-1])
		return "\x00" + itoa(len(codes)-1) + "\x00"
	})

	s = escapeHTML(s)
	s = mdBoldRe.ReplaceAllString(s, "<strong>$1</strong>")
	s = mdLinkRe.ReplaceAllStringFunc(s, func(m string) string {
		parts := mdLinkRe.FindStringSubmatch(m)
		if len(parts) != 3 {
			return m
		}
		text, target := parts[1], parts[2]
		if !safeLinkTarget(target) {
			return text
		}
		return `<a href="` + target + `">` + text + `</a>`
	})

	s = mdCodePlaceh.ReplaceAllStringFunc(s, func(m string) string {
		sub := mdCodePlaceh.FindStringSubmatch(m)
		n := atoi(sub[1])
		if n < 0 || n >= len(codes) {
			return ""
		}
		return "<code>" + escapeHTML(codes[n]) + "</code>"
	})
	return s
}

// safeLinkTarget пропускает только безопасные адреса: якоря внутри документа
// и http/https/mailto. Всё остальное (javascript:, data:, vbscript:) — не ссылка.
func safeLinkTarget(t string) bool {
	lt := strings.ToLower(strings.TrimSpace(t))
	if strings.HasPrefix(lt, "#") {
		return true
	}
	return strings.HasPrefix(lt, "http://") ||
		strings.HasPrefix(lt, "https://") ||
		strings.HasPrefix(lt, "mailto:")
}

func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func atoi(s string) int {
	if s == "" {
		return -1
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}

type renderCtx struct {
	headings  []MarkdownHeading
	sections  []MarkdownSection
	usedSlugs map[string]int
	cur       *MarkdownSection
	buf       *strings.Builder
	subs      []MarkdownHeading
}

func (c *renderCtx) flush() {
	if c.cur == nil {
		return
	}
	c.cur.HTML = c.buf.String()
	c.cur.Plain = plainTextFromHTML(c.cur.HTML)
	c.cur.Subs = c.subs
	c.sections = append(c.sections, *c.cur)
	c.cur = nil
	c.subs = nil
}

// RenderMarkdown — главная точка входа: Markdown → документ с разделами.
func RenderMarkdown(src string) MarkdownDoc {
	src = strings.ReplaceAll(strings.ReplaceAll(src, "\r\n", "\n"), "\r", "\n")
	src = strings.ReplaceAll(src, "\t", "    ")
	lines := strings.Split(src, "\n")

	ctx := &renderCtx{buf: &strings.Builder{}, usedSlugs: map[string]int{}}
	// Текст ДО первого заголовка 1–2 уровня — отдельный раздел «Начало»
	// (в FAQ так не бывает, но рендерер общий: кусок текста не должен теряться).
	if preface := strings.TrimSpace(renderBlocks(lines, ctx, true)); preface != "" {
		ctx.sections = append([]MarkdownSection{{
			Anchor: "preface",
			Title:  "Начало",
			Level:  1,
			HTML:   preface,
			Plain:  plainTextFromHTML(preface),
		}}, ctx.sections...)
	}
	ctx.flush()

	var html strings.Builder
	for _, s := range ctx.sections {
		html.WriteString(s.HTML)
	}

	doc := MarkdownDoc{
		HTML:     html.String(),
		Headings: ctx.headings,
		Sections: ctx.sections,
	}
	sum := sha256.Sum256([]byte(src))
	doc.SHA256 = hex.EncodeToString(sum[:])
	doc.Bytes = len(src)
	for _, h := range ctx.headings {
		if h.Level == 1 {
			doc.Title = h.Text
			break
		}
	}
	if doc.Title == "" && len(ctx.sections) > 0 {
		doc.Title = ctx.sections[0].Title
	}
	return doc
}

// renderBlocks разбирает поток строк на блоки. splitSections=true включает
// нарезку документа на разделы по заголовкам 1–2 уровня.
func renderBlocks(lines []string, ctx *renderCtx, splitSections bool) string {
	out := &strings.Builder{}

	// emit направляет готовый HTML либо в текущий раздел, либо в общий поток.
	emit := func(s string) {
		if splitSections && ctx.cur != nil {
			ctx.buf.WriteString(s)
			return
		}
		out.WriteString(s)
	}

	i := 0
	for i < len(lines) {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			i++
			continue
		}

		// Блок кода ```lang … ```
		if strings.HasPrefix(trimmed, "```") {
			lang := strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
			i++
			var code []string
			for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
				code = append(code, lines[i])
				i++
			}
			if i < len(lines) {
				i++ // закрывающий ```
			}
			var b strings.Builder
			b.WriteString(`<pre class="md-code"><code`)
			if cls := sanitizeClass(lang); cls != "" {
				b.WriteString(` class="lang-` + cls + `"`)
			}
			b.WriteString(`>`)
			b.WriteString(escapeHTML(strings.Join(code, "\n")))
			b.WriteString("</code></pre>\n")
			emit(b.String())
			continue
		}

		// Горизонтальная линия
		if trimmed == "---" || trimmed == "***" || trimmed == "___" {
			emit("<hr class=\"md-hr\">\n")
			i++
			continue
		}

		// Заголовок
		if m := mdHeadingRe.FindStringSubmatch(trimmed); m != nil {
			level := len(m[1])
			text := strings.TrimSpace(m[2])
			anchor := ctx.uniqueSlug(slugifyHeading(text))
			htmlLevel := level
			if htmlLevel > 4 {
				htmlLevel = 4
			}
			headingHTML := "<h" + itoa(htmlLevel) + ` id="` + anchor + `" class="md-h md-h` + itoa(level) + `">` +
				renderInline(text) + "</h" + itoa(htmlLevel) + ">\n"

			ctx.headings = append(ctx.headings, MarkdownHeading{
				Level: level, Text: stripInlineMarkup(text), Anchor: anchor,
			})

			if splitSections && level <= 2 {
				ctx.flush()
				ctx.cur = &MarkdownSection{Anchor: anchor, Title: stripInlineMarkup(text), Level: level}
				ctx.buf = &strings.Builder{}
				ctx.buf.WriteString(headingHTML)
			} else {
				emit(headingHTML)
				if splitSections && ctx.cur != nil && level >= 3 {
					ctx.subs = append(ctx.subs, MarkdownHeading{
						Level: level, Text: stripInlineMarkup(text), Anchor: anchor,
					})
				}
			}
			i++
			continue
		}

		// Таблица
		if strings.HasPrefix(trimmed, "|") && i+1 < len(lines) && mdTableDelim.MatchString(strings.TrimSpace(lines[i+1])) {
			rows := []string{trimmed}
			align := parseTableAlign(strings.TrimSpace(lines[i+1]))
			i += 2
			for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "|") {
				rows = append(rows, strings.TrimSpace(lines[i]))
				i++
			}
			emit(renderTable(rows, align))
			continue
		}

		// Цитата
		if strings.HasPrefix(trimmed, ">") {
			var inner []string
			for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), ">") {
				t := strings.TrimPrefix(strings.TrimSpace(lines[i]), ">")
				inner = append(inner, strings.TrimPrefix(t, " "))
				i++
			}
			sub := &renderCtx{buf: &strings.Builder{}, usedSlugs: ctx.usedSlugs}
			emit(`<blockquote class="md-quote">` + renderBlocks(inner, sub, false) + "</blockquote>\n")
			continue
		}

		// Список (маркированный или нумерованный, с вложенностью)
		if mdListRe.MatchString(line) {
			var block []string
			for i < len(lines) {
				l := lines[i]
				if strings.TrimSpace(l) == "" {
					// пустая строка внутри списка допустима, если дальше снова пункт
					if i+1 < len(lines) && (mdListRe.MatchString(lines[i+1]) || strings.HasPrefix(lines[i+1], "  ")) {
						i++
						continue
					}
					break
				}
				if mdListRe.MatchString(l) {
					block = append(block, l)
					i++
					continue
				}
				// продолжение пункта — строка с отступом
				if strings.HasPrefix(l, " ") && len(block) > 0 {
					block[len(block)-1] += " " + strings.TrimSpace(l)
					i++
					continue
				}
				break
			}
			emit(renderList(block))
			continue
		}

		// Абзац: склеиваем подряд идущие строки
		var para []string
		for i < len(lines) {
			l := lines[i]
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "```") ||
				strings.HasPrefix(t, ">") || mdListRe.MatchString(l) ||
				t == "---" || t == "***" || t == "___" ||
				(strings.HasPrefix(t, "|") && i+1 < len(lines) && mdTableDelim.MatchString(strings.TrimSpace(lines[i+1]))) {
				break
			}
			para = append(para, t)
			i++
		}
		if len(para) > 0 {
			emit("<p class=\"md-p\">" + renderInline(strings.Join(para, " ")) + "</p>\n")
		}
	}

	if splitSections {
		ctx.flush()
	}
	return out.String()
}

func (c *renderCtx) uniqueSlug(slug string) string {
	if slug == "" {
		slug = "section"
	}
	n, ok := c.usedSlugs[slug]
	if !ok {
		c.usedSlugs[slug] = 0
		return slug
	}
	n++
	c.usedSlugs[slug] = n
	return slug + "-" + itoa(n)
}

func sanitizeClass(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

type tableAlign int

const (
	alignLeft tableAlign = iota
	alignCenter
	alignRight
)

func parseTableAlign(delim string) []tableAlign {
	cells := splitTableRow(delim)
	aligns := make([]tableAlign, len(cells))
	for i, c := range cells {
		c = strings.TrimSpace(c)
		left := strings.HasPrefix(c, ":")
		right := strings.HasSuffix(c, ":")
		switch {
		case left && right:
			aligns[i] = alignCenter
		case right:
			aligns[i] = alignRight
		default:
			aligns[i] = alignLeft
		}
	}
	return aligns
}

func splitTableRow(row string) []string {
	row = strings.TrimSpace(row)
	row = strings.TrimPrefix(row, "|")
	row = strings.TrimSuffix(row, "|")
	raw := strings.Split(row, "|")
	for i := range raw {
		raw[i] = strings.TrimSpace(raw[i])
	}
	return raw
}

func renderTable(rows []string, aligns []tableAlign) string {
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="table-scroll"><table class="md-table"><thead><tr>`)
	header := splitTableRow(rows[0])
	for i, c := range header {
		b.WriteString("<th" + alignAttr(aligns, i) + ">" + renderInline(c) + "</th>")
	}
	b.WriteString("</tr></thead><tbody>")
	for _, r := range rows[1:] {
		cells := splitTableRow(r)
		b.WriteString("<tr>")
		for i := range header {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			b.WriteString("<td" + alignAttr(aligns, i) + ">" + renderInline(cell) + "</td>")
		}
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table></div>\n")
	return b.String()
}

func alignAttr(aligns []tableAlign, i int) string {
	if i >= len(aligns) || aligns[i] == alignLeft {
		return ""
	}
	if aligns[i] == alignCenter {
		return ` style="text-align:center"`
	}
	return ` style="text-align:right"`
}

// renderList собирает вложенный список из плоского набора строк.
// Смена типа списка на том же уровне (маркированный → нумерованный)
// закрывает предыдущий список и открывает новый — как в обычном Markdown.
func renderList(block []string) string {
	type item struct {
		level   int
		ordered bool
		text    string
	}
	// Уровень вложенности определяем по «ступеням» отступа: 0–1, 2–3, 4–5 пробелов…
	indentLevel := func(indent int) int {
		if indent < 2 {
			return 0
		}
		return 1 + (indent-2)/2
	}

	var items []item
	for _, line := range block {
		m := mdListRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ordered := m[2] != "-" && m[2] != "*" && m[2] != "+"
		items = append(items, item{
			level:   indentLevel(len(m[1])),
			ordered: ordered,
			text:    strings.TrimSpace(m[3]),
		})
	}
	if len(items) == 0 {
		return ""
	}

	var b strings.Builder
	openLevel := -1
	var openTags []string

	openList := func(tag string) {
		b.WriteString("<" + tag + ` class="md-list">`)
		openTags = append(openTags, tag)
	}
	writeItem := func(it item) {
		b.WriteString("<li>" + renderInline(it.text))
	}
	// switchList закрывает текущий список того же уровня и открывает другой тип.
	switchList := func(tag string) {
		last := openTags[len(openTags)-1]
		b.WriteString("</li></" + last + ">")
		openTags[len(openTags)-1] = tag
		b.WriteString("<" + tag + ` class="md-list">`)
	}
	sameType := func(tag string) bool {
		return openTags[len(openTags)-1] == tag
	}

	for _, it := range items {
		tag := "ul"
		if it.ordered {
			tag = "ol"
		}
		switch {
		case openLevel < 0, it.level > openLevel:
			openList(tag)
			openLevel = it.level
			writeItem(it)
		case it.level < openLevel:
			for openLevel > it.level && len(openTags) > 1 {
				b.WriteString("</li></" + openTags[len(openTags)-1] + ">")
				openTags = openTags[:len(openTags)-1]
				openLevel--
			}
			if !sameType(tag) {
				switchList(tag)
			}
			b.WriteString("</li>")
			writeItem(it)
		default: // тот же уровень
			if !sameType(tag) {
				switchList(tag)
			} else {
				b.WriteString("</li>")
			}
			writeItem(it)
		}
	}
	for len(openTags) > 0 {
		b.WriteString("</li></" + openTags[len(openTags)-1] + ">")
		openTags = openTags[:len(openTags)-1]
	}
	return b.String() + "\n"
}

// plainTextFromHTML — «плоский» текст раздела (для поиска в инструкции).
func plainTextFromHTML(s string) string {
	s = mdHTagRe.ReplaceAllString(s, " ")
	s = strings.NewReplacer(
		"&nbsp;", " ", "&amp;", "&", "&lt;", "<", "&gt;", ">",
		"&quot;", `"`, "&#39;", "'", "&#x27;", "'",
	).Replace(s)
	s = mdMultiSpace.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}
