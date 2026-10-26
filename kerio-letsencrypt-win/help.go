package main

// help.go — «Встроенная инструкция»: тот же самый FAQ.md, что лежит рядом
// с программой и в ZIP-архиве, но открытый прямо в окне программы на вкладке
// «ФАК». Ничего не скачивается из интернета: текст вкомпилирован в .exe
// (go:embed ui/FAQ.md) и всегда соответствует версии сборки — это проверяют
// тесты (help_test.go):
//
//	TestEmbeddedFAQMatchesRoot — ui/FAQ.md побайтово равен FAQ.md в корне репозитория;
//	TestFAQAnchorsResolve      — все ссылки «Содержания» находят свой заголовок;
//	TestFAQVisibleInUI         — у вкладки «ФАК» есть разметка и обработчики.
//
// Зачем это нужно: администратор Kerio на сервере часто не имеет ни браузера
// с интернетом, ни распакованного архива — а инструкция должна быть под рукой.
// Поэтому документ доступен тремя способами: вкладка «ФАК» в окне программы,
// скачивание .md из этой же вкладки и печать/сохранение в PDF.

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

var (
	helpOnce  sync.Once
	helpCache MarkdownDoc
)

// HelpDocument возвращает разобранный (один раз) документ инструкции.
func HelpDocument() MarkdownDoc {
	helpOnce.Do(func() {
		helpCache = RenderMarkdown(string(embeddedFAQMD))
	})
	return helpCache
}

func registerHelpRoutes(mux *http.ServeMux) {
	// JSON с разделами документа — из него UI строит оглавление, поиск и текст.
	mux.HandleFunc("/api/help/doc", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		doc := HelpDocument()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"version":  appVersion,
			"title":    doc.Title,
			"sha256":   doc.SHA256,
			"bytes":    doc.Bytes,
			"headings": doc.Headings,
			"sections": doc.Sections,
		})
	})

	// Скачивание исходного .md — ровно те же байты, что и в ZIP-архиве.
	mux.HandleFunc("/api/help/download", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition",
			`attachment; filename="FAQ-`+appVersion+`.md"; filename*=UTF-8''`+urlEscape(`FAQ-Полная-инструкция.md`))
		_, _ = w.Write(embeddedFAQMD)
	})

	// Автономная HTML-версия (для печати, PDF и отправки коллеге по почте).
	mux.HandleFunc("/api/help/print", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition",
				`attachment; filename="FAQ-`+appVersion+`.html"; filename*=UTF-8''`+urlEscape(`FAQ-Полная-инструкция.html`))
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		_, _ = w.Write(helpStandaloneHTML(HelpDocument()))
	})
}

// urlEscape кодирует имя файла для заголовка Content-Disposition (RFC 5987).
func urlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// helpStandaloneHTML собирает печатную версию инструкции: один файл, без
// внешних ресурсов, светлая тема (так экономнее для принтера и понятнее в PDF).
func helpStandaloneHTML(doc MarkdownDoc) []byte {
	const style = `
  :root{color-scheme:light}
  body{font-family:"Segoe UI",Arial,sans-serif;max-width:960px;margin:0 auto;padding:28px 20px 60px;
       color:#0f172a;background:#fff;line-height:1.62;font-size:14px}
  h1{font-size:24px;margin:0 0 6px}
  h2{font-size:18px;margin:30px 0 10px;padding-bottom:6px;border-bottom:1px solid #d7dee8}
  h3{font-size:15px;margin:20px 0 8px}
  h4{font-size:14px;margin:16px 0 6px}
  p{margin:0 0 10px}
  ul,ol{margin:0 0 12px;padding-left:22px}
  li{margin:4px 0}
  code{background:#f1f5f9;padding:1px 5px;border-radius:5px;font-family:Consolas,monospace;font-size:12.5px;word-break:break-word}
  pre{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px;overflow:auto;font-size:12.6px;line-height:1.5}
  pre code{background:none;padding:0}
  table{width:100%;border-collapse:collapse;font-size:12.6px;margin:0 0 14px}
  th,td{border:1px solid #d7dee8;padding:7px 9px;text-align:left;vertical-align:top}
  th{background:#f1f5f9;font-weight:700}
  blockquote{margin:0 0 14px;padding:10px 14px;border-left:3px solid #2563eb;background:#f8fafc;color:#334155}
  hr{border:none;border-top:1px solid #d7dee8;margin:22px 0}
  a{color:#1d4ed8}
  .meta{color:#64748b;font-size:12.5px;margin-bottom:22px}
  .table-scroll{overflow-x:auto}
  @media print{body{padding:0;max-width:none;font-size:12.5px}
    h2{page-break-after:avoid} table{page-break-inside:auto} tr{page-break-inside:avoid}
    a{color:#0f172a;text-decoration:none}}
`
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString(`<title>` + escapeHTML(stripInlineMarkup(doc.Title)) + `</title><style>` + style + `</style></head><body>`)
	b.WriteString(`<div class="meta">KerioCertManager v` + appVersion + ` · встроенная инструкция (разделов: ` +
		itoa(len(doc.Sections)) + `) · разработчик Zakharevich Igor · ziv@csl.by · +375293371412</div>`)
	b.WriteString(doc.HTML)
	b.WriteString(`</body></html>`)
	return []byte(b.String())
}
