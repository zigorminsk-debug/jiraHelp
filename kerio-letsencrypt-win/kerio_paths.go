package main

// kerio_paths.go — поиск каталога правил SpamAssassin в Kerio Connect.
//
// Почему это отдельный модуль: раскладка каталогов у Kerio менялась от версии
// к версии и зависит от разрядности установки. На реальных серверах
// встречаются как минимум такие варианты:
//
//	C:\Program Files\Kerio\MailServer\plugins\spamassassin\rules
//	C:\Program Files (x86)\Kerio\MailServer\plugins\spamassassin\rules
//	C:\Program Files (x86)\Kerio\MailServer\plugins\spamserver\spamassassin\rules
//	D:\Kerio\MailServer\plugins\spamassassin\rules            (нестандартный диск)
//	\\server\c$\Program Files\Kerio\MailServer\plugins\...    (Kerio на другом ПК)
//	/opt/kerio/mailserver/plugins/spamassassin/rules          (Linux-сервер)
//
// Старая версия искала ровно три пути и, если сервер стоял в «нетипичном»
// месте (или Kerio вообще был на другой машине), показывала бесполезное
// «не найден каталог SpamAssassin». Теперь поиск идёт по цепочке:
//
//	1) путь, который ввёл пользователь (в т.ч. сразу папка rules и UNC-путь);
//	2) команда запуска службы KerioMailServer (sc qc / реестр) — точный путь;
//	3) значения реестра Kerio (InstallPath / Path / InstallLocation / -dir);
//	4) стандартные каталоги на всех дисках;
//	5) обход дерева Kerio в глубину: ищем папку spamassassin, а если её нет —
//	   любую папку с настоящими .cf-правилами SpamAssassin.
//
// Всё, что было проверено, попадает в отчёт (KerioPathReport): его показывает
// кнопка «Что проверено» и он же вставляется в текст ошибки, чтобы админ
// видел конкретику, а не общую фразу.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// maxScanEntries ограничивает обход дерева: даже огромный каталог Kerio
// (с письмами и бэкапами) просматривается за доли секунды.
const maxScanEntries = 6000

// skipScanDirs — папки, в которые обход не заходит никогда: там нет правил,
// зато могут быть гигабайты писем и резервных копий.
var skipScanDirs = map[string]bool{
	"store": true, "logs": true, "log": true, "backup": true, "backups": true,
	"archive": true, "archives": true, "queue": true, "spool": true, "mail": true,
	"tmp": true, "temp": true, "cache": true, "node_modules": true, ".git": true,
	"system volume information": true, "$recycle.bin": true, "windows": true,
	"winsxs": true, "driverstore": true, "assembly": true, "installer": true,
}

// KerioProbe — одна проверенная гипотеза о каталоге (для отчёта в UI).
type KerioProbe struct {
	Path       string `json:"path"`
	Source     string `json:"source"`
	Exists     bool   `json:"exists"`
	Kind       string `json:"kind"` // "rules" | "kerio" | "plugins" | "unknown"
	HasExe     bool   `json:"hasMailserverExe"`
	HasCfg     bool   `json:"hasMailserverCfg"`
	HasPlugins bool   `json:"hasPlugins"`
	RulesDir   string `json:"rulesDir"`
	Note       string `json:"note"`
}

// KerioPathReport — полный отчёт «что и где искали».
type KerioPathReport struct {
	OK             bool         `json:"ok"`
	OS             string       `json:"os"`
	IsWindows      bool         `json:"isWindows"`
	Admin          bool         `json:"admin"`
	ServiceName    string       `json:"serviceName"`
	ServiceStatus  string       `json:"serviceStatus"`
	ServiceCommand string       `json:"serviceCommand"`
	Probes         []KerioProbe `json:"probes"`
	KerioDir       string       `json:"kerioDir"`
	KerioDirSource string       `json:"kerioDirSource"`
	RulesDir       string       `json:"rulesDir"`
	RulesDirSource string       `json:"rulesDirSource"`
	RulesDirExists bool         `json:"rulesDirExists"`
	ManualChecked  bool         `json:"manualChecked"`
	SearchedDirs   int          `json:"searchedDirs"`
	ElapsedMs      int64        `json:"elapsedMs"`
	Advice         []string     `json:"advice"`
	Summary        string       `json:"summary"`
}

// ---------------------------------------------------------------------------
// Нормализация путей
// ---------------------------------------------------------------------------

// expandPercentEnv раскрывает %ProgramFiles%-подобные переменные (os.ExpandEnv
// понимает только $VAR, а в проводнике Windows копируется именно %VAR%).
func expandPercentEnv(p string) string {
	if !strings.Contains(p, "%") {
		return p
	}
	var b strings.Builder
	for i := 0; i < len(p); {
		if p[i] == '%' {
			if j := strings.IndexByte(p[i+1:], '%'); j > 0 {
				name := p[i+1 : i+1+j]
				if val := os.Getenv(name); val != "" {
					b.WriteString(val)
					i += j + 2
					continue
				}
			}
		}
		b.WriteByte(p[i])
		i++
	}
	return b.String()
}

// normalizeKerioPath приводит путь из поля ввода к виду, понятному os.Stat:
// убирает кавычки и пробелы, раскрывает %VAR%, чистит «\\?\» и хвостовые «\».
func normalizeKerioPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"'`)
	p = expandPercentEnv(p)
	p = strings.TrimPrefix(p, `\\?\`)
	if p == "" {
		return ""
	}
	p = filepath.Clean(p)
	if p == "." {
		return ""
	}
	return trimTrailingSep(p)
}

// dirOfPathAnySep — каталог пути, в котором разделителем может быть и «\\», и
// «/»: так пути из вывода sc.exe/reg.exe разбираются одинаково на любой ОС
// (в том числе когда Windows-путь обрабатывает Linux-сборка).
func dirOfPathAnySep(p string) string {
	p = strings.TrimRight(p, `\/`)
	idx := strings.LastIndexAny(p, `\/`)
	if idx < 0 {
		return p
	}
	if idx == 2 && p[1] == ':' { // корень диска «C:\\»
		return p[:3]
	}
	if idx == 0 { // корень «/»
		return p[:1]
	}
	return p[:idx]
}

// trimTrailingSep убирает хвостовой «\» или «/», но сохраняет корни вида
// «C:\» и «/»: такие пути лежат в основе всех кандидатов.
func trimTrailingSep(p string) string {
	if p == "" {
		return p
	}
	t := strings.TrimRight(p, `\/`)
	if t == "" || (len(t) == 2 && t[1] == ':') {
		return p
	}
	return t
}

// looksLikeRulesDir — путь уже указывает на каталог правил (rules).
func looksLikeRulesDir(p string) bool {
	base := strings.ToLower(filepath.Base(p))
	if base == "rules" {
		return true
	}
	if base == "spamassassin" {
		return dirExists(filepath.Join(p, "rules"))
	}
	return false
}

// trimToKerioRoot поднимается вверх, если пользователь указал внутреннюю папку
// (plugins, spamserver, spamassassin, rules) вместо папки установки Kerio.
func trimToKerioRoot(p string) string {
	for i := 0; i < 6; i++ {
		base := strings.ToLower(filepath.Base(p))
		switch base {
		case "rules", "spamassassin", "spamserver", "plugins":
			parent := filepath.Dir(p)
			if parent == p || parent == "." || parent == string(filepath.Separator) {
				return p
			}
			p = parent
			continue
		}
		return p
	}
	return p
}

// normalizetoKerioDir превращает любой «внутренний» путь в папку установки.
func normalizeToKerioDir(p string) string {
	p = normalizeKerioPath(p)
	if p == "" {
		return ""
	}
	low := strings.ToLower(p)
	if idx := strings.Index(low, "spamassassin"); idx > 0 {
		cut := strings.TrimRight(p[:idx], `\/`)
		if cut != "" {
			return trimToKerioRoot(cut)
		}
	}
	return trimToKerioRoot(p)
}

// kerioInstallMarkers проверяет признаки настоящей папки установки Kerio.
func kerioInstallMarkers(dir string) (hasExe, hasCfg, hasPlugins bool) {
	hasExe = fileExists(filepath.Join(dir, "mailserver.exe")) ||
		fileExists(filepath.Join(dir, "mailserver"))
	hasCfg = fileExists(filepath.Join(dir, "mailserver.cfg"))
	hasPlugins = dirExists(filepath.Join(dir, "plugins"))
	return
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// ---------------------------------------------------------------------------
// Список вероятных каталогов правил
// ---------------------------------------------------------------------------

// spamAssassinRulesCandidates — «быстрые» адреса правил относительно папки
// Kerio. Порядок важен: первым идёт вариант, который встречается чаще всего.
func spamAssassinRulesCandidates(kerioDir string) []string {
	kerioDir = normalizeToKerioDir(kerioDir)
	if kerioDir == "" {
		return nil
	}
	return []string{
		// Классика Kerio MailServer / Connect 7–9 (Windows и Linux)
		filepath.Join(kerioDir, "plugins", "spamassassin", "rules"),
		// Kerio Connect 8+ с отдельным процессом spamserver (самый частый
		// вариант на Windows-серверах по отзывам администраторов)
		filepath.Join(kerioDir, "plugins", "spamserver", "spamassassin", "rules"),
		// Старые сборки, где была вложенная папка kerio
		filepath.Join(kerioDir, "kerio", "plugins", "spamassassin", "rules"),
		// Совсем старые/portable-сборки
		filepath.Join(kerioDir, "spamassassin", "rules"),
		filepath.Join(kerioDir, "plugins", "rules"),
	}
}

// spamAssassinDirsWithoutRules — каталоги spamassassin, в которых папку rules
// можно создать (Kerio сам её не всегда создаёт до первой настройки).
func spamAssassinDirsWithoutRules(kerioDir string) []string {
	kerioDir = normalizeToKerioDir(kerioDir)
	if kerioDir == "" {
		return nil
	}
	return []string{
		filepath.Join(kerioDir, "plugins", "spamassassin"),
		filepath.Join(kerioDir, "plugins", "spamserver", "spamassassin"),
		filepath.Join(kerioDir, "kerio", "plugins", "spamassassin"),
		filepath.Join(kerioDir, "spamassassin"),
	}
}

// ---------------------------------------------------------------------------
// Обход дерева
// ---------------------------------------------------------------------------

// scanDirsNamed ищет папки с именем want внутри root (в глубину, с лимитами).
func scanDirsNamed(root, want string, maxDepth, limit int) []string {
	root = normalizeKerioPath(root)
	if root == "" || !dirExists(root) {
		return nil
	}
	want = strings.ToLower(want)
	var found []string
	visited := 0

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth || visited > limit {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		visited += len(entries)
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := strings.ToLower(e.Name())
			if skipScanDirs[name] {
				continue
			}
			full := filepath.Join(dir, e.Name())
			if name == want {
				found = append(found, full)
				continue
			}
			walk(full, depth+1)
		}
	}
	walk(root, 0)
	sort.Strings(found)
	return found
}

// scanRuleDirsByContent ищет папки с настоящими правилами SpamAssassin
// (файлы .cf, содержащие директивы header/body/uri/score/describe).
// Нужен для нестандартных сборок, где папка называется иначе.
func scanRuleDirsByContent(root string, maxDepth, limit int) []string {
	root = normalizeKerioPath(root)
	if root == "" || !dirExists(root) {
		return nil
	}
	var found []string
	visited := 0

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth || visited > limit {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		visited += len(entries)
		cfCount := 0
		cfWithRules := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if strings.EqualFold(filepath.Ext(e.Name()), ".cf") {
				cfCount++
				if fileHasSpamAssassinDirectives(filepath.Join(dir, e.Name())) {
					cfWithRules++
				}
			}
		}
		if cfCount > 0 && cfWithRules > 0 {
			found = append(found, dir)
			return // глубже смысла нет: это уже каталог правил
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := strings.ToLower(e.Name())
			if skipScanDirs[name] {
				continue
			}
			walk(filepath.Join(dir, e.Name()), depth+1)
		}
	}
	walk(root, 0)
	sort.Strings(found)
	return found
}

// fileHasSpamAssassinDirectives читает первые 8 КБ файла: настоящий .cf
// начинается с комментариев и содержит директивы вида «score NAME 3.2».
func fileHasSpamAssassinDirectives(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	if n <= 0 {
		return false
	}
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, kw := range []string{"header ", "body ", "uri ", "score ", "describe ", "meta ", "rawbody "} {
			if strings.HasPrefix(line, kw) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Поиск каталога правил
// ---------------------------------------------------------------------------

// findExistingRulesDir ищет уже существующий каталог правил (без побочных
// эффектов: ничего не создаёт). Используется в диагностике и отчётах.
func findExistingRulesDir(kerioDir string) (string, string) {
	kerioDir = normalizeKerioPath(kerioDir)
	if kerioDir == "" {
		return "", ""
	}
	// Пользователь мог сразу указать папку правил.
	if looksLikeRulesDir(kerioDir) && dirExists(kerioDir) {
		if strings.EqualFold(filepath.Base(kerioDir), "spamassassin") {
			return filepath.Join(kerioDir, "rules"), "указан каталог spamassassin"
		}
		return kerioDir, "указан каталог правил"
	}

	root := normalizeToKerioDir(kerioDir)
	if root == "" {
		return "", ""
	}
	for _, cand := range spamAssassinRulesCandidates(root) {
		if dirExists(cand) {
			return cand, "найден по стандартному пути"
		}
	}
	for _, sa := range scanDirsNamed(root, "spamassassin", 5, maxScanEntries) {
		rules := filepath.Join(sa, "rules")
		if dirExists(rules) {
			return rules, "найден обходом дерева Kerio"
		}
		if dirExists(sa) {
			return rules, "найден обходом дерева Kerio (папка rules будет создана)"
		}
	}
	for _, d := range scanRuleDirsByContent(root, 4, maxScanEntries) {
		return d, "найден по файлам .cf внутри Kerio"
	}
	return "", ""
}

// detectSpamAssassinRulesDir возвращает каталог, в который нужно положить
// kerio-antispam.cf. Второй результат — существовал ли каталог раньше
// (false = программа создаст его сама).
func detectSpamAssassinRulesDir(kerioDir string) (string, bool) {
	if dir, _ := findExistingRulesDir(kerioDir); dir != "" {
		if dirExists(dir) {
			return dir, true
		}
		// Поиск нашёл папку spamassassin, но подпапки rules ещё нет — создаём
		// её именно там: Kerio читает правила только из своего дерева.
		if err := os.MkdirAll(dir, 0o755); err == nil {
			return dir, false
		}
	}

	root := normalizeToKerioDir(kerioDir)
	if root == "" {
		return "", false
	}
	// Папка spamassassin есть, а rules в ней нет — именно её читает Kerio
	// (так бывает на свежих установках, где правила ещё не настраивались).
	for _, sa := range spamAssassinDirsWithoutRules(root) {
		if !dirExists(sa) {
			continue
		}
		rules := filepath.Join(sa, "rules")
		if err := os.MkdirAll(rules, 0o755); err == nil {
			return rules, false
		}
	}
	for _, sa := range scanDirsNamed(root, "spamassassin", 5, maxScanEntries) {
		rules := filepath.Join(sa, "rules")
		if err := os.MkdirAll(rules, 0o755); err == nil {
			return rules, false
		}
	}

	// Самая последняя возможность: создаём plugins\spamassassin\rules, но
	// только внутри уже существующего plugins — чтобы не насоздавать пустышек
	// в случайном месте.
	plugins := filepath.Join(root, "plugins")
	if dirExists(plugins) {
		primary := filepath.Join(plugins, "spamassassin", "rules")
		if err := os.MkdirAll(primary, 0o755); err == nil {
			return primary, false
		}
	}
	// Старые сборки держали правила прямо в каталоге установки, но создавать
	// там папки можно только если это действительно установка Kerio —
	// иначе опечатка в пути плодит мусорные каталоги.
	if hasExe, hasCfg, _ := kerioInstallMarkers(root); hasExe || hasCfg {
		primary := filepath.Join(root, "spamassassin", "rules")
		if err := os.MkdirAll(primary, 0o755); err == nil {
			return primary, false
		}
	}
	return "", false
}

// findRulesDirInSearchRoots — последняя попытка, когда папка установки так и
// не определилась (нет службы, нестандартный путь, portable-сборка): смотрим
// «широкие» корни вроде C:\Program Files\Kerio и D:\Kerio целиком.
func findRulesDirInSearchRoots() (string, string) {
	return findRulesDirInRoots(PlatformKerioSearchRoots())
}

// findRulesDirInRoots — то же, но со списком корней (удобно тестировать).
func findRulesDirInRoots(roots []string) (string, string) {
	for _, root := range roots {
		root = normalizeKerioPath(root)
		if root == "" || !dirExists(root) {
			continue
		}
		if dir, src := findExistingRulesDir(root); dir != "" {
			return dir, src + " (поиск по " + root + ")"
		}
	}
	return "", ""
}

// ---------------------------------------------------------------------------
// Поиск самой папки установки Kerio
// ---------------------------------------------------------------------------

// kerioSystemDirs — каталоги, подсказанные системой (служба и реестр).
func kerioSystemDirs() []KerioProbe {
	var out []KerioProbe
	if name, cmd := PlatformKerioServiceImagePath(); cmd != "" {
		for _, d := range kerioDirsFromServiceCommand(cmd) {
			out = append(out, KerioProbe{Path: d, Source: "команда запуска службы " + name})
		}
	}
	for _, d := range PlatformKerioRegistryDirs() {
		out = append(out, KerioProbe{Path: d, Source: "реестр Windows"})
	}
	return out
}

// kerioDirsFromServiceCommand разбирает строку запуска службы:
//
//	"C:\Program Files\Kerio\MailServer\mailserver.exe" -dir "C:\Kerio\data"
//
// Возвращает и папку самого mailserver.exe, и каталог из параметра -dir.
func kerioDirsFromServiceCommand(cmd string) []string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil
	}
	var out []string

	// Путь к exe: в кавычках или до первого пробела.
	exe := ""
	rest := cmd
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			exe = cmd[1 : 1+end]
			rest = cmd[end+2:]
		}
	}
	if exe == "" {
		if idx := strings.IndexAny(cmd, " \t"); idx > 0 {
			exe = cmd[:idx]
			rest = cmd[idx+1:]
		} else {
			exe = cmd
			rest = ""
		}
	}
	exe = normalizeKerioPath(exe)
	add := func(p string) {
		p = normalizeKerioPath(p)
		if p == "" {
			return
		}
		for _, existing := range out {
			if strings.EqualFold(filepath.ToSlash(existing), filepath.ToSlash(p)) {
				return
			}
		}
		out = append(out, p)
	}
	if exe != "" && (strings.EqualFold(filepath.Base(exe), "mailserver.exe") || strings.EqualFold(filepath.Base(exe), "mailserver")) {
		add(dirOfPathAnySep(exe))
	} else if exe != "" && dirExists(exe) {
		add(exe)
	}

	// Параметры -dir / --dir: каталог данных Kerio.
	low := strings.ToLower(rest)
	for _, flag := range []string{"-dir", "--dir", "-d"} {
		idx := strings.Index(low, flag)
		if idx < 0 {
			continue
		}
		tail := strings.TrimSpace(rest[idx+len(flag):])
		if strings.HasPrefix(tail, `"`) {
			if end := strings.Index(tail[1:], `"`); end >= 0 {
				add(tail[1 : 1+end])
			}
		} else if f := strings.Fields(tail); len(f) > 0 {
			add(f[0])
		}
		break
	}
	return out
}

// resolveKerioInstallDir возвращает папку установки Kerio и источник, откуда
// она взялась. Порядок: ручной ввод → служба/реестр → стандартные пути.
func resolveKerioInstallDir(settings SavedUISettings) (string, string) {
	var manual []string
	if p := normalizeToKerioDir(settings.KerioInstallPath); p != "" && dirExists(p) {
		manual = append(manual, p)
	}
	for _, p := range manual {
		if hasAnyKerioMarker(p) || dirExists(filepath.Join(p, "plugins")) {
			return p, "из настроек программы"
		}
	}

	for _, probe := range kerioSystemDirs() {
		dir := normalizeToKerioDir(probe.Path)
		if dir == "" || !dirExists(dir) {
			continue
		}
		if hasAnyKerioMarker(dir) || dirExists(filepath.Join(dir, "plugins")) {
			return dir, "найден через " + probe.Source
		}
	}

	for _, cand := range PlatformCandidateKerioDirs() {
		dir := normalizeToKerioDir(cand)
		if dir == "" || !dirExists(dir) {
			continue
		}
		if hasAnyKerioMarker(dir) || dirExists(filepath.Join(dir, "plugins")) {
			return dir, "найден автоматически"
		}
	}
	// Мягкий вариант: каталог существует, но признаков Kerio внутри нет.
	for _, probe := range kerioSystemDirs() {
		if dir := normalizeToKerioDir(probe.Path); dir != "" && dirExists(dir) {
			return dir, "найден через " + probe.Source + " (без признаков Kerio)"
		}
	}
	for _, cand := range PlatformCandidateKerioDirs() {
		if dir := normalizeToKerioDir(cand); dir != "" && dirExists(dir) {
			return dir, "найден по стандартному пути"
		}
	}
	for _, p := range manual {
		return p, "из настроек программы"
	}
	return "", "не найден"
}

// hasAnyKerioMarker — есть ли в каталоге хоть один признак установки Kerio.
func hasAnyKerioMarker(dir string) bool {
	hasExe, hasCfg, hasPlugins := kerioInstallMarkers(dir)
	if hasExe || hasCfg || hasPlugins {
		return true
	}
	// Пользователь мог указать родительский каталог (например, C:\Program Files\Kerio).
	sub := filepath.Join(dir, "MailServer")
	if dirExists(sub) {
		return true
	}
	return dirExists(filepath.Join(dir, "ssl")) && dirExists(filepath.Join(dir, "store"))
}

// kerioDirCandidates — существующие каталоги Kerio (для справки в UI).
func kerioDirCandidates(settings SavedUISettings) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = normalizeToKerioDir(p)
		if p == "" || seen[strings.ToLower(p)] || !dirExists(p) {
			return
		}
		seen[strings.ToLower(p)] = true
		out = append(out, p)
	}
	add(settings.KerioInstallPath)
	for _, probe := range kerioSystemDirs() {
		add(probe.Path)
	}
	for _, c := range PlatformCandidateKerioDirs() {
		add(c)
	}
	return out
}

// ---------------------------------------------------------------------------
// Диагностика: полный отчёт «что проверено»
// ---------------------------------------------------------------------------

// DiagnoseKerioPaths собирает отчёт о поиске каталога правил: какие пути
// проверены, что в них найдено, что делать дальше.
func DiagnoseKerioPaths(settings SavedUISettings, extraKerioDir, extraRulesDir string) KerioPathReport {
	start := time.Now()
	serviceName, serviceCmd := PlatformKerioServiceImagePath()
	rep := KerioPathReport{
		OK:             true,
		OS:             runtime.GOOS,
		IsWindows:      runtime.GOOS == "windows",
		Admin:          IsRunningAsAdmin(),
		ServiceName:    serviceName,
		ServiceStatus:  PlatformKerioServiceStatus(),
		ServiceCommand: serviceCmd,
	}

	// 1. Ручной ввод пользователя (поле «Папка правил» и «Папка Kerio»).
	manualRules := normalizeKerioPath(extraRulesDir)
	if manualRules != "" {
		rep.ManualChecked = true
		probe := KerioProbe{Path: manualRules, Source: "указано вручную (папка правил)", Exists: dirExists(manualRules)}
		if probe.Exists {
			probe.Kind = "rules"
			probe.RulesDir = manualRules
			rep.RulesDir = manualRules
			rep.RulesDirSource = "указана вручную"
			rep.RulesDirExists = true
		}
		rep.Probes = append(rep.Probes, probe)
	}

	// 2. Гипотезы о папке установки: ручной ввод → служба/реестр → стандартные.
	type candidate struct{ path, source string }
	var cands []candidate
	seen := map[string]bool{}
	addCand := func(p, source string) {
		p = normalizeToKerioDir(p)
		if p == "" || seen[strings.ToLower(p)] {
			return
		}
		seen[strings.ToLower(p)] = true
		cands = append(cands, candidate{p, source})
	}
	addCand(extraKerioDir, "указано вручную (папка Kerio)")
	addCand(settings.KerioInstallPath, "сохранено в настройках программы")
	// Вложенная папка MailServer: пользователь мог указать C:\Program Files\Kerio
	if extraKerioDir != "" {
		if sub := filepath.Join(normalizeKerioPath(extraKerioDir), "MailServer"); dirExists(sub) {
			addCand(sub, "подпапка MailServer указанного каталога")
		}
	}
	for _, probe := range kerioSystemDirs() {
		addCand(probe.Path, probe.Source)
	}
	for _, c := range PlatformCandidateKerioDirs() {
		addCand(c, "стандартный путь")
	}

	for _, c := range cands {
		exists := dirExists(c.path)
		hasExe, hasCfg, hasPlugins := kerioInstallMarkers(c.path)
		probe := KerioProbe{
			Path: c.path, Source: c.source, Exists: exists,
			HasExe: hasExe, HasCfg: hasCfg, HasPlugins: hasPlugins,
		}
		switch {
		case looksLikeRulesDir(c.path) && exists:
			probe.Kind = "rules"
		case hasExe || hasCfg:
			probe.Kind = "kerio"
		case hasPlugins:
			probe.Kind = "kerio"
			probe.Note = "есть plugins, но нет mailserver.exe/mailserver.cfg"
		case exists:
			probe.Kind = "unknown"
		}
		if exists && probe.Kind == "kerio" && rep.RulesDir == "" {
			if dir, src := findExistingRulesDir(c.path); dir != "" {
				probe.RulesDir = dir
				rep.RulesDir = dir
				rep.RulesDirSource = src
				rep.RulesDirExists = dirExists(dir)
				if rep.KerioDir == "" {
					rep.KerioDir = c.path
					rep.KerioDirSource = c.source
				}
			}
		}
		rep.Probes = append(rep.Probes, probe)
	}

	if rep.KerioDir == "" {
		for _, p := range rep.Probes {
			if p.Exists && p.Kind == "kerio" {
				rep.KerioDir = p.Path
				rep.KerioDirSource = p.Source
				break
			}
		}
	}
	// Если правила нашлись, но папку Kerio ещё не определили — выводим её из пути.
	if rep.RulesDir != "" && rep.KerioDir == "" {
		rep.KerioDir = normalizeToKerioDir(rep.RulesDir)
		rep.KerioDirSource = "выведен из пути к правилам"
	}

	// Широкий поиск: помогает, когда установка нестандартная, а службы нет.
	if rep.RulesDir == "" {
		if dir, src := findRulesDirInSearchRoots(); dir != "" {
			rep.RulesDir = dir
			rep.RulesDirSource = src
			rep.RulesDirExists = dirExists(dir)
			if rep.KerioDir == "" {
				rep.KerioDir = normalizeToKerioDir(dir)
				rep.KerioDirSource = src
			}
		}
	}
	for _, root := range PlatformKerioSearchRoots() {
		if !dirExists(normalizeKerioPath(root)) {
			continue
		}
		rep.Probes = append(rep.Probes, KerioProbe{
			Path: normalizeKerioPath(root), Source: "широкий поиск", Exists: true,
			Kind: "unknown", Note: "обход дерева на наличие spamassassin",
		})
	}

	rep.SearchedDirs = len(rep.Probes)
	rep.Advice = kerioPathAdvice(&rep)
	rep.ElapsedMs = time.Since(start).Milliseconds()
	rep.Summary = kerioPathSummary(&rep)
	return rep
}

// kerioPathSummary — одна строка для UI и текста ошибки.
func kerioPathSummary(rep *KerioPathReport) string {
	existing := 0
	for _, p := range rep.Probes {
		if p.Exists {
			existing++
		}
	}
	if rep.RulesDir != "" {
		return "Каталог правил найден: " + rep.RulesDir
	}
	if existing == 0 {
		return fmt.Sprintf("Проверено путей: %d — ни один не существует. Похоже, Kerio Connect установлен на другом компьютере или в другом каталоге.", len(rep.Probes))
	}
	return fmt.Sprintf("Проверено путей: %d, существует %d, но папки правил SpamAssassin среди них нет.", len(rep.Probes), existing)
}

// kerioPathAdvice — понятные шаги «что делать» под конкретную ситуацию.
func kerioPathAdvice(rep *KerioPathReport) []string {
	var advice []string

	if rep.RulesDir != "" {
		if rep.RulesDirExists {
			advice = append(advice, "Каталог правил найден: "+rep.RulesDir+" — можно устанавливать базу.")
		} else {
			advice = append(advice, "Каталог правил найден: "+rep.RulesDir+" — при установке программа создаст его сама и положит kerio-antispam.cf внутрь.")
		}
		return advice
	}

	if !rep.IsWindows {
		advice = append(advice,
			"Программа запущена не на Windows. На Linux-сервере правила лежат в /opt/kerio/mailserver/plugins/spamassassin/rules (или /usr/local/kerio/mailserver/plugins/spamassassin/rules).",
			"Скопируйте kerio-antispam.cf на сервер и перезапустите Kerio: /etc/init.d/kerio-connect restart (или systemctl restart kerio-connect).")
		return advice
	}

	anyExisting := false
	for _, p := range rep.Probes {
		if p.Exists {
			anyExisting = true
			break
		}
	}

	if !anyExisting {
		advice = append(advice,
			"Kerio Connect не найден на этом компьютере. Если почтовый сервер стоит на другой машине — установка базы возможна только там.",
			"Тогда: скачайте .cf кнопкой «⬇ Скачать .cf», положите файл на сервер в <Kerio>\\plugins\\spamassassin\\rules и перезапустите службу KerioMailServer.",
			"Либо впишите сетевой путь к серверу в поле «Папка правил», например \\\\SERVER\\c$\\Program Files\\Kerio\\MailServer\\plugins\\spamassassin\\rules (нужны права администратора на том сервере).")
		return advice
	}

	advice = append(advice,
		"Папка Kerio найдена, но папки SpamAssassin внутри нет. Откройте в Проводнике каталог установки Kerio, затем plugins — и посмотрите, как называется папка с правилами (обычно spamassassin или spamserver\\spamassassin).",
		"Впишите этот путь в поле «Папка правил SpamAssassin» (например ...\\plugins\\spamserver\\spamassassin\\rules) — программа запомнит его и больше спрашивать не будет.",
		"Если папка называется spamassassin, но внутри нет rules — просто укажите саму папку spamassassin: подпапка rules будет создана автоматически.")
	if !rep.Admin {
		advice = append(advice, "Запустите программу от имени администратора: без этого запись в C:\\Program Files запрещена.")
	}
	if rep.ServiceStatus == "NOT_INSTALLED" {
		advice = append(advice, "Служба KerioMailServer на этом компьютере не зарегистрирована — значит, Kerio здесь не установлен как служба (портативная сборка или другой сервер).")
	}
	return advice
}

// kerioPathError формирует текст ошибки установки: конкретика вместо общей фразы.
func kerioPathError(rep KerioPathReport) error {
	var b strings.Builder
	b.WriteString("не найден каталог правил SpamAssassin Kerio Connect.\n\n")
	b.WriteString("Что проверено:\n")
	shown := 0
	for _, p := range rep.Probes {
		if shown >= 6 {
			b.WriteString("• … (полный список — кнопка «Что проверено» на вкладке «Антиспам»)\n")
			break
		}
		status := "папки нет"
		if p.Exists {
			status = "папка есть"
			switch {
			case p.RulesDir != "":
				status += ", правила: " + p.RulesDir
			case p.HasPlugins:
				status += ", внутри есть plugins, но нет spamassassin"
			case p.Kind == "unknown":
				status += ", признаков Kerio нет"
			}
		}
		fmt.Fprintf(&b, "• %s — %s (%s)\n", p.Path, status, p.Source)
		shown++
	}
	if len(rep.Probes) == 0 {
		b.WriteString("• ни один путь не удалось проверить\n")
	}
	b.WriteString("\nЧто делать:\n")
	for i, a := range rep.Advice {
		if i >= 3 {
			break
		}
		fmt.Fprintf(&b, "%d) %s\n", i+1, a)
	}
	return fmt.Errorf("%s", strings.TrimSpace(b.String()))
}

// sortProbes ставит сначала существующие каталоги — так отчёт читается сверху вниз.
func sortProbes(probes []KerioProbe) {
	sort.SliceStable(probes, func(i, j int) bool {
		if probes[i].Exists != probes[j].Exists {
			return probes[i].Exists
		}
		if (probes[i].RulesDir != "") != (probes[j].RulesDir != "") {
			return probes[i].RulesDir != ""
		}
		return probes[i].Path < probes[j].Path
	})
}

// ---------------------------------------------------------------------------
// Выбор каталога для установки
// ---------------------------------------------------------------------------

// RulesDirChoice — выбранный каталог правил и откуда он взялся.
type RulesDirChoice struct {
	Dir      string          `json:"dir"`
	Source   string          `json:"source"`
	Exists   bool            `json:"exists"`
	KerioDir string          `json:"kerioDir"`
	Report   KerioPathReport `json:"report,omitempty"`
}

// ChooseRulesDir решает, куда ставить kerio-antispam.cf.
//
// Пользователь мог ввести в поля разное:
//   - …\plugins\spamassassin\rules  — папку правил;
//   - …\plugins\spamassassin        — саму папку SpamAssassin (rules создадим);
//   - C:\Program Files\Kerio\MailServer — папку установки Kerio;
//   - \\server\c$\…\rules           — сетевой путь (Kerio на другом ПК);
//   - ничего.
//
// create=true (установка) разрешает создать папку rules, create=false
// (проверка статуса, предпросмотр) — только ищет существующую.
func ChooseRulesDir(settings SavedUISettings, st AntiSpamState, kerioHint, rulesHint string, create bool) RulesDirChoice {
	var choice RulesDirChoice
	hint := normalizeKerioPath(rulesHint)

	// 1. Пользователь явно указал папку правил (или папку spamassassin).
	if hint != "" {
		base := strings.ToLower(filepath.Base(hint))
		if base == "rules" {
			if create {
				_ = os.MkdirAll(hint, 0o755)
			}
			if dirExists(hint) {
				choice.Dir, choice.Source, choice.Exists = hint, "указана вручную", true
				choice.KerioDir = normalizeToKerioDir(hint)
				return choice
			}
			choice.Source = "указанный каталог правил недоступен"
		}
		if base == "spamassassin" {
			rules := filepath.Join(hint, "rules")
			if create {
				_ = os.MkdirAll(rules, 0o755)
			}
			if dirExists(rules) {
				choice.Dir, choice.Source, choice.Exists = rules, "внутри указанной папки spamassassin", true
				choice.KerioDir = normalizeToKerioDir(hint)
				return choice
			}
		}
		if kerioHint == "" {
			// Возможно, это папка установки Kerio, а не папка правил.
			kerioHint = hint
		}
	}

	// 2. Каталог, сохранённый от прошлой установки.
	if p := normalizeKerioPath(st.RulesDir); p != "" && dirExists(p) {
		choice.Dir, choice.Source, choice.Exists = p, "сохранён с прошлой установки", true
		choice.KerioDir = normalizeToKerioDir(st.KerioDir)
		return choice
	}

	// 3. Ищем внутри Kerio: указанная папка → сохранённая → автоопределение.
	for _, kd := range []string{kerioHint, st.KerioDir, settings.KerioInstallPath} {
		if strings.TrimSpace(kd) == "" {
			continue
		}
		if create {
			if dir, existed := detectSpamAssassinRulesDir(kd); dir != "" {
				choice.Dir, choice.Exists, choice.Source = dir, existed, "найден в Kerio"
				choice.KerioDir = normalizeToKerioDir(kd)
				return choice
			}
		} else if dir, src := findExistingRulesDir(kd); dir != "" {
			choice.Dir, choice.Source, choice.Exists = dir, src, dirExists(dir)
			choice.KerioDir = normalizeToKerioDir(kd)
			return choice
		}
	}
	if kd, src := resolveKerioInstallDir(settings); kd != "" {
		if create {
			if dir, existed := detectSpamAssassinRulesDir(kd); dir != "" {
				choice.Dir, choice.Exists, choice.Source = dir, existed, "найден через "+src
				choice.KerioDir = kd
				return choice
			}
		} else if dir, src2 := findExistingRulesDir(kd); dir != "" {
			choice.Dir, choice.Source, choice.Exists = dir, src2, dirExists(dir)
			choice.KerioDir = kd
			return choice
		}
	}

	// 3.5. Последняя попытка: обходим «широкие» корни Kerio на дисках.
	if dir, src := findRulesDirInSearchRoots(); dir != "" {
		choice.Dir, choice.Source, choice.Exists = dir, src, dirExists(dir)
		if !create && !dirExists(dir) {
			choice.Dir = ""
		}
		if choice.Dir != "" {
			choice.KerioDir = normalizeToKerioDir(dir)
			return choice
		}
	}

	// 4. Ничего не нашли — собираем отчёт для понятной ошибки.
	choice.Report = DiagnoseKerioPaths(settings, kerioHint, rulesHint)
	if hint != "" && choice.Source == "" {
		choice.Source = "указанный путь не подошёл"
	}
	return choice
}

// RulesDirError — ошибка «куда ставить» с подробным отчётом.
func RulesDirError(choice RulesDirChoice) error {
	if choice.Report.OK {
		return kerioPathError(choice.Report)
	}
	rep := DiagnoseKerioPaths(LoadSavedUISettings(DefaultCertsRoot()), "", "")
	return kerioPathError(rep)
}

// firstNonEmpty возвращает первое непустое значение (удобно для отчётов).
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Разбор вывода системных утилит (чистые функции — тестируются на любой ОС)
// ---------------------------------------------------------------------------

// kerioSysCacheTTL — сколько секунд доверять сведениям о службе и реестре.
const kerioSysCacheTTL = 90 * time.Second

// parseScBinaryPath достаёт путь запуска службы из вывода `sc qc`:
//
//	BINARY_PATH_NAME   : "C:\Program Files\Kerio\MailServer\mailserver.exe" -dir "..."
func parseScBinaryPath(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(strings.ToUpper(line), "BINARY_PATH_NAME") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		if cmd := strings.TrimSpace(line[idx+1:]); cmd != "" {
			return cmd
		}
	}
	// Страховка для локализованной Windows, где подписи полей переведены:
	// ищем любую строку с путём к mailserver.exe и берём её после двоеточия.
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(strings.ToLower(line), "mailserver.exe") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		if cmd := strings.TrimSpace(line[idx+1:]); cmd != "" {
			return cmd
		}
	}
	return ""
}

// parseRegSZ вытаскивает первое значение вида REG_SZ/REG_EXPAND_SZ из вывода
// `reg query … /v Имя`.
func parseRegSZ(out string) string {
	for _, line := range strings.Split(out, "\n") {
		for _, kind := range []string{"REG_SZ", "REG_EXPAND_SZ"} {
			if idx := strings.Index(line, kind); idx >= 0 {
				v := strings.TrimSpace(line[idx+len(kind):])
				if v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// parseKerioPathValues вытаскивает из вывода `reg query ключ /s` все строковые
// значения, которые похожи на путь установки Kerio (содержат kerio/mailserver).
func parseKerioPathValues(out string) []string {
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		value := ""
		for _, kind := range []string{"REG_SZ", "REG_EXPAND_SZ"} {
			if idx := strings.Index(line, kind); idx >= 0 {
				value = strings.TrimSpace(line[idx+len(kind):])
				break
			}
		}
		if value == "" {
			continue
		}
		low := strings.ToLower(value)
		if !strings.Contains(low, "kerio") && !strings.Contains(low, "mailserver.cfg") {
			continue
		}
		if strings.HasSuffix(low, ".exe") || strings.HasSuffix(low, ".dll") {
			value = dirOfPathAnySep(normalizeKerioPath(value))
		}
		paths = append(paths, value)
	}
	return paths
}

// parseInstallLocationValues достаёт InstallLocation из вывода reg query
// по ветке Uninstall (там лежат записи «Программ и компонентов»).
func parseInstallLocationValues(out string) []string {
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(strings.ToUpper(line), "INSTALLLOCATION") {
			continue
		}
		if idx := strings.Index(line, "REG_SZ"); idx >= 0 {
			if v := strings.TrimSpace(line[idx+len("REG_SZ"):]); v != "" {
				paths = append(paths, v)
			}
		}
	}
	return paths
}

// parseKerioServiceNames достаёт имена служб из вывода
// `reg query HKLM\SYSTEM\CurrentControlSet\Services /f Kerio /k`.
func parseKerioServiceNames(out string) []string {
	var names []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(line), "HKEY_LOCAL_MACHINE") {
			continue
		}
		idx := strings.LastIndexAny(line, `\/`)
		if idx < 0 || idx+1 >= len(line) {
			continue
		}
		name := line[idx+1:]
		if !strings.Contains(strings.ToLower(name), "kerio") || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true
		names = append(names, name)
	}
	return names
}
