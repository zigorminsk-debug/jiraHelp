package main

// kerio_paths_test.go — проверки поиска каталога правил SpamAssassin.
//
// Эти тесты родились из реальной жалобы: «не найден каталог SpamAssassin
// Kerio Connect», хотя сервер стоял штатно. Причина — старая версия искала
// всего три пути и не умела ни читать команду запуска службы Kerio, ни
// обходить дерево установки. Здесь зафиксированы ВСЕ раскладки, которые
// встречаются у администраторов, чтобы поиск снова не «сломался».

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeKerioTree создаёт дерево каталогов и возвращает его корень.
func makeKerioTree(t *testing.T, relDirs ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range relDirs {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
	}
	return root
}

func TestSpamAssassinCandidatesCoverRealLayouts(t *testing.T) {
	// Пути, которые встречаются на настоящих серверах (см. шапку kerio_paths.go).
	kerio := filepath.FromSlash(`C:/Program Files (x86)/Kerio/MailServer`)
	cands := spamAssassinRulesCandidates(kerio)

	want := []string{
		filepath.FromSlash(`C:/Program Files (x86)/Kerio/MailServer/plugins/spamassassin/rules`),
		filepath.FromSlash(`C:/Program Files (x86)/Kerio/MailServer/plugins/spamserver/spamassassin/rules`),
	}
	for _, w := range want {
		found := false
		for _, c := range cands {
			if strings.EqualFold(filepath.ToSlash(c), filepath.ToSlash(w)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("в списке кандидатов нет реального пути %q\nполучено: %v", w, cands)
		}
	}
}

func TestDetectRulesDirClassicLayout(t *testing.T) {
	kerio := makeKerioTree(t, "plugins/spamassassin/rules")
	// Признаки настоящей установки Kerio.
	writeTestFile(t, filepath.Join(kerio, "mailserver.cfg"), "<config/>")

	dir, existed := detectSpamAssassinRulesDir(kerio)
	want := filepath.Join(kerio, "plugins", "spamassassin", "rules")
	if dir != want || !existed {
		t.Fatalf("получено (%q, %v), ожидалось (%q, true)", dir, existed, want)
	}
}

// Самый частый реальный случай: 32-битный Kerio на 64-битной Windows,
// правила лежат в plugins\spamserver\spamassassin\rules.
func TestDetectRulesDirSpamServerLayout(t *testing.T) {
	kerio := makeKerioTree(t, "plugins/spamserver/spamassassin/rules")
	writeTestFile(t, filepath.Join(kerio, "mailserver.exe"), "MZ")

	dir, existed := detectSpamAssassinRulesDir(kerio)
	want := filepath.Join(kerio, "plugins", "spamserver", "spamassassin", "rules")
	if dir != want || !existed {
		t.Fatalf("получено (%q, %v), ожидалось (%q, true)", dir, existed, want)
	}
}

// Папка spamassassin есть, а rules в ней ещё нет (правила не настраивались).
// Программа обязана создать rules РЯДОМ с существующей папкой, а не в другом
// месте дерева — иначе Kerio файл не прочитает.
func TestDetectRulesDirCreatesRulesInsideSpamServer(t *testing.T) {
	kerio := makeKerioTree(t, "plugins/spamserver/spamassassin")

	dir, existed := detectSpamAssassinRulesDir(kerio)
	want := filepath.Join(kerio, "plugins", "spamserver", "spamassassin", "rules")
	if dir != want {
		t.Fatalf("правила созданы в %q, ожидалось %q", dir, want)
	}
	if existed {
		t.Errorf("existed = true, хотя папка только что создана")
	}
	if !dirExists(want) {
		t.Fatalf("папка %q не создана", want)
	}
	// Неправильный вариант (plugins\spamassassin\rules) появляться не должен.
	if dirExists(filepath.Join(kerio, "plugins", "spamassassin", "rules")) {
		t.Errorf("создана лишняя папка plugins/spamassassin/rules")
	}
}

// Нестандартная установка: правила глубже обычного.
func TestDetectRulesDirDeepCustomLayout(t *testing.T) {
	kerio := makeKerioTree(t, "custom/kerio/plugins/spamassassin/rules")
	writeTestFile(t, filepath.Join(kerio, "mailserver.cfg"), "<config/>")

	dir, _ := detectSpamAssassinRulesDir(kerio)
	want := filepath.Join(kerio, "custom", "kerio", "plugins", "spamassassin", "rules")
	if dir != want {
		t.Fatalf("получено %q, ожидалось %q", dir, want)
	}
}

// Совсем редкий случай: папка с правилами называется иначе, но внутри
// лежат настоящие .cf с директивами SpamAssassin — её тоже надо найти.
func TestDetectRulesDirByContent(t *testing.T) {
	kerio := makeKerioTree(t, "plugins/myfilters")
	writeTestFile(t, filepath.Join(kerio, "mailserver.cfg"), "<config/>")
	writeTestFile(t, filepath.Join(kerio, "plugins", "myfilters", "10_custom.cf"),
		"# custom\nheader TEST_SUBJ Subject =~ /viagra/i\nscore TEST_SUBJ 2.5\n")

	dir, existed := detectSpamAssassinRulesDir(kerio)
	want := filepath.Join(kerio, "plugins", "myfilters")
	if dir != want || !existed {
		t.Fatalf("получено (%q, %v), ожидалось (%q, true)", dir, existed, want)
	}
}

// Пользователь ввёл в поле «Папка правил» саму папку spamassassin —
// подставляем rules внутри неё.
func TestChooseRulesDirFromSpamAssassinFolder(t *testing.T) {
	kerio := makeKerioTree(t, "plugins/spamassassin")
	settings := SavedUISettings{}
	hint := filepath.Join(kerio, "plugins", "spamassassin")

	choice := ChooseRulesDir(settings, AntiSpamState{}, "", hint, true)
	want := filepath.Join(hint, "rules")
	if choice.Dir != want {
		t.Fatalf("получено %q, ожидалось %q (source=%q)", choice.Dir, want, choice.Source)
	}
	if !dirExists(want) {
		t.Fatalf("папка %q не создана", want)
	}
}

// Пользователь ввёл в поле «Папка правил» уже готовый каталог rules.
func TestChooseRulesDirFromRulesFolder(t *testing.T) {
	kerio := makeKerioTree(t, "plugins/spamassassin/rules")
	hint := filepath.Join(kerio, "plugins", "spamassassin", "rules")

	choice := ChooseRulesDir(SavedUISettings{}, AntiSpamState{}, "", hint, true)
	if choice.Dir != hint || !choice.Exists {
		t.Fatalf("получено (%q, %v), ожидалось (%q, true)", choice.Dir, choice.Exists, hint)
	}
}

// Пользователь указал папку установки Kerio в поле «Папка правил».
func TestChooseRulesDirFromKerioFolderHint(t *testing.T) {
	kerio := makeKerioTree(t, "plugins/spamassassin/rules")
	writeTestFile(t, filepath.Join(kerio, "mailserver.cfg"), "<config/>")

	choice := ChooseRulesDir(SavedUISettings{}, AntiSpamState{}, "", kerio, true)
	want := filepath.Join(kerio, "plugins", "spamassassin", "rules")
	if choice.Dir != want {
		t.Fatalf("получено %q, ожидалось %q", choice.Dir, want)
	}
}

// Сохранённый с прошлой установки путь имеет приоритет над автопоиском.
func TestChooseRulesDirUsesSavedPath(t *testing.T) {
	saved := makeKerioTree(t, "rules")
	st := AntiSpamState{RulesDir: saved, KerioDir: t.TempDir()}

	choice := ChooseRulesDir(SavedUISettings{}, st, "", "", true)
	if choice.Dir != saved || !choice.Exists {
		t.Fatalf("получено (%q, %v), ожидалось (%q, true)", choice.Dir, choice.Exists, saved)
	}
}

// Ничего не найдено → отчёт с проверенными путями и внятными подсказками.
func TestChooseRulesDirNotFoundProducesReport(t *testing.T) {
	empty := t.TempDir()
	choice := ChooseRulesDir(SavedUISettings{KerioInstallPath: empty}, AntiSpamState{}, "", "", true)

	if choice.Dir != "" {
		// На машине с установленным Kerio (например, при прогоне тестов на
		// сервере) правило может найтись по-настоящему — это не ошибка теста.
		t.Skipf("на этой машине найден реальный Kerio: %s", choice.Dir)
	}
	if !choice.Report.OK {
		t.Fatalf("отчёт диагностики не заполнен")
	}
	if len(choice.Report.Probes) == 0 {
		t.Fatalf("в отчёте нет ни одного проверенного пути")
	}
	if len(choice.Report.Advice) == 0 {
		t.Fatalf("в отчёте нет ни одной подсказки")
	}
	err := RulesDirError(choice)
	if err == nil || !strings.Contains(err.Error(), "Что проверено") {
		t.Fatalf("ошибка должна перечислять проверенные пути, получено: %v", err)
	}
	if !strings.Contains(err.Error(), "Что делать") {
		t.Fatalf("ошибка должна содержать раздел «Что делать», получено: %v", err)
	}
}

// Разбор команды запуска службы: путь к exe и параметр -dir.
// Пути собираем через filepath.Join, чтобы тест проверял логику разбора, а не
// различия разделителей Windows и Linux (CI собирает и тестирует на Linux).
func TestKerioDirsFromServiceCommand(t *testing.T) {
	base := filepath.Join("C:", "Kerio", "MailServer")
	exe := filepath.Join(base, "mailserver.exe")
	dataDir := filepath.Join("C:", "Kerio", "data")

	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			name: "кавычки + -dir",
			cmd:  `"` + exe + `" -dir "` + dataDir + `"`,
			want: []string{base, dataDir},
		},
		{
			name: "без кавычек",
			cmd:  exe + ` -dir ` + dataDir,
			want: []string{base, dataDir},
		},
		{
			name: "только exe без параметров",
			cmd:  `"` + exe + `"`,
			want: []string{base},
		},
		{
			name: "служба с другим именем файла",
			cmd:  `"` + filepath.Join(base, "mailserver") + `" -dir "` + dataDir + `"`,
			want: []string{base, dataDir},
		},
		{
			name: "мусор",
			cmd:  `не путь`,
			want: nil,
		},
	}
	for _, c := range cases {
		got := kerioDirsFromServiceCommand(c.cmd)
		if len(got) != len(c.want) {
			t.Fatalf("%s: получено %v, ожидалось %v", c.name, got, c.want)
		}
		for i := range c.want {
			if !strings.EqualFold(filepath.ToSlash(got[i]), filepath.ToSlash(c.want[i])) {
				t.Fatalf("%s: получено %v, ожидалось %v", c.name, got, c.want)
			}
		}
	}
}

// Дубликаты путей не должны появляться: exe и -dir часто указывают на одно место.
func TestKerioDirsFromServiceCommandDedup(t *testing.T) {
	base := filepath.Join("C:", "Kerio", "MailServer")
	cmd := `"` + filepath.Join(base, "mailserver.exe") + `" -dir "` + base + `"`
	if got := kerioDirsFromServiceCommand(cmd); len(got) != 1 {
		t.Fatalf("ожидался один путь, получено %v", got)
	}
}

// Нормализация путей: кавычки, хвостовые слэши, внутренние папки Kerio.
func TestNormalizeKerioPath(t *testing.T) {
	root := t.TempDir()
	kerio := filepath.Join(root, "Kerio", "MailServer")
	cases := map[string]string{
		`"` + kerio + `"`:                                        kerio,
		kerio + string(filepath.Separator):                       kerio,
		filepath.Join(kerio, "plugins", "spamassassin"):          kerio,
		filepath.Join(kerio, "plugins", "spamserver"):            kerio,
		filepath.Join(kerio, "plugins", "spamassassin", "rules"): kerio,
		"   ": "",
	}
	for in, want := range cases {
		if got := normalizeToKerioDir(in); got != want {
			t.Errorf("normalizeToKerioDir(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

// На Windows в поле вставляют путь с переменными окружения (%ProgramFiles%).
func TestExpandPercentEnv(t *testing.T) {
	t.Setenv("KCM_TEST_DIR", filepath.Join("C:", "Program Files"))
	if got := expandPercentEnv(`%KCM_TEST_DIR%\Kerio`); !strings.HasPrefix(got, filepath.Join("C:", "Program Files")) {
		t.Fatalf("expandPercentEnv вернул %q", got)
	}
	if got := expandPercentEnv(`%НЕТ_ТАКОЙ_ПЕРЕМЕННОЙ%\x`); got != `%НЕТ_ТАКОЙ_ПЕРЕМЕННОЙ%\x` {
		t.Fatalf("неизвестная переменная должна остаться как есть, получено %q", got)
	}
}

// UNC-путь (Kerio на другом компьютере) не должен ломать нормализацию.
func TestNormalizeUncPath(t *testing.T) {
	unc := `\\SERVER\c$\Program Files\Kerio\MailServer\plugins\spamassassin\rules`
	got := normalizeKerioPath(unc)
	if got == "" {
		t.Fatalf("UNC-путь потерялся")
	}
	if !strings.HasPrefix(got, `\\SERVER\c$`) {
		t.Fatalf("UNC-префикс повреждён: %q", got)
	}
}

func TestLooksLikeRulesDir(t *testing.T) {
	root := makeKerioTree(t, "spamassassin/rules", "spamassassin-empty")
	if !looksLikeRulesDir(filepath.Join(root, "spamassassin", "rules")) {
		t.Errorf("папка rules не распознана")
	}
	if !looksLikeRulesDir(filepath.Join(root, "spamassassin")) {
		t.Errorf("папка spamassassin с rules не распознана")
	}
	if looksLikeRulesDir(filepath.Join(root, "spamassassin-empty")) {
		t.Errorf("пустая папка spamassassin не должна считаться готовой")
	}
}

// Диагностика: отчёт JSON-совместим и содержит осмысленные поля.
func TestDiagnoseKerioPathsReport(t *testing.T) {
	kerio := makeKerioTree(t, "plugins/spamassassin/rules")
	writeTestFile(t, filepath.Join(kerio, "mailserver.cfg"), "<config/>")

	rep := DiagnoseKerioPaths(SavedUISettings{}, kerio, "")
	if !rep.OK {
		t.Fatalf("OK = false")
	}
	if rep.RulesDir == "" {
		t.Fatalf("каталог правил не найден в заведомо корректном дереве: %+v", rep)
	}
	if !strings.HasSuffix(filepath.ToSlash(rep.RulesDir), "plugins/spamassassin/rules") {
		t.Fatalf("неожиданный каталог правил: %q", rep.RulesDir)
	}
	if rep.Summary == "" {
		t.Errorf("пустой Summary")
	}
	if len(rep.Advice) == 0 {
		t.Errorf("пустой Advice")
	}
	if rep.OS == "" {
		t.Errorf("пустой OS")
	}
}

// Правила, которые пользователь явно указал вручную, важнее любых догадок.
func TestDiagnoseKerioPathsManualRulesWin(t *testing.T) {
	kerio := makeKerioTree(t, "plugins/spamassassin/rules")
	manual := makeKerioTree(t, "rules")
	writeTestFile(t, filepath.Join(manual, "rules", "10_local.cf"), "score X 1.0\n")

	rep := DiagnoseKerioPaths(SavedUISettings{KerioInstallPath: kerio}, "", filepath.Join(manual, "rules"))
	if rep.RulesDir != filepath.Join(manual, "rules") {
		t.Fatalf("RulesDir = %q, ожидался вручную указанный %q", rep.RulesDir, filepath.Join(manual, "rules"))
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Разбор вывода системных утилит — на реальных образцах вывода sc.exe/reg.exe
// ---------------------------------------------------------------------------

func TestParseScBinaryPath(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "стандартный вывод sc qc (CRLF)",
			out: "SERVICE_NAME: KerioMailServer\r\n" +
				"        TYPE               : 10  WIN32_OWN_PROCESS\r\n" +
				"        START_TYPE         : 2   AUTO_START\r\n" +
				"        BINARY_PATH_NAME   : \"C:\\Program Files\\Kerio\\MailServer\\mailserver.exe\" -dir \"C:\\Program Files\\Kerio\\MailServer\"\r\n" +
				"        DISPLAY_NAME       : Kerio Connect\r\n",
			want: `"C:\Program Files\Kerio\MailServer\mailserver.exe" -dir "C:\Program Files\Kerio\MailServer"`,
		},
		{
			name: "локализованный вывод без английских подписей",
			out:  "ИМЯ_СЛУЖБЫ: KerioMailServer\n        ПУТЬ_К_ФАЙЛУ : D:\\Kerio\\MailServer\\mailserver.exe -dir D:\\Kerio\\data\n",
			want: `D:\Kerio\MailServer\mailserver.exe -dir D:\Kerio\data`,
		},
		{
			name: "служба не найдена",
			out:  "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\r\n",
			want: "",
		},
		{
			name: "пустой вывод",
			out:  "",
			want: "",
		},
	}
	for _, c := range cases {
		if got := parseScBinaryPath(c.out); got != c.want {
			t.Errorf("%s:\n получено: %q\n ожидалось: %q", c.name, got, c.want)
		}
	}
}

func TestParseRegSZ(t *testing.T) {
	out := "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\KerioMailServer\r\n" +
		"    ImagePath    REG_EXPAND_SZ    \"C:\\Program Files\\Kerio\\MailServer\\mailserver.exe\" -dir \"C:\\Program Files\\Kerio\\MailServer\"\r\n"
	want := `"C:\Program Files\Kerio\MailServer\mailserver.exe" -dir "C:\Program Files\Kerio\MailServer"`
	if got := parseRegSZ(out); got != want {
		t.Fatalf("получено %q, ожидалось %q", got, want)
	}
}

func TestParseKerioPathValues(t *testing.T) {
	out := "HKEY_LOCAL_MACHINE\\SOFTWARE\\Kerio\\MailServer\r\n" +
		"    InstallPath    REG_SZ    C:\\Program Files\\Kerio\\MailServer\r\n" +
		"    Version    REG_SZ    10.0.1234\r\n" +
		"    RunDir    REG_SZ    D:\\Kerio\\data\r\n" +
		"    ExePath    REG_SZ    D:\\Kerio\\MailServer\\mailserver.exe\r\n"

	got := parseKerioPathValues(out)
	want := []string{`C:\Program Files\Kerio\MailServer`, `D:\Kerio\data`, `D:\Kerio\MailServer`}
	if len(got) != len(want) {
		t.Fatalf("получено %v, ожидалось %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("получено %v, ожидалось %v", got, want)
		}
	}
}

func TestParseInstallLocationValues(t *testing.T) {
	out := "HKEY_LOCAL_MACHINE\\...\\Uninstall\\Kerio Connect\r\n" +
		"    DisplayName     REG_SZ    Kerio Connect\r\n" +
		"    InstallLocation REG_SZ    C:\\Program Files\\Kerio\\MailServer\\\r\n"
	got := parseInstallLocationValues(out)
	if len(got) != 1 || got[0] != `C:\Program Files\Kerio\MailServer\` {
		t.Fatalf("получено %v", got)
	}
}

func TestParseKerioServiceNames(t *testing.T) {
	out := "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\KerioMailServer\r\n" +
		"End of search: 1 match(es) found.\r\n"
	got := parseKerioServiceNames(out)
	if len(got) != 1 || got[0] != "KerioMailServer" {
		t.Fatalf("получено %v", got)
	}
	// Дубликаты и посторонние ключи отбрасываются.
	out2 := "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\KerioMailServer\r\n" +
		"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\KerioMailServer\r\n" +
		"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Spooler\r\n"
	if got := parseKerioServiceNames(out2); len(got) != 1 {
		t.Fatalf("ожидалось одно имя службы, получено %v", got)
	}
}

// Интеграция: команда службы → каталоги → каталог правил.
func TestServiceCommandToRulesDir(t *testing.T) {
	kerio := makeKerioTree(t, "plugins/spamserver/spamassassin/rules")
	writeTestFile(t, filepath.Join(kerio, "mailserver.exe"), "MZ")
	cmd := `"` + filepath.Join(kerio, "mailserver.exe") + `" -dir "` + kerio + `"`

	dirs := kerioDirsFromServiceCommand(cmd)
	if len(dirs) == 0 {
		t.Fatalf("команда службы не разобрана: %q", cmd)
	}
	found := ""
	for _, d := range dirs {
		if r, _ := detectSpamAssassinRulesDir(d); r != "" {
			found = r
			break
		}
	}
	want := filepath.Join(kerio, "plugins", "spamserver", "spamassassin", "rules")
	if found != want {
		t.Fatalf("получено %q, ожидалось %q", found, want)
	}
}

// TestFindRulesDirInSearchRoots — службы нет, путь неизвестен, но Kerio
// установлен в «широком» корне: правила всё равно должны найтись.
func TestFindRulesDirInSearchRoots(t *testing.T) {
	root := makeKerioTree(t, "Kerio/MailServer/plugins/spamassassin/rules")
	t.Setenv("ProgramFiles", root)
	t.Setenv("ProgramFiles(x86)", "")
	t.Setenv("ProgramW6432", "")
	t.Setenv("ProgramData", "")

	// Платформенные корни на Linux — /opt/kerio и т.п., поэтому передаём
	// корень явно: проверяем саму логику обхода.
	dir, src := findRulesDirInRoots([]string{filepath.Join(root, "Kerio")})
	want := filepath.Join(root, "Kerio", "MailServer", "plugins", "spamassassin", "rules")
	if dir != want || src == "" {
		t.Fatalf("получено (%q, %q), ожидалось (%q, непустой источник)", dir, src, want)
	}
	// Несуществующие корни не должны ломать поиск.
	if d, _ := findRulesDirInRoots([]string{filepath.Join(root, "нет-такого"), filepath.Join(root, "Kerio")}); d != want {
		t.Fatalf("поиск по нескольким корням вернул %q", d)
	}
}
