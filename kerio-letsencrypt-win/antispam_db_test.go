package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestCompareAntiSpamVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2026.10.24-0810", "2026.10.24-0810", 0},
		{"2026.10.25-0000", "2026.10.24-2359", 1},
		{"2026.10.23-2359", "2026.10.24-0000", -1},
		{"2026.9.30-1200", "2026.10.01-0000", -1},
		{"", "2026.10.24-0810", -1},
	}
	for _, c := range cases {
		if got := compareAntiSpamVersions(c.a, c.b); got != c.want {
			t.Errorf("compareAntiSpamVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseAntiSpamRuleNames(t *testing.T) {
	cf := `# Версия базы: 2026.10.24-0810
header   KCM_SPAM_FROM_DOMAIN_001   From =~ /@evil\.com/i
score    KCM_SPAM_FROM_DOMAIN_001   3.2
header   KCM_ALLOW_FROM_001   From =~ /@bank\.by/i
body     KCM_SCAM_PHRASE_001   /оплатите комиссию/i
uri      KCM_PHISH_URL_001   /(?i)(?:evil\.com)/
`
	version, counts, total := parseAntiSpamRuleNames([]byte(cf))
	if version != "2026.10.24-0810" {
		t.Fatalf("version = %q", version)
	}
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if counts["domains"] != 1 || counts["phrases"] != 1 || counts["urls"] != 1 || counts["allowlist"] != 1 {
		t.Fatalf("unexpected counts: %#v", counts)
	}
	groups := antiSpamGroupsFromCounts(counts)
	if len(groups) != len(antiSpamRuleGroupMeta) {
		t.Fatalf("groups = %d, want %d", len(groups), len(antiSpamRuleGroupMeta))
	}
}

func TestValidateAntiSpamRuleFile(t *testing.T) {
	good := "# KCM AntiSpam DB\nheader KCM_SPAM_FROM_DOMAIN_001   From =~ /@evil\\.com/i\nscore KCM_SPAM_FROM_DOMAIN_001 3.2\n"
	if err := validateAntiSpamRuleFile([]byte(good)); err != nil {
		t.Fatalf("good file rejected: %v", err)
	}
	bad := []struct {
		name string
		data string
	}{
		{"no rules", "# KCM AntiSpam DB\n"},
		{"unknown directive", "hacker KCM_X 1\n"},
		{"unclosed regex", "header KCM_SPAM_FROM_DOMAIN_001 From =~ /@evil.com\n"},
	}
	for _, c := range bad {
		if err := validateAntiSpamRuleFile([]byte(c.data)); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

func TestBuildAntiSpamDiff(t *testing.T) {
	oldCF := "# Версия базы: 1.0\nheader KCM_SPAM_FROM_DOMAIN_001 From =~ /@a\\.com/i\nscore KCM_SPAM_FROM_DOMAIN_001 3.2\n"
	newCF := "# Версия базы: 2.0\nheader KCM_SPAM_FROM_DOMAIN_001 From =~ /@a\\.com/i\nscore KCM_SPAM_FROM_DOMAIN_001 3.2\n" +
		"header KCM_SPAM_FROM_DOMAIN_002 From =~ /@b\\.com/i\nscore KCM_SPAM_FROM_DOMAIN_002 3.2\n"
	diff := buildAntiSpamDiff([]byte(oldCF), []byte(newCF))
	if diff.OldVersion != "1.0" || diff.NewVersion != "2.0" {
		t.Fatalf("versions: %#v", diff)
	}
	if diff.OldTotal != 1 || diff.NewTotal != 2 || diff.AddedCount != 1 || diff.RemovedCount != 0 {
		t.Fatalf("unexpected diff: %#v", diff)
	}
	if len(diff.SampleNew) != 1 || !strings.Contains(diff.SampleNew[0], "KCM_SPAM_FROM_DOMAIN_002") {
		t.Fatalf("sample = %#v", diff.SampleNew)
	}
}

func TestAntiSpamEmailDryRun(t *testing.T) {
	certsDir := t.TempDir()
	listsDir := antiSpamListsDir(certsDir)
	if err := os.MkdirAll(listsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"spam-domains.txt":    "scam-sender.com\n",
		"phishing-links.txt":  "evil-phish.com\n",
		"spam-emails.txt":     "bad@evil-phish.com\n",
		"scam-subjects.txt":   "аккаунт будет заблокирован\n",
		"scam-phrases-ru.txt": "оплатите комиссию\n",
		"threat-ips.txt":      "203.0.113.0/24\n",
		"allowlist.txt":       "trusted.by\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(listsDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	raw := strings.Join([]string{
		`From: "Банк" <bad@evil-phish.com>`,
		`Subject: Ваш аккаунт будет заблокирован`,
		`Received: from unknown (unknown [203.0.113.45]) by mail.company.by`,
		`Content-Type: text/plain; charset=UTF-8`,
		``,
		`Оплатите комиссию и перейдите по ссылке https://evil-phish.com/login`,
	}, "\r\n")

	res, err := TestEmailAgainstAntiSpamDB(certsDir, raw)
	if err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	if res.FromDomain != "evil-phish.com" {
		t.Fatalf("fromDomain = %q", res.FromDomain)
	}
	linkHit := false
	for _, m := range res.Matches {
		if m.Rule == "KCM_PHISH_URL" {
			linkHit = true
		}
	}
	if !linkHit {
		t.Fatalf("expected KCM_PHISH_URL match from phishing-links.txt, got %#v", res.Matches)
	}
	if res.RulesHit < 5 {
		t.Fatalf("expected >= 5 matched groups, got %d (%#v)", res.RulesHit, res.Matches)
	}
	if res.Level != "spam" || res.Score < 5 {
		t.Fatalf("expected spam verdict, got level=%q score=%.1f", res.Level, res.Score)
	}

	allowRaw := "From: client@trusted.by\r\nSubject: Счёт\r\n\r\nОплатите комиссию\r\n"
	allowRes, err := TestEmailAgainstAntiSpamDB(certsDir, allowRaw)
	if err != nil {
		t.Fatalf("allowlist dry-run failed: %v", err)
	}
	if allowRes.Level != "clean" {
		t.Fatalf("allowlisted sender must be clean, got %q (%.1f)", allowRes.Level, allowRes.Score)
	}
}

func TestImportAntiSpamRuleFile(t *testing.T) {
	certsDir := t.TempDir()
	kerioDir := t.TempDir()
	rulesDir := filepath.Join(kerioDir, "plugins", "spamassassin", "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SaveUISettings(certsDir, SavedUISettings{KerioInstallPath: kerioDir}); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "kerio-antispam.cf")
	cf := "# Версия базы: 2026.10.24-1200\nheader KCM_SPAM_FROM_DOMAIN_001 From =~ /@bad\\.com/i\n"
	if err := os.WriteFile(src, []byte(cf), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ImportAntiSpamRuleFile(certsDir, src, false)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if res.Version != "2026.10.24-1200" {
		t.Fatalf("version = %q", res.Version)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, antiSpamRuleFileName)); err != nil {
		t.Fatalf("rule file not written: %v", err)
	}
	st := GetAntiSpamStatus(certsDir)
	if !st.Installed || st.Version != "2026.10.24-1200" {
		t.Fatalf("status after import: installed=%v version=%q", st.Installed, st.Version)
	}
}

// buildTestManifest собирает manifest.json + файлы базы для локального зеркала.
func buildTestManifest(t *testing.T, version string) (map[string][]byte, []byte) {
	t.Helper()
	cf := fmt.Sprintf(`# Версия базы: %s
header   KCM_SPAM_FROM_DOMAIN_001   From =~ /@evil\\.com/i
describe KCM_SPAM_FROM_DOMAIN_001   Тестовое правило
score    KCM_SPAM_FROM_DOMAIN_001   3.2
header   KCM_ALLOW_FROM_001         From =~ /@bank\\.by/i
score    KCM_ALLOW_FROM_001         -6.0
`, version)
	files := map[string][]byte{
		antiSpamRuleFileName:  []byte(cf),
		"spam-domains.txt":    []byte("evil.com\n"),
		"phishing-links.txt":  []byte("phish.example\n"),
		"spam-emails.txt":     []byte("bad@evil.com\n"),
		"scam-subjects.txt":   []byte("выигрыш\n"),
		"scam-phrases-ru.txt": []byte("оплатите комиссию\n"),
		"threat-ips.txt":      []byte("203.0.113.0/24\n"),
		"allowlist.txt":       []byte("bank.by\n"),
	}
	sha := map[string]string{}
	sizes := map[string]int{}
	names := make([]string, 0, len(files))
	for name, data := range files {
		sum := sha256.Sum256(data)
		sha[name] = hex.EncodeToString(sum[:])
		sizes[name] = len(data)
		names = append(names, name)
	}
	sort.Strings(names)
	manifest := AntiSpamManifest{
		Schema:      1,
		Version:     version,
		GeneratedAt: "2026-10-24T00:00:00Z",
		Counts:      map[string]int{"domains": 1, "allowlist": 1},
		Files:       names,
		SHA256:      sha,
		Sizes:       sizes,
		RuleFile:    antiSpamRuleFileName,
		Credits:     []string{"test"},
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return files, raw
}

func newTestMirror(t *testing.T, version string) (*httptest.Server, map[string][]byte) {
	t.Helper()
	files, manifest := buildTestManifest(t, version)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "manifest.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(manifest)
			return
		}
		data, ok := files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv, files
}

func TestInstallAntiSpamDBFromMirror(t *testing.T) {
	srv, _ := newTestMirror(t, "2026.10.24-0810")
	t.Setenv("KCM_ANTISPAM_DB_BASE", srv.URL)

	certsDir := t.TempDir()
	kerioDir := t.TempDir()
	rulesDir := filepath.Join(kerioDir, "plugins", "spamassassin", "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SaveUISettings(certsDir, SavedUISettings{KerioInstallPath: kerioDir}); err != nil {
		t.Fatal(err)
	}

	res, err := InstallAntiSpamDB(certsDir, AntiSpamInstallOptions{Restart: false})
	if err != nil {
		t.Fatalf("install failed: %v", err)
	}
	if res.Version != "2026.10.24-0810" || res.TotalRules != 2 {
		t.Fatalf("unexpected result: version=%q rules=%d", res.Version, res.TotalRules)
	}
	installed, err := os.ReadFile(filepath.Join(rulesDir, antiSpamRuleFileName))
	if err != nil {
		t.Fatalf("rule file missing: %v", err)
	}
	if !strings.Contains(string(installed), "2026.10.24-0810") {
		t.Fatalf("installed file has wrong version")
	}
	if _, err := os.Stat(antiSpamListsDir(certsDir)); err != nil {
		t.Fatalf("lists dir missing: %v", err)
	}

	st := GetAntiSpamStatus(certsDir)
	if !st.Installed || st.Version != "2026.10.24-0810" {
		t.Fatalf("status: installed=%v version=%q", st.Installed, st.Version)
	}
	if !st.ListsAvailable {
		t.Fatalf("expected all local lists available")
	}

	// Повторная проверка: обновлений нет
	preview, err := PreviewAntiSpamInstall(certsDir)
	if err != nil {
		t.Fatalf("preview failed: %v", err)
	}
	if !preview.UpToDate {
		t.Fatalf("expected up-to-date preview, got %#v", preview.Diff)
	}
}

func TestInstallAndRollbackAntiSpamDB(t *testing.T) {
	srv1, _ := newTestMirror(t, "2026.10.24-0810")
	t.Setenv("KCM_ANTISPAM_DB_BASE", srv1.URL)

	certsDir := t.TempDir()
	kerioDir := t.TempDir()
	rulesDir := filepath.Join(kerioDir, "plugins", "spamassassin", "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SaveUISettings(certsDir, SavedUISettings{KerioInstallPath: kerioDir}); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallAntiSpamDB(certsDir, AntiSpamInstallOptions{Restart: false}); err != nil {
		t.Fatalf("first install failed: %v", err)
	}

	// Новая версия на «GitHub»
	srv2, _ := newTestMirror(t, "2026.10.25-0100")
	t.Setenv("KCM_ANTISPAM_DB_BASE", srv2.URL)
	res2, err := InstallAntiSpamDB(certsDir, AntiSpamInstallOptions{Restart: false})
	if err != nil {
		t.Fatalf("second install failed: %v", err)
	}
	if res2.Version != "2026.10.25-0100" {
		t.Fatalf("second install version = %q", res2.Version)
	}
	if res2.BackupPath == "" {
		t.Fatalf("expected backup path on second install")
	}

	rb, err := RollbackAntiSpamDB(certsDir, false)
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if rb.Version != "2026.10.24-0810" {
		t.Fatalf("rollback version = %q", rb.Version)
	}
	st := GetAntiSpamStatus(certsDir)
	if st.Version != "2026.10.24-0810" {
		t.Fatalf("status version after rollback = %q", st.Version)
	}

	if _, err := RemoveAntiSpamDB(certsDir, false); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, antiSpamRuleFileName)); !os.IsNotExist(err) {
		t.Fatalf("rule file still exists after remove")
	}
}

func TestFetchAntiSpamManifestBadChecksum(t *testing.T) {
	srv, files := newTestMirror(t, "2026.10.24-0900")
	// Портим правило: SHA-256 в manifest.json больше не совпадёт
	files[antiSpamRuleFileName] = append(files[antiSpamRuleFileName], []byte("\n# tampered\n")...)
	t.Setenv("KCM_ANTISPAM_DB_BASE", srv.URL)

	certsDir := t.TempDir()
	kerioDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(kerioDir, "plugins", "spamassassin", "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SaveUISettings(certsDir, SavedUISettings{KerioInstallPath: kerioDir}); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallAntiSpamDB(certsDir, AntiSpamInstallOptions{Restart: false}); err == nil {
		t.Fatalf("expected checksum error, install succeeded")
	} else if !strings.Contains(err.Error(), "контрольная сумма") {
		t.Fatalf("unexpected error: %v", err)
	}
}
