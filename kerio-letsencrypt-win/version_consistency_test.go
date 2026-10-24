package main

// version_consistency_test.go — «сторож» единообразия сборки.
//
// Идея простая: версия программы и количество проверяемых чёрных списков
// должны совпадать во всех местах сразу — в коде, в UI и в PE-ресурсе Windows.
// Если кто-то поправил одно и забыл другое, `go test ./...` (а значит и CI
// перед сборкой .exe) падает с понятным сообщением. Именно это не даёт
// «сборке откатиться» к смешанным версиям: старый exe с новым UI и т.п.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"
)

// readRepoFile читает файл относительно каталога пакета (kerio-letsencrypt-win).
func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"."}, strings.Split(rel, "/")...)...))
	if err != nil {
		t.Fatalf("не удалось прочитать %s: %v", rel, err)
	}
	return string(b)
}

func TestAppVersionFormat(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(appVersion) {
		t.Fatalf("appVersion = %q: ожидается формат X.Y.Z", appVersion)
	}
	if appVersion4 != appVersion+".0" {
		t.Fatalf("appVersion4 = %q: ожидается %q", appVersion4, appVersion+".0")
	}
}

func TestUIUsesAppVersion(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	if !strings.Contains(ui, "GUI v"+appVersion) {
		t.Errorf("ui/index.html: бейдж в шапке не содержит «GUI v%s»", appVersion)
	}
	if !strings.Contains(ui, "Suite v"+appVersion) {
		t.Errorf("ui/index.html: строка в подвале не содержит «Suite v%s»", appVersion)
	}
	if !strings.Contains(ui, "const APP_VERSION = '"+appVersion+"'") {
		t.Errorf("ui/index.html: JS-константа APP_VERSION не равна %q", appVersion)
	}
}

func TestWindowsResourceMatchesAppVersion(t *testing.T) {
	raw, err := os.ReadFile("rsrc_windows_amd64.syso")
	if err != nil {
		t.Fatalf("нет rsrc_windows_amd64.syso: %v", err)
	}

	want := utf16.Encode([]rune(appVersion4))
	pat := make([]byte, 0, len(want)*2)
	for _, r := range want {
		pat = append(pat, byte(r), byte(r>>8))
	}
	if n := bytes.Count(raw, pat); n != 4 {
		t.Errorf("rsrc_windows_amd64.syso: строк %q найдено %d, ожидалось 4 (FileVersion/ProductVersion + строковые ресурсы)", appVersion4, n)
	}

	sig := []byte{0xbd, 0x04, 0xef, 0xfe} // 0xFEEF04BD
	i := bytes.Index(raw, sig)
	if i < 0 {
		t.Fatalf("rsrc_windows_amd64.syso: не найден VS_FIXEDFILEINFO")
	}
	// VS_FIXEDFILEINFO: DWORD × 13, нужны FileVersionMS/LS, ProductVersionMS/LS и FileFlagsMask.
	get := func(offset int) uint32 { return binary.LittleEndian.Uint32(raw[i+offset:]) }
	fileMS, fileLS := get(8), get(12)
	prodMS, prodLS := get(16), get(20)
	mask := get(24)

	parts := strings.Split(appVersion, ".")
	var major, minor, patch uint32
	if _, err := fmt.Sscanf(parts[0], "%d", &major); err != nil {
		t.Fatalf("appVersion %q: %v", appVersion, err)
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &minor); err != nil {
		t.Fatalf("appVersion %q: %v", appVersion, err)
	}
	if _, err := fmt.Sscanf(parts[2], "%d", &patch); err != nil {
		t.Fatalf("appVersion %q: %v", appVersion, err)
	}

	wantMS := (major << 16) | minor
	wantLS := patch << 16

	if fileMS != wantMS || fileLS != wantLS {
		t.Errorf("syso FileVersion = %d.%d.%d.0, ожидалось %s",
			fileMS>>16, fileMS&0xffff, fileLS>>16, appVersion4)
	}
	if prodMS != wantMS || prodLS != wantLS {
		t.Errorf("syso ProductVersion = %d.%d.%d.0, ожидалось %s",
			prodMS>>16, prodMS&0xffff, prodLS>>16, appVersion4)
	}
	if mask != 0x3f {
		t.Errorf("syso dwFileFlagsMask = 0x%x, ожидалось 0x3f (ресурс повреждён)", mask)
	}
}

func TestClientUserAgentUsesAppVersion(t *testing.T) {
	want := "KerioCertManager/" + appVersion + " (Windows)"
	if kerioClientUserAgent != want {
		t.Fatalf("kerioClientUserAgent = %q, ожидалось %q", kerioClientUserAgent, want)
	}
}

// TestBlacklistCountsMatchUI не даёт подписи «16 RBL баз / 4 DBL базы» разойтись
// с реально опрашиваемыми списками (именно из-за такого расхождения раньше
// в UI стояло 16, в коде — 11 «мёртвых», а аудит использовал третью копию).
func TestBlacklistCountsMatchUI(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")
	want := fmt.Sprintf("Репутация IP (%d RBL баз) + Репутация Домена (%d DBL базы)",
		len(dnsblProviders), len(domainRBLProviders))
	if !strings.Contains(ui, want) {
		t.Fatalf("ui/index.html: подпись списков не совпадает с кодом.\nНужно: %s\n(провайдеры: dnsblProviders=%d, domainRBLProviders=%d)",
			want, len(dnsblProviders), len(domainRBLProviders))
	}

	seen := map[string]bool{}
	for _, p := range dnsblProviders {
		if strings.TrimSpace(p.zone) == "" {
			t.Errorf("провайдер %q: пустая RBL-зона", p.name)
		}
		if seen[p.zone] {
			t.Errorf("дубликат RBL-зоны %q", p.zone)
		}
		seen[p.zone] = true
	}
	for _, p := range domainRBLProviders {
		if strings.TrimSpace(p.zone) == "" {
			t.Errorf("доменный провайдер %q: пустая зона", p.name)
		}
	}
}

func TestNoStaleVersionInShippedDocs(t *testing.T) {
	// Документация обязана называть ту же версию, что и код.
	faq := readRepoFile(t, "../FAQ.md")
	if !strings.Contains(faq, "KerioCertManager v"+appVersion) {
		t.Errorf("FAQ.md: заголовок не содержит «KerioCertManager v%s»", appVersion)
	}
	readme := readRepoFile(t, "README.md")
	if !strings.Contains(readme, "Suite v"+appVersion) {
		t.Errorf("kerio-letsencrypt-win/README.md: заголовок не содержит «Suite v%s»", appVersion)
	}
}
