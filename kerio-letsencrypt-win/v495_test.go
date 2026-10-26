package main

// v495_test.go — проверки релиза v4.9.5:
//   • кнопка «Скачать APK для телефона» в программе для Windows;
//   • проверка обновлений в приложении Android и её кнопка;
//   • проверка спам-баз на телефоне (контрольная точка + несколько каналов DNS).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPickNewestAndroidRelease — из списка релизов берётся самый новый,
// в котором действительно есть APK. Служебные теги, черновики и pre-release
// не должны попадать в выбор ни при каких обстоятельствах.
func TestPickNewestAndroidRelease(t *testing.T) {
	releases := []githubRelease{
		{TagName: "antispam-db-latest", Assets: []githubAsset{{Name: "rules.tar.gz"}}},
		{TagName: "kerio-latest", Assets: []githubAsset{{Name: "KerioCertManager.exe"}}},
		{TagName: "v4.9.3", Assets: []githubAsset{{Name: "KerioCertManager-Mobile-4.9.3.apk"}}},
		{TagName: "v4.9.5", Assets: []githubAsset{
			{Name: "KerioCertManager.exe"},
			{Name: "KerioCertManager-Mobile-4.9.5.apk", Size: 42000, Digest: "sha256:" + strings.Repeat("a", 64)},
		}},
		{TagName: "v4.9.9", Draft: true, Assets: []githubAsset{{Name: "KerioCertManager-Mobile-4.9.9.apk"}}},
		{TagName: "v4.9.8", Prerelease: true, Assets: []githubAsset{{Name: "KerioCertManager-Mobile-4.9.8.apk"}}},
		{TagName: "v4.9.6", Assets: []githubAsset{{Name: "KerioCertManager-Windows-x64.zip"}}},
	}
	rel, asset, ok := pickNewestAndroidRelease(releases)
	if !ok {
		t.Fatal("APK не найден, хотя релиз v4.9.5 его содержит")
	}
	if rel.TagName != "v4.9.5" {
		t.Errorf("выбран релиз %s, ожидался v4.9.5", rel.TagName)
	}
	if asset.Name != "KerioCertManager-Mobile-4.9.5.apk" {
		t.Errorf("выбран файл %s", asset.Name)
	}
}

func TestPickNewestAndroidReleaseEmpty(t *testing.T) {
	if _, _, ok := pickNewestAndroidRelease([]githubRelease{
		{TagName: "kerio-latest", Assets: []githubAsset{{Name: "KerioCertManager.exe"}}},
	}); ok {
		t.Error("релиз без APK не должен считаться подходящим")
	}
}

func TestPickAndroidApkAssetIgnoresOtherFiles(t *testing.T) {
	rel := githubRelease{Assets: []githubAsset{
		{Name: "KerioCertManager-Mobile-4.9.5.apk.sha256"},
		{Name: "KerioCertManager-Setup-4.9.5.exe"},
		{Name: "KerioCertManager-Mobile-4.9.5.apk"},
	}}
	asset, ok := pickAndroidApkAsset(&rel)
	if !ok || asset.Name != "KerioCertManager-Mobile-4.9.5.apk" {
		t.Fatalf("выбран не тот файл: %q, ok=%v", asset.Name, ok)
	}
}

// TestFindDownloadedApk — программа должна находить уже скачанный файл после
// перезапуска, а не предлагать качать заново.
func TestFindDownloadedApk(t *testing.T) {
	dir := t.TempDir()
	if path, _, _, _ := findDownloadedApk(dir); path != "" {
		t.Fatalf("в пустой папке найден файл %q", path)
	}
	older := filepath.Join(dir, "KerioCertManager-Mobile-4.9.4.apk")
	newer := filepath.Join(dir, "KerioCertManager-Mobile-4.9.5.apk")
	for _, p := range []string{older, newer} {
		if err := os.WriteFile(p, []byte("PK\x03\x04test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Явно разносим время изменения: файловая система может округлять метки.
	jan := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	feb := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(older, jan, jan); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newer, feb, feb); err != nil {
		t.Fatal(err)
	}
	path, size, sum, _ := findDownloadedApk(dir)
	if filepath.Base(path) != "KerioCertManager-Mobile-4.9.5.apk" {
		t.Fatalf("выбран файл %q, ожидался самый новый", path)
	}
	if size != 8 {
		t.Errorf("размер %d, ожидался 8", size)
	}
	if len(sum) != 64 {
		t.Errorf("SHA-256 не посчитан: %q", sum)
	}
}

func TestHumanSize(t *testing.T) {
	cases := map[int64]string{
		900:       "900 Б",
		42 * 1024: "42.0 КБ",
		5 << 20:   "5.0 МБ",
	}
	for in, want := range cases {
		if got := humanSize(in); got != want {
			t.Errorf("humanSize(%d) = %q, ожидалось %q", in, got, want)
		}
	}
}

// TestAndroidApkRoutesRegistered — без маршрутов кнопка в интерфейсе молчит.
func TestAndroidApkRoutesRegistered(t *testing.T) {
	src := readRepoFile(t, "handlers_v46.go")
	if !strings.Contains(src, "registerAndroidApkRoutes(mux)") {
		t.Fatal("registerAndroidApkRoutes не вызывается из registerV46Routes")
	}
	apk := readRepoFile(t, "android_apk.go")
	for _, want := range []string{
		`"/api/android/apk"`,
		`"/api/android/apk/download"`,
		`"/api/android/apk/open"`,
		`"/api/mobile/apk"`,
	} {
		if !strings.Contains(apk, want) {
			t.Errorf("android_apk.go: нет маршрута %s", want)
		}
	}
	// Файл, отданный телефону, обязан проверяться: только APK из папки загрузок.
	if !strings.Contains(apk, `string(head) != "PK"`) {
		t.Error("android_apk.go: не проверяется, что скачанный файл — APK")
	}
}

// TestAndroidApkCardInUI — карточка и обработчики кнопки должны быть в интерфейсе.
func TestAndroidApkCardInUI(t *testing.T) {
	html := readRepoFile(t, "ui/index.html")
	for _, want := range []string{
		`id="androidApkCard"`,
		`id="androidApkDownloadBtn"`,
		"function downloadAndroidApk",
		"function loadAndroidApk",
		"/api/android/apk/download",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("ui/index.html: нет %q", want)
		}
	}
}

// TestAndroidRblUsesControlPoint — проверка спам-баз на телефоне обязана
// отличать «записи нет» от «база не отвечает». Для этого есть контрольная
// точка 2.0.0.127 и несколько каналов DNS.
func TestAndroidRblUsesControlPoint(t *testing.T) {
	src := readRepoFile(t, "../android/src/by/csl/kcm/Checks.java")
	for _, want := range []string{
		`CONTROL_IP = "2.0.0.127"`,
		"zoneAlive(",
		"probeDoh(",
		"probeSystem(",
		"probeUdp(",
		"cloudflare-dns.com",
		"dns.google",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("Checks.java: нет %q", want)
		}
	}
	// Мёртвые зоны не должны возвращаться в список: они дают только «нет ответа».
	for _, dead := range []string{"dnsbl.sorbs.net", "cbl.abuseat.org"} {
		if strings.Contains(src, dead) {
			t.Errorf("Checks.java: закрытая база %s снова в списке", dead)
		}
	}
	// Отказ Spamhaus публичным резолверам — это не «спам», а «проверьте на сайте».
	if !strings.Contains(src, "127.255.255.") {
		t.Error("Checks.java: не распознаётся отказ Spamhaus (127.255.255.x)")
	}
}

// TestAndroidUpdateButtonAlwaysRecovers — после неудачной проверки кнопка
// обновления обязана снова стать нажимаемой. Именно из-за этого «кнопки нет»:
// она оставалась серой и не реагировала.
func TestAndroidUpdateButtonAlwaysRecovers(t *testing.T) {
	src := readRepoFile(t, "../android/src/by/csl/kcm/MainActivity.java")
	if !strings.Contains(src, "updateButton.setEnabled(true)") {
		t.Fatal("MainActivity.java: кнопка обновления не включается обратно")
	}
	if strings.Contains(src, `"⬇ Проверить обновления"`) {
		t.Error("MainActivity.java: остался символ ⬇, который не рисуется на телефоне")
	}
	if !strings.Contains(src, "🔄 Проверить обновления") {
		t.Error("MainActivity.java: нет понятной подписи кнопки проверки обновлений")
	}
}
