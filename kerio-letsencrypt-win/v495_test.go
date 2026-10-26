package main

// v495_test.go — проверки релиза v4.9.5:
//   • кнопка «Скачать APK для телефона» в программе для Windows;
//   • проверка обновлений в приложении Android и её кнопка;
//   • проверка спам-баз на телефоне (контрольная точка + несколько каналов DNS).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
		"DnsSystem.query(",
		"dohUsable(",
		"resetDohBreaker()",
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

// TestDownloadAndroidApk — полный путь кнопки без сети: фальшивый GitHub
// отдаёт релиз, фальшивый сервер — APK. Проверяем, что файл сохранился,
// SHA-256 посчитан, а «не-APK» (без PK) отвергается.
func TestDownloadAndroidApk(t *testing.T) {
	payload := append([]byte("PK\x03\x04"), make([]byte, 2048)...)
	assetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer assetSrv.Close()

	releaseSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := fmt.Sprintf(`[{"tag_name":"v9.9.9","assets":[{"name":"KerioCertManager-Mobile-9.9.9.apk","size":%d,"browser_download_url":%q}]}]`,
			len(payload), assetSrv.URL+"/apk")
		_, _ = w.Write([]byte(body))
	}))
	defer releaseSrv.Close()

	t.Setenv("KCM_UPDATE_API", releaseSrv.URL)
	dir := t.TempDir()
	t.Setenv("KCM_ANDROID_APK_DIR", dir)

	state, err := DownloadAndroidApk(context.Background())
	if err != nil {
		t.Fatalf("скачивание не удалось: %v", err)
	}
	if state.MobileVersion != "9.9.9" {
		t.Errorf("версия %q, ожидалась 9.9.9", state.MobileVersion)
	}
	if state.FileSize != int64(len(payload)) {
		t.Errorf("размер %d, ожидался %d", state.FileSize, len(payload))
	}
	if len(state.FileSHA256) != 64 {
		t.Errorf("SHA-256 не посчитан: %q", state.FileSHA256)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "KerioCertManager-Mobile-9.9.9.apk")); statErr != nil {
		t.Errorf("файл не сохранён в папку: %v", statErr)
	}
}

func TestDownloadAndroidApkRejectsNonApk(t *testing.T) {
	assetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>это не APK</html>"))
	}))
	defer assetSrv.Close()

	releaseSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := fmt.Sprintf(`[{"tag_name":"v9.9.9","assets":[{"name":"KerioCertManager-Mobile-9.9.9.apk","size":26,"browser_download_url":%q}]}]`,
			assetSrv.URL+"/apk")
		_, _ = w.Write([]byte(body))
	}))
	defer releaseSrv.Close()

	t.Setenv("KCM_UPDATE_API", releaseSrv.URL)
	dir := t.TempDir()
	t.Setenv("KCM_ANDROID_APK_DIR", dir)

	if _, err := DownloadAndroidApk(context.Background()); err == nil {
		t.Fatal("файл без признака ZIP принят как APK")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "KerioCertManager-Mobile-9.9.9.apk")); statErr == nil {
		t.Error("испорченный файл остался на диске")
	}
}

// TestAndroidRblUsesSystemResolver — главный канал проверки спам-баз на
// телефоне: системный резолвер Android. Именно его отсутствие в 4.9.5 давало
// «нет ответа» на всех базах, кроме первой (DNS-over-HTTPS ограничивал частоту).
func TestAndroidRblUsesSystemResolver(t *testing.T) {
	dns := readRepoFile(t, "../android/src/by/csl/kcm/DnsSystem.java")
	for _, want := range []string{
		"android.net.DnsResolver",
		"rawQuery(",
		"RCODE_NXDOMAIN",
		"Build.VERSION_CODES.Q",
	} {
		if !strings.Contains(dns, want) {
			t.Errorf("DnsSystem.java: нет %q", want)
		}
	}
	// Обратный вызов обязан соответствовать API: onAnswer(answer, rcode).
	if !strings.Contains(dns, "public void onAnswer(byte[] answer, int rcode)") {
		t.Error("DnsSystem.java: подпись onAnswer не совпадает с DnsResolver.Callback")
	}
	if !strings.Contains(dns, "public void onError(DnsResolver.DnsException error)") {
		t.Error("DnsSystem.java: подпись onError не совпадает с DnsResolver.Callback")
	}

	// Контекст приложения передаётся из Activity — иначе резолвер недоступен.
	main := readRepoFile(t, "../android/src/by/csl/kcm/MainActivity.java")
	if !strings.Contains(main, "Checks.init(getApplicationContext())") {
		t.Error("MainActivity.java: Checks.init не вызывается")
	}
	checks := readRepoFile(t, "../android/src/by/csl/kcm/Checks.java")
	if !strings.Contains(checks, "static void init(Context context)") {
		t.Error("Checks.java: нет init(Context)")
	}
}
