package main

// v492_test.go — проверки релиза v4.9.2 «Android-пульт и проверки с телефона».
//
// Главное, что здесь защищается: пунт для телефона не должен пускать кого
// попало. Это полный доступ к API программы, поэтому без кода не должно быть
// видно ничего, кроме /api/ping, а код должен сравниваться безопасно и
// меняться при каждом включении.

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestLanAccessCodeFormat — код должен состоять ровно из 6 цифр: его диктуют
// голосом и вводят одной рукой на телефоне.
func TestLanAccessCodeFormat(t *testing.T) {
	re := regexp.MustCompile(`^[0-9]{6}$`)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		code := newLanAccessCode()
		if !re.MatchString(code) {
			t.Fatalf("код %q не соответствует формату 6 цифр", code)
		}
		seen[code] = true
	}
	if len(seen) < 20 {
		t.Fatalf("код почти не меняется: %d разных из 50 попыток", len(seen))
	}
}

func TestCodeMatches(t *testing.T) {
	cases := []struct {
		got, want string
		ok        bool
	}{
		{"123456", "123456", true},
		{" 123456 ", "123456", true},
		{"123456", "123457", false},
		{"", "123456", false},
		{"123456", "", false},
		{"12345", "123456", false},
		{"1234567", "123456", false},
	}
	for _, c := range cases {
		if got := codeMatches(c.got, c.want); got != c.ok {
			t.Errorf("codeMatches(%q, %q) = %v, ожидалось %v", c.got, c.want, got, c.ok)
		}
	}
}

// TestLanGuardBlocksWithoutCode — без кода и без cookie не должно быть доступа
// ни к одному маршруту, кроме /api/ping.
func TestLanGuardBlocksWithoutCode(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("SECRET-BODY"))
	})
	handler := lanGuard(inner, "424242")

	blocked := []string{"/", "/api/certs", "/api/kerio/install", "/index.html"}
	for _, path := range blocked {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: ожидался код 401, получено %d", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "SECRET-BODY") {
			t.Errorf("%s: содержимое программы утекло без кода", path)
		}
		if !strings.Contains(rec.Body.String(), "код доступа") {
			t.Errorf("%s: нет страницы ввода кода", path)
		}
	}
}

func TestLanGuardAllowsPingWithoutCode(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	rec := httptest.NewRecorder()
	lanGuard(inner, "424242").ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/ping должен отвечать без кода (по нему телефон ищет программу), получено %d", rec.Code)
	}
}

func TestLanGuardHeaderAndCookie(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("SECRET-BODY"))
	})
	handler := lanGuard(inner, "424242")

	// Заголовок X-KCM-Code — так ходит приложение.
	req := httptest.NewRequest(http.MethodGet, "/api/certs", nil)
	req.Header.Set(lanCodeHeader, "424242")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SECRET-BODY") {
		t.Fatalf("с верным заголовком доступ должен быть открыт, получено %d", rec.Code)
	}

	// Cookie — после первого входа через ?code=.
	req2 := httptest.NewRequest(http.MethodGet, "/api/certs", nil)
	req2.AddCookie(&http.Cookie{Name: lanCookieName, Value: "424242"})
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("с верной cookie доступ должен быть открыт, получено %d", rec2.Code)
	}

	// Чужой код — отказ.
	req3 := httptest.NewRequest(http.MethodGet, "/api/certs", nil)
	req3.Header.Set(lanCodeHeader, "000000")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("с неверным кодом должен быть отказ, получено %d", rec3.Code)
	}
}

// TestLanGuardCodeInQuerySetsCookie — вход по ссылке с кодом ставит cookie и
// убирает код из адреса, чтобы он не остался в истории браузера.
func TestLanGuardCodeInQuerySetsCookie(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	req := httptest.NewRequest(http.MethodGet, "/?code=424242", nil)
	rec := httptest.NewRecorder()
	lanGuard(inner, "424242").ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("ожидался редирект 303 после ввода кода, получено %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "424242") {
		t.Errorf("код остался в адресе после входа: %s", loc)
	}
	var found bool
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == lanCookieName && ck.Value == "424242" {
			found = true
			if !ck.HttpOnly {
				t.Error("cookie с кодом доступа должна быть HttpOnly")
			}
		}
	}
	if !found {
		t.Fatal("cookie с кодом доступа не установлена")
	}
}

// TestLanURLsFormat — адреса для телефона должны быть полными URL с портом
// и без 127.0.0.1 (иначе телефон будет стучаться сам в себя).
func TestLanURLsFormat(t *testing.T) {
	for _, u := range lanURLs(17840) {
		if !strings.HasPrefix(u, "http://") || !strings.HasSuffix(u, ":17840/") {
			t.Errorf("некорректный адрес для телефона: %q", u)
		}
		if strings.Contains(u, "127.0.0.1") || strings.Contains(u, "0.0.0.0") {
			t.Errorf("в адресах для телефона не должно быть локальных заглушек: %q", u)
		}
	}
}

// TestLanRemoteStartStop — полный цикл: включили, получили код и адрес,
// выключили — код забыт и порт закрыт.
func TestLanRemoteStartStop(t *testing.T) {
	StopLanRemote() // на случай, если предыдущий тест оставил пунт
	defer StopLanRemote()

	info, err := StartLanRemote(0)
	if err != nil {
		t.Fatalf("не удалось включить пунт: %v", err)
	}
	if !info.Enabled || len(info.Code) != 6 || info.Port == 0 {
		t.Fatalf("некорректное состояние пунта: %+v", info)
	}

	// Пинг по реальному порту должен работать без кода.
	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(info.Port) + "/api/ping")
	if err != nil {
		t.Fatalf("пунт не отвечает по сети: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("пинг вернул %d", resp.StatusCode)
	}

	// Без кода — 401 на любой другой адрес.
	resp2, err := http.Get("http://127.0.0.1:" + strconv.Itoa(info.Port) + "/")
	if err != nil {
		t.Fatalf("пунт не отвечает: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("без кода главная страница должна требовать код, получено %d", resp2.StatusCode)
	}

	StopLanRemote()
	if state := LanRemoteState(); state.Enabled {
		t.Fatalf("после выключения пунт должен быть выключен: %+v", state)
	}
}

// TestLanRoutesRegistered — маршруты управления пунтом должны быть в роутере
// и в интерфейсе, иначе карточка в программе не работает.
func TestLanRoutesRegistered(t *testing.T) {
	// В main.go достаточно самого вызова: маршруты живут в lan_access.go.
	mainSrc := readRepoFile(t, "main.go")
	if !strings.Contains(mainSrc, "registerLanRoutes(mux)") {
		t.Error("main.go: маршруты пунта не подключены к роутеру")
	}
	lan := readRepoFile(t, "lan_access.go")
	for _, want := range []string{
		"/api/mobile/remote", "/api/mobile/remote/start",
		"/api/mobile/remote/stop", "/api/mobile/remote/code",
	} {
		if !strings.Contains(lan, want) {
			t.Errorf("lan_access.go: нет маршрута %q", want)
		}
	}
	ui := readRepoFile(t, "ui/index.html")
	for _, want := range []string{
		`id="androidRemoteStartBtn"`, `id="androidRemoteStopBtn"`,
		"/api/mobile/remote/start", "androidRemoteCard",
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui/index.html: нет %q", want)
		}
	}
	faq := readRepoFile(t, "../FAQ.md")
	for _, want := range []string{"## 22. Android-приложение", "### 22.2 Режим", "### 22.3 Режим"} {
		if !strings.Contains(faq, want) {
			t.Errorf("FAQ.md: нет раздела %q", want)
		}
	}
}

// TestAndroidProjectConsistent — версия и пакет в Android-проекте должны
// совпадать с программой, иначе APK «отстанет» от релиза.
func TestAndroidProjectConsistent(t *testing.T) {
	java := readRepoFile(t, "../android/src/by/csl/kcm/Versions.java")
	if !strings.Contains(java, `APP_VERSION = "`+appVersion+`"`) {
		t.Errorf("Versions.java не содержит версию %s", appVersion)
	}
	manifest := readRepoFile(t, "../android/AndroidManifest.xml")
	if !strings.Contains(manifest, `android:versionName="`+appVersion+`"`) {
		t.Errorf("AndroidManifest.xml не содержит версию %s", appVersion)
	}
	for _, want := range []string{`package="by.csl.kcm"`, "android.permission.INTERNET", "usesCleartextTraffic"} {
		if !strings.Contains(manifest, want) {
			t.Errorf("AndroidManifest.xml: нет %q", want)
		}
	}
	// Обе вкладки приложения должны существовать в исходниках.
	main := readRepoFile(t, "../android/src/by/csl/kcm/MainActivity.java")
	for _, want := range []string{"RemotePane", "CheckPane"} {
		if !strings.Contains(main, want) {
			t.Errorf("MainActivity.java: нет %q", want)
		}
	}
	checks := readRepoFile(t, "../android/src/by/csl/kcm/Checks.java")
	for _, want := range []string{"checkTls", "checkDns", "checkPorts", "checkRbl"} {
		if !strings.Contains(checks, want) {
			t.Errorf("Checks.java: нет проверки %q", want)
		}
	}

	// versionCode обязан соответствовать версии: от него зависит, примет ли
	// Android APK «поверх» установленного.
	parts := strings.Split(appVersion, ".")
	if len(parts) != 3 {
		t.Fatalf("appVersion %q не в формате X.Y.Z", appVersion)
	}
	var nums [3]int
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			t.Fatalf("appVersion %q: %v", appVersion, err)
		}
		nums[i] = n
	}
	wantCode := nums[0]*10000 + nums[1]*100 + nums[2]
	if !strings.Contains(manifest, `android:versionCode="`+strconv.Itoa(wantCode)+`"`) {
		t.Errorf("AndroidManifest.xml: versionCode должен быть %d", wantCode)
	}
	if !strings.Contains(java, "VERSION_CODE = "+strconv.Itoa(wantCode)+";") {
		t.Errorf("Versions.java: VERSION_CODE должен быть %d", wantCode)
	}
	if !strings.Contains(java, `REPO = "zigorminsk-debug/jiraHelp"`) {
		t.Error("Versions.java: не указан репозиторий обновлений")
	}

	// Обновление с GitHub: класс загрузки, провайдер файла и разрешение
	// на установку APK — без любого из них кнопка обновления не работает.
	updates := readRepoFile(t, "../android/src/by/csl/kcm/Updates.java")
	for _, want := range []string{"api.github.com", "isNewer", "downloadAndInstall",
		"canRequestPackageInstalls", "ACTION_MANAGE_UNKNOWN_APP_SOURCES"} {
		if !strings.Contains(updates, want) {
			t.Errorf("Updates.java: нет %q", want)
		}
	}
	if !strings.Contains(manifest, "android.permission.REQUEST_INSTALL_PACKAGES") {
		t.Error("AndroidManifest.xml: нет разрешения REQUEST_INSTALL_PACKAGES")
	}
	if !strings.Contains(manifest, `android:name=".UpdateProvider"`) {
		t.Error("AndroidManifest.xml: не объявлен UpdateProvider")
	}
	if !strings.Contains(main, "Проверить обновления") {
		t.Error("MainActivity.java: нет кнопки проверки обновлений")
	}

	// Постоянный ключ подписи: без него обновления не устанавливаются поверх.
	ks := readRepoFile(t, "../android/keystore/keystore.properties")
	for _, want := range []string{"storePassword=", "keyAlias=", "sha256="} {
		if !strings.Contains(ks, want) {
			t.Errorf("keystore.properties: нет %q", want)
		}
	}
	build := readRepoFile(t, "../android/build-apk.sh")
	for _, want := range []string{"kcm-release.p12", "Ожидался", "apksigner"} {
		if !strings.Contains(build, want) {
			t.Errorf("build-apk.sh: нет %q", want)
		}
	}
}
