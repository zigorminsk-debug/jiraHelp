package main

// kerio_auth_test.go — тесты карточки «Вход под администратором Kerio Connect».
//
// Главное, что защищаем:
//  1. при верном пароле проверка обязана завершиться успехом и показать, кто
//     вошёл, роль и права на сертификаты;
//  2. при неверном пароле/2FA/правах/сети — вернуть ПРИЧИНУ с шагами
//     устранения, а не просто «ошибка»;
//  3. пароль и токен никогда не попадают в отчёт (он копируется в буфер и
//     уходит в заявки).

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// mockKerio — минимальный сервер Kerio Connect Admin API для тестов.
type mockKerio struct {
	user       string
	password   string
	isAdmin    bool
	role       string
	twoFactor  bool
	htmlReply  bool
	loginCalls []string
	certError  bool
}

func (m *mockKerio) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin/api/jsonrpc/") {
			var req struct {
				Method string          `json:"method"`
				ID     int             `json:"id"`
				Params json.RawMessage `json:"params"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if m.htmlReply {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<html><body>login page</body></html>"))
				return
			}
			w.Header().Set("Content-Type", "application/json-rpc")
			reply := func(result any) {
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
			}
			fail := func(code int, msg string) {
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]any{"code": code, "message": msg}})
			}
			switch req.Method {
			case "Session.login":
				var p struct {
					UserName string `json:"userName"`
					Password string `json:"password"`
				}
				_ = json.Unmarshal(req.Params, &p)
				m.loginCalls = append(m.loginCalls, p.UserName)
				if m.twoFactor {
					fail(1002, "Two-factor authentication is required")
					return
				}
				if p.UserName != m.user || p.Password != m.password {
					fail(1000, "Invalid user name or password")
					return
				}
				http.SetCookie(w, &http.Cookie{Name: "SESSION_CONNECT_WEBADMIN", Value: "abc123", Path: "/"})
				reply(map[string]any{"token": "token-0123456789abcdef"})
			case "Session.whoAmI":
				reply(map[string]any{"userDetails": map[string]any{
					"loginName": m.user,
					"fullName":  "Kerio Administrator",
					"isAdmin":   m.isAdmin,
					"effectiveRole": map[string]any{
						"userRole": m.role,
					},
				}})
			case "Version.getProductVersion":
				reply(map[string]any{"productVersion": map[string]any{
					"productName": "Kerio Connect", "major": 9, "minor": 4, "revision": 1,
					"displayNumber": "9.4.1",
				}})
			case "Version.getApiVersion":
				reply(map[string]any{"apiVersion": 8})
			case "ConnectCertificate.get", "Certificates.get":
				if m.certError {
					fail(1003, "Access denied: permission denied")
					return
				}
				reply(map[string]any{"certificates": []any{
					map[string]any{"id": "1", "name": "server", "isActive": true},
				}})
			case "Session.logout":
				reply(map[string]any{})
			default:
				fail(-32601, "Method not found: "+req.Method)
			}
			return
		}
		if r.URL.Path == "/admin/" {
			_, _ = w.Write([]byte("<html>Kerio WebAdmin</html>"))
			return
		}
		http.NotFound(w, r)
	})
}

func startMockKerio(t *testing.T, m *mockKerio) (host string, port int) {
	t.Helper()
	srv := httptest.NewTLSServer(m.handler())
	t.Cleanup(srv.Close)
	u := srv.URL // https://127.0.0.1:PORT
	u = strings.TrimPrefix(u, "https://")
	host, portStr, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatalf("не удалось разобрать адрес тестового сервера %q: %v", srv.URL, err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("порт тестового сервера: %v", err)
	}
	return host, p
}

func authCauseCodes(res KerioAuthResult) []string {
	out := make([]string, 0, len(res.Causes))
	for _, c := range res.Causes {
		out = append(out, c.Code)
	}
	return out
}

func hasCause(res KerioAuthResult, code string) bool {
	for _, c := range res.Causes {
		if c.Code == code {
			return true
		}
	}
	return false
}

func authCheckStatus(res KerioAuthResult, key string) string {
	for _, c := range res.Checks {
		if c.Key == key {
			return c.Status
		}
	}
	return ""
}

// --- успешный вход ---------------------------------------------------------

func TestKerioAuthSuccess(t *testing.T) {
	m := &mockKerio{user: "admin", password: "Secret123", isAdmin: true, role: "admin"}
	host, port := startMockKerio(t, m)

	res := CheckKerioAdminLogin(KerioLoginCheckRequest{
		Host: host, Port: port, User: "admin", Password: "Secret123", ProbeCerts: true,
	})

	if !res.OK {
		t.Fatalf("ожидался успешный вход, получено: %s (причины: %v)", res.Verdict, authCauseCodes(res))
	}
	if !strings.Contains(res.Verdict, "Вход выполнен") {
		t.Errorf("вердикт не сообщает об успехе: %q", res.Verdict)
	}
	if res.LoginUser != "admin" {
		t.Errorf("LoginUser = %q, ожидался admin", res.LoginUser)
	}
	if !res.IsAdmin || res.Role != "admin" {
		t.Errorf("роль/права не подтверждены: role=%q isAdmin=%v", res.Role, res.IsAdmin)
	}
	if res.Version != "9.4.1" || res.Product != "Kerio Connect" {
		t.Errorf("версия продукта: %q %q", res.Product, res.Version)
	}
	if !res.CertsChecked || !res.CanManageCerts || res.CertsCount != 1 {
		t.Errorf("права на сертификаты: checked=%v can=%v count=%d err=%q",
			res.CertsChecked, res.CanManageCerts, res.CertsCount, res.CertsError)
	}
	if !res.SessionOK || !res.CookieOK {
		t.Errorf("сессия: token=%v cookie=%v (%s)", res.SessionOK, res.CookieOK, res.SessionNote)
	}
	if authCheckStatus(res, "login") != "ok" {
		t.Errorf("шаг login = %q", authCheckStatus(res, "login"))
	}
	if len(res.Causes) != 0 {
		t.Errorf("при успехе не должно быть причин, получено: %v", authCauseCodes(res))
	}
	if res.Summary == "" {
		t.Error("пустое резюме для журнала")
	}
	if res.ElapsedMS <= 0 {
		t.Error("не измерено время проверки")
	}
}

// --- неверный пароль -------------------------------------------------------

func TestKerioAuthWrongPassword(t *testing.T) {
	m := &mockKerio{user: "admin", password: "Secret123", isAdmin: true, role: "admin"}
	host, port := startMockKerio(t, m)

	res := CheckKerioAdminLogin(KerioLoginCheckRequest{
		Host: host, Port: port, User: "admin", Password: "wrong", ProbeCerts: true,
	})

	if res.OK {
		t.Fatal("неверный пароль не должен давать успех")
	}
	if !strings.Contains(res.Verdict, "Не удалось войти") {
		t.Errorf("вердикт: %q", res.Verdict)
	}
	if !hasCause(res, "auth") {
		t.Errorf("нет причины auth: %v", authCauseCodes(res))
	}
	// Первая причина должна быть блокирующей и содержать шаги.
	var blocking *KerioAuthCause
	for i := range res.Causes {
		if res.Causes[i].Severity == "block" {
			blocking = &res.Causes[i]
			break
		}
	}
	if blocking == nil {
		t.Fatal("нет блокирующей причины")
	}
	if len(blocking.Steps) < 3 {
		t.Errorf("в причине %q мало шагов устранения: %d", blocking.Title, len(blocking.Steps))
	}
	if blocking.CheckWhere == "" {
		t.Errorf("в причине %q не указано, где проверить руками", blocking.Title)
	}
	if authCheckStatus(res, "login") != "fail" {
		t.Errorf("шаг login = %q, ожидался fail", authCheckStatus(res, "login"))
	}
	// Пароль не должен нигде появиться в результате.
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), "wrong") {
		t.Error("введённый пароль попал в результат проверки")
	}
}

// --- 2FA -------------------------------------------------------------------

func TestKerioAuthTwoFactor(t *testing.T) {
	m := &mockKerio{user: "admin", password: "Secret123", isAdmin: true, role: "admin", twoFactor: true}
	host, port := startMockKerio(t, m)

	res := CheckKerioAdminLogin(KerioLoginCheckRequest{Host: host, Port: port, User: "admin", Password: "Secret123"})
	if res.OK {
		t.Fatal("2FA не должна давать успех")
	}
	if !hasCause(res, "otp") {
		t.Fatalf("нет причины otp: %v", authCauseCodes(res))
	}
	for _, c := range res.Causes {
		if c.Code == "otp" {
			joined := strings.Join(c.Steps, " ")
			if !strings.Contains(joined, "без 2FA") && !strings.Contains(joined, "НЕ включайте") {
				t.Errorf("шаги для 2FA не предлагают учётку без 2FA: %v", c.Steps)
			}
		}
	}
}

// --- вошёл, но не администратор -------------------------------------------

func TestKerioAuthNotAdmin(t *testing.T) {
	m := &mockKerio{user: "info", password: "Secret123", isAdmin: false, role: "user"}
	host, port := startMockKerio(t, m)

	res := CheckKerioAdminLogin(KerioLoginCheckRequest{Host: host, Port: port, User: "info", Password: "Secret123"})
	if res.OK {
		t.Fatal("учётка без прав администратора не должна давать успех")
	}
	if !hasCause(res, "rights") {
		t.Fatalf("нет причины rights: %v", authCauseCodes(res))
	}
	if authCheckStatus(res, "rights") != "fail" {
		t.Errorf("шаг rights = %q", authCheckStatus(res, "rights"))
	}
	if !strings.Contains(res.Verdict, "прав") {
		t.Errorf("вердикт не упоминает права: %q", res.Verdict)
	}
}

// --- нет доступа к сертификатам -------------------------------------------

func TestKerioAuthNoCertAccess(t *testing.T) {
	m := &mockKerio{user: "admin", password: "Secret123", isAdmin: true, role: "admin", certError: true}
	host, port := startMockKerio(t, m)

	res := CheckKerioAdminLogin(KerioLoginCheckRequest{Host: host, Port: port, User: "admin", Password: "Secret123", ProbeCerts: true})
	if res.CanManageCerts {
		t.Error("доступ к сертификатам не должен подтверждаться при ошибке")
	}
	if !hasCause(res, "certs") {
		t.Fatalf("нет причины certs: %v", authCauseCodes(res))
	}
	if res.CertsError == "" {
		t.Error("не сохранён текст ошибки сертификатов")
	}
}

// --- локальные проверки до сети -------------------------------------------

func TestKerioAuthEmptyPassword(t *testing.T) {
	res := CheckKerioAdminLogin(KerioLoginCheckRequest{Host: "127.0.0.1", Port: 1, User: "admin"})
	if res.OK {
		t.Fatal("пустой пароль не должен давать успех")
	}
	if !hasCause(res, "empty-password") {
		t.Fatalf("нет причины empty-password: %v", authCauseCodes(res))
	}
	if authCheckStatus(res, "tcp") != "" {
		t.Error("при пустом пароле не нужно ходить по сети")
	}
}

func TestKerioAuthSpacesInPassword(t *testing.T) {
	// Пробел по краям: до сети дело не дойдёт, но причина должна быть.
	res := CheckKerioAdminLogin(KerioLoginCheckRequest{Host: "127.0.0.1", Port: 1, User: "admin", Password: " Secret123"})
	if !hasCause(res, "spaces-in-password") {
		t.Fatalf("нет причины spaces-in-password: %v", authCauseCodes(res))
	}
}

func TestKerioAuthEmailLoginHint(t *testing.T) {
	m := &mockKerio{user: "admin", password: "Secret123", isAdmin: true, role: "admin"}
	host, port := startMockKerio(t, m)

	res := CheckKerioAdminLogin(KerioLoginCheckRequest{
		Host: host, Port: port, User: "info@company.by", Password: "Secret123",
	})
	// Kerio не знает такую учётку — но программа обязана объяснить, что дело в формате логина.
	if !hasCause(res, "email-as-admin") {
		t.Fatalf("нет причины email-as-admin: %v", authCauseCodes(res))
	}
	// Должны быть видны варианты перебора: info@company.by и admin.
	if len(res.Attempts) == 0 {
		t.Fatal("нет списка попыток входа")
	}
	seenAdminFallback := false
	for _, a := range res.Attempts {
		if a.Login == "admin" && a.OK {
			seenAdminFallback = true
		}
	}
	if !seenAdminFallback {
		t.Errorf("программа не попробовала fallback на admin: %+v", res.Attempts)
	}
}

func TestKerioAuthNetworkFailure(t *testing.T) {
	// Свободный порт, на котором точно никто не слушает.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("не удалось занять порт")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	res := CheckKerioAdminLogin(KerioLoginCheckRequest{Host: "127.0.0.1", Port: port, User: "admin", Password: "x", ProbeCerts: true})
	if res.OK {
		t.Fatal("без сервера успех невозможен")
	}
	if !hasCause(res, "tcp") {
		t.Fatalf("нет причины tcp: %v", authCauseCodes(res))
	}
	if authCheckStatus(res, "tcp") != "fail" {
		t.Errorf("шаг tcp = %q", authCheckStatus(res, "tcp"))
	}
	for _, c := range res.Causes {
		if c.Code == "tcp" && len(c.Steps) < 3 {
			t.Errorf("мало шагов для причины tcp: %v", c.Steps)
		}
	}
}

// --- маскирование секретов -------------------------------------------------

func TestKerioAuthMasking(t *testing.T) {
	if got := maskToken("token-0123456789abcdef"); strings.Contains(got, "0123456789") {
		t.Errorf("токен не замаскирован: %q", got)
	}
	for _, pw := range []string{"", "x", "Secret123", "Пароль123"} {
		hint := maskPasswordHint(pw)
		if pw != "" && strings.Contains(hint, pw) {
			t.Errorf("подсказка о пароле раскрывает сам пароль: %q → %q", pw, hint)
		}
	}
	if hint := maskPasswordHint("Secret123"); !strings.Contains(hint, "9 симв") {
		t.Errorf("подсказка не сообщает длину пароля: %q", hint)
	}
	if !hasNonASCII("Пароль123") || hasNonASCII("Secret123") {
		t.Error("hasNonASCII работает неверно")
	}
	if !looksLikeEmail("info@company.by") || looksLikeEmail("admin") {
		t.Error("looksLikeEmail работает неверно")
	}
}

// --- HTML-ответ вместо JSON ------------------------------------------------

func TestKerioAuthHtmlInsteadOfJson(t *testing.T) {
	m := &mockKerio{user: "admin", password: "Secret123", isAdmin: true, role: "admin", htmlReply: true}
	host, port := startMockKerio(t, m)

	res := CheckKerioAdminLogin(KerioLoginCheckRequest{Host: host, Port: port, User: "admin", Password: "Secret123"})
	if res.OK {
		t.Fatal("HTML вместо JSON не может быть успешным входом")
	}
	codes := authCauseCodes(res)
	if !hasCause(res, "protocol") && !hasCause(res, "method") && !hasCause(res, "auth") {
		t.Fatalf("ожидалась причина протокола/метода, получено: %v", codes)
	}
	if len(res.Causes) == 0 || len(res.Causes[0].Steps) == 0 {
		t.Error("у причины нет шагов устранения")
	}
}

// --- полнота базы причин ---------------------------------------------------

func TestKerioAuthCauseKnowledgeBase(t *testing.T) {
	// Каждая причина, которую может вернуть классификатор ошибок Kerio,
	// должна иметь объяснение и хотя бы 3 шага — иначе «устранение причин»
	// превращается в пустую заглушку.
	codes := []string{"empty-password", "spaces-in-password", "email-as-admin", "non-ascii-password",
		"auth", "auth-common", "otp", "rights", "locked", "cookie", "certs", "wrong-product",
		"protocol", "dns", "tcp", "tls", "unknown"}
	seen := map[string]bool{}
	for _, code := range codes {
		c := kerioAuthCause(code)
		if c.Code == "" || c.Title == "" || c.Explanation == "" {
			t.Errorf("причина %q не заполнена: %+v", code, c)
		}
		if len(c.Steps) < 3 {
			t.Errorf("причина %q: шагов %d, нужно не меньше 3", code, len(c.Steps))
		}
		if c.Severity != "block" && c.Severity != "warn" {
			t.Errorf("причина %q: severity = %q", code, c.Severity)
		}
		if seen[c.Code] {
			t.Errorf("дубликат кода причины %q", c.Code)
		}
		seen[c.Code] = true
	}
}

// --- HTTP API --------------------------------------------------------------

func TestKerioLoginCheckEndpoint(t *testing.T) {
	m := &mockKerio{user: "admin", password: "Secret123", isAdmin: true, role: "admin"}
	host, port := startMockKerio(t, m)

	mux := buildRouter()
	body := fmt.Sprintf(`{"host":%q,"port":%d,"user":"admin","password":"Secret123","probeCerts":true}`, host, port)
	req := httptest.NewRequest(http.MethodPost, "/api/kerio/login-check", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OK   bool            `json:"ok"`
		Auth KerioAuthResult `json:"auth"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ не разобрался: %v (%s)", err, rec.Body.String())
	}
	if !resp.OK || !resp.Auth.OK {
		t.Fatalf("ожидался успешный вход: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Secret123") {
		t.Error("пароль попал в ответ API")
	}

	// GET должен отклоняться.
	req2 := httptest.NewRequest(http.MethodGet, "/api/kerio/login-check", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/kerio/login-check → HTTP %d, ожидался 405", rec2.Code)
	}
}

// TestKerioAuthCauseAliases — типы ошибок из classifyKerioMessage/transportError
// должны находить свою причину, а не проваливаться в «неизвестно».
func TestKerioAuthCauseAliases(t *testing.T) {
	cases := map[string]string{
		"method":     "protocol", // «method not found» = не тот продукт/версия API
		"protocol":   "protocol",
		"auth":       "auth",
		"otp":        "otp",
		"rights":     "rights",
		"locked":     "locked",
		"dns":        "dns",
		"tcp":        "tcp",
		"tls":        "tls",
		"":           "unknown",
		"rpc-что-то": "unknown",
	}
	for kind, wantCode := range cases {
		if got := kerioAuthCause(kind).Code; got != wantCode {
			t.Errorf("kerioAuthCause(%q).Code = %q, ожидался %q", kind, got, wantCode)
		}
	}
}

// TestUIKerioAuthCard — карточка «Вход под администратором Kerio Connect»
// должна присутствовать в разметке, быть связанной с обработчиками и API,
// а пароль из неё не должен попадать в сохраняемые настройки.
func TestUIKerioAuthCard(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")

	for _, want := range []string{
		`id="kerioAuthCard"`,
		`Вход под администратором Kerio Connect`,
		`id="kerioAuthHost"`,
		`id="kerioAuthPort"`,
		`id="kerioAuthUser"`,
		`id="kerioAuthPass"`,
		`id="kerioAuthProbeCerts"`,
		`id="kerioAuthCheckBtn"`,
		`id="kerioAuthWebAdminBtn"`,
		`id="kerioAuthReportBtn"`,
		`id="kerioAuthResult"`,
		`function checkKerioAdminLogin(`,
		`function renderKerioAuthResult(`,
		`function kerioAuthReportText(`,
		`function copyKerioAuthReport(`,
		`/api/kerio/login-check`,
		`Причина и как устранить`,
		`Где проверить:`,
		`Попытки входа`,
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui/index.html: нет %q — карточка входа развалилась", want)
		}
	}

	// Пароль карточки не должен уезжать в сохранение настроек.
	saveStart := strings.Index(ui, "function saveCurrentUiSettingsQuiet()")
	if saveStart < 0 {
		t.Fatal("не найдена saveCurrentUiSettingsQuiet")
	}
	saveEnd := strings.Index(ui[saveStart:], "}, 650);")
	if saveEnd < 0 {
		t.Fatal("не найден конец saveCurrentUiSettingsQuiet")
	}
	saveBody := ui[saveStart : saveStart+saveEnd]
	if strings.Contains(saveBody, "kerioAuth") {
		t.Error("настройки сохраняют поля карточки входа — пароль администратора не должен попадать в файл")
	}

	// Ссылка «Как это работает» обязана вести на существующий раздел FAQ.
	anchors := map[string]bool{}
	for _, h := range HelpDocument().Headings {
		anchors[h.Anchor] = true
	}
	const faqAnchor = "46-вход-под-администратором-kerio-connect--проверка-и-разбор-ошибок"
	if !strings.Contains(ui, "openHelpSection('"+faqAnchor+"')") {
		t.Errorf("нет ссылки на раздел инструкции %q", faqAnchor)
	}
	if !anchors[faqAnchor] {
		t.Errorf("в FAQ нет раздела 4.6 (якорь %q)", faqAnchor)
	}
}
