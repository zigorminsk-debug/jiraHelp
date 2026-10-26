package main

// v491_test.go — регрессии версии 4.9.1.
//
// Два независимых блока:
//  1. Установка сертификата в Kerio Connect 10.0.0. На этом сервере SSL-раздел
//     в веб-админке открывается, учётка Admin имеет полные права, но импорт
//     через старый интерфейс ConnectCertificate.* не проходит. Поэтому здесь
//     поднимается «фальшивый Kerio 10» с современным интерфейсом Certificates.*
//     и проверяется, что установка идёт через него, а не падает.
//  2. Диагностика не имеет права называть разницу версий «отсутствием прав»:
//     ошибки method/protocol не должны давать красный вердикт «нет прав на SSL».

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeKerio10 — минимальный сервер Kerio Connect 10 для проверки установки.
// Поддерживает только те методы, которые программа реально вызывает.
type fakeKerio10 struct {
	t      *testing.T
	mu     sync.Mutex
	mode   string // "modern" — только Certificates.*, "legacy" — только ConnectCertificate.*
	calls  []string
	params map[string]map[string]any

	imported    bool
	certID      string
	activatedID string
	fingerprint string
}

func (f *fakeKerio10) record(method string, raw json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method)
	if len(raw) > 0 {
		var p map[string]any
		if json.Unmarshal(raw, &p) == nil {
			if f.params == nil {
				f.params = map[string]map[string]any{}
			}
			f.params[method] = p
		}
	}
}

func (f *fakeKerio10) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == method {
			n++
		}
	}
	return n
}

func (f *fakeKerio10) certListResult() string {
	f.mu.Lock()
	imported, fp := f.imported, f.fingerprint
	f.mu.Unlock()
	if !imported {
		return `{"certificates":[{"id":"cert-old","name":"Default","type":"InactiveCertificate"}]}`
	}
	return fmt.Sprintf(`{"certificates":[{"id":"cert-old","name":"Default","type":"InactiveCertificate"},`+
		`{"id":"cert-new","name":"mail.example.com","type":"ActiveCertificate","fingerprintSha256":%q,`+
		`"validPeriod":{"validToDate":"2027-01-01"}}]}`, fp)
}

func (f *fakeKerio10) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json-rpc")
	if strings.HasSuffix(r.URL.Path, "/upload/") {
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"fileUpload":{"id":"upload-1"}}}`)
		return
	}
	var req struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		f.t.Errorf("некорректный JSON-RPC запрос: %v", err)
		return
	}
	f.record(req.Method, req.Params)

	ok := func(result string) {
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":`+result+`}`)
	}
	methodMissing := func() {
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`)
	}
	f.mu.Lock()
	modern := f.mode == "modern"
	f.mu.Unlock()

	switch req.Method {
	case "Session.login":
		ok(`{"token":"token-0123456789abcdef"}`)
	case "Session.logout":
		ok(`{}`)
	case "Session.whoAmI":
		ok(`{"userDetails":{"loginName":"Admin","isAdmin":true,"effectiveRole":{"userRole":"BuiltinAdmin"}}}`)
	case "Version.getProductVersion":
		ok(`{"productVersion":{"productName":"Kerio Connect","major":10,"minor":0,"revision":0,"displayNumber":"10.0.0"}}`)
	case "Version.getApiVersion":
		ok(`{"apiVersion":8}`)

	case "Certificates.get":
		if !modern {
			methodMissing()
			return
		}
		ok(f.certListResult())
	case "ConnectCertificate.get":
		if modern {
			methodMissing()
			return
		}
		ok(f.certListResult())

	case "Certificates.importPrivateKey":
		if !modern {
			methodMissing()
			return
		}
		ok(`{"keyId":"key-1","needPassword":false}`)
	case "Certificates.importCertificate":
		if !modern {
			methodMissing()
			return
		}
		f.mu.Lock()
		f.imported = true
		f.certID = "cert-new"
		f.mu.Unlock()
		ok(`{"id":"cert-new"}`)
	case "Certificates.setActive":
		if !modern {
			methodMissing()
			return
		}
		f.mu.Lock()
		f.activatedID = "cert-new"
		f.mu.Unlock()
		ok(`{}`)

	case "ConnectCertificate.importPrivateKey":
		if modern {
			methodMissing()
			return
		}
		ok(`{"needPassword":false,"id":"tmp-key"}`)
	case "ConnectCertificate.importCertificate":
		if modern {
			methodMissing()
			return
		}
		f.mu.Lock()
		f.imported = true
		f.certID = "cert-new"
		f.mu.Unlock()
		ok(`{}`)
	case "ConnectCertificate.setActive":
		if modern {
			methodMissing()
			return
		}
		var p struct {
			Id string `json:"id"`
		}
		_ = json.Unmarshal(req.Params, &p)
		f.mu.Lock()
		f.activatedID = p.Id
		f.mu.Unlock()
		ok(`{}`)

	default:
		f.t.Errorf("неожиданный метод JSON-RPC: %s", req.Method)
		methodMissing()
	}
}

// newFakeKerio10 поднимает TLS-сервер (как настоящая админка Kerio).
func newFakeKerio10(t *testing.T, mode, fingerprint string) (*fakeKerio10, string, int) {
	t.Helper()
	f := &fakeKerio10{t: t, mode: mode, fingerprint: fingerprint}
	srv := httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("не разобрать адрес тестового сервера: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("не разобрать порт тестового сервера: %v", err)
	}
	return f, host, port
}

// testCertRecord создаёт минимальную запись о сертификате с реальными файлами.
func testCertRecord(t *testing.T, fingerprint string) *IssuedCertRecord {
	t.Helper()
	dir := t.TempDir()
	crt := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")
	leaf := filepath.Join(dir, "cert-only.crt")
	body := "-----BEGIN CERTIFICATE-----\nMIIBdkdU1NTi\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(crt, []byte(body), 0o600); err != nil {
		t.Fatalf("не записать сертификат: %v", err)
	}
	if err := os.WriteFile(leaf, []byte(body), 0o600); err != nil {
		t.Fatalf("не записать листовой сертификат: %v", err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatalf("не записать ключ: %v", err)
	}
	return &IssuedCertRecord{
		ID:                "rec-1",
		Slug:              "mail-example-com",
		PrimaryDomain:     "mail.example.com",
		DNSNames:          []string{"mail.example.com"},
		SHA256Fingerprint: fingerprint,
		Files: map[string]string{
			"serverCrt": crt,
			"serverKey": key,
			"certOnly":  leaf,
		},
	}
}

// TestInstallViaCertificatesInterfaceKerio10 — главный сценарий жалобы
// «раздел SSL открывается, права есть, а добавление сертификата с ошибкой».
func TestInstallViaCertificatesInterfaceKerio10(t *testing.T) {
	const fp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
	f, host, port := newFakeKerio10(t, "modern", fp)
	rec := testCertRecord(t, fp)

	note, err := InstallCertificateToKerio(rec, KerioInstallConfig{
		Enabled:     true,
		Method:      "api",
		APIHost:     host,
		APIPort:     port,
		APIUser:     "Admin",
		APIPassword: "secret",
	}, func(string, string) {})
	if err != nil {
		t.Fatalf("установка через Certificates.* не должна падать: %v", err)
	}
	if !strings.Contains(note, "Certificates.setActive") {
		t.Errorf("ожидалась активация через Certificates.setActive, получено: %s", note)
	}
	if !strings.Contains(note, "Kerio подтвердил активный сертификат") {
		t.Errorf("нет проверки результата установки: %s", note)
	}
	if f.count("Certificates.importPrivateKey") != 1 || f.count("Certificates.importCertificate") != 1 {
		t.Fatalf("импорт должен пройти один раз через Certificates.*: %+v", f.calls)
	}
	if f.count("ConnectCertificate.importPrivateKey") != 0 {
		t.Errorf("старый интерфейс не должен вызываться, если новый работает: %+v", f.calls)
	}
	f.mu.Lock()
	params := f.params["Certificates.importCertificate"]
	active := f.activatedID
	f.mu.Unlock()
	if params["type"] != "InactiveCertificate" {
		t.Errorf("Certificates.importCertificate должен получать type=InactiveCertificate, получено %v", params)
	}
	if params["name"] != "mail.example.com" {
		t.Errorf("сертификат должен получать имя домена, получено %v", params["name"])
	}
	if active != "cert-new" {
		t.Errorf("активирован не тот сертификат: %q", active)
	}
}

// TestInstallViaLegacyInterfaceStillWorks — Kerio Connect 8.5–9.1: современного
// интерфейса нет, должен сработать старый. Иначе мы «починим» 10-ку и сломаем
// парк старых серверов.
func TestInstallViaLegacyInterfaceStillWorks(t *testing.T) {
	const fp = "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF"
	f, host, port := newFakeKerio10(t, "legacy", fp)
	rec := testCertRecord(t, fp)

	note, err := InstallCertificateToKerio(rec, KerioInstallConfig{
		Enabled:     true,
		Method:      "api",
		APIHost:     host,
		APIPort:     port,
		APIUser:     "admin",
		APIPassword: "secret",
	}, func(string, string) {})
	if err != nil {
		t.Fatalf("установка через ConnectCertificate.* не должна падать: %v", err)
	}
	if !strings.Contains(note, "ConnectCertificate.setActive") {
		t.Errorf("ожидалась активация через ConnectCertificate.setActive: %s", note)
	}
	if f.count("ConnectCertificate.importCertificate") != 1 {
		t.Fatalf("старый интерфейс импорта должен быть вызван ровно один раз: %+v", f.calls)
	}
}

// TestCertProbeNotRights — если ни один интерфейс не ответил, но Kerio не
// сказал «нет прав», диагностика обязана сообщить о версии API, а не о правах.
func TestCertProbeNotRights(t *testing.T) {
	attempts := []kerioCertAttempt{
		{Iface: "Certificates", Method: "Certificates.get", Err: kerioErr("method", "Certificates.get", "Method not found", "")},
		{Iface: "ConnectCertificate", Method: "ConnectCertificate.get", Err: kerioErr("protocol", "ConnectCertificate.get", "Invalid params", "")},
	}
	err := combineCertAttemptsError(attempts)
	if kind := kerioErrKind(err); kind == "rights" || kind == "auth" || kind == "locked" {
		t.Fatalf("разница версий API не должна выдаваться за отказ в правах, kind=%q: %s", kind, err.Error())
	}
	if kind := kerioErrKind(err); kind != "method" {
		t.Fatalf("ожидался kind=method, получено %q", kind)
	}
	for _, want := range []string{"Certificates.get", "ConnectCertificate.get", "НЕ отказ в правах"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в тексте ошибки нет %q: %s", want, err.Error())
		}
	}
}

// TestCertProbeKeepsRealRightsError — настоящий отказ (1004/access denied)
// по-прежнему должен считаться отказом в правах, иначе мы скроем реальную
// проблему учётной записи.
func TestCertProbeKeepsRealRightsError(t *testing.T) {
	attempts := []kerioCertAttempt{
		{Iface: "Certificates", Method: "Certificates.get", Err: kerioErr("rights", "Certificates.get", "Access denied", "")},
		{Iface: "ConnectCertificate", Method: "ConnectCertificate.get", Err: kerioErr("method", "ConnectCertificate.get", "Method not found", "")},
	}
	err := combineCertAttemptsError(attempts)
	if kind := kerioErrKind(err); kind != "rights" {
		t.Fatalf("настоящий отказ в правах должен сохраняться, получено kind=%q", kind)
	}
}

func TestCertRightsDeniedKinds(t *testing.T) {
	cases := map[string]bool{
		"rights":   true,
		"auth":     true,
		"locked":   true,
		"method":   false,
		"protocol": false,
		"http":     false,
		"tcp":      false,
		"":         false,
	}
	for kind, want := range cases {
		if got := certRightsDenied(kerioErr(kind, "Certificates.get", "x", "")); got != want {
			t.Errorf("certRightsDenied(%q) = %v, ожидалось %v", kind, got, want)
		}
	}
}

// TestAuthVerdictCertAPIMismatchIsNotRights — карточка «Проверить вход» больше
// не пишет «прав не хватает», когда сервер просто ответил другой формой API.
func TestAuthVerdictCertAPIMismatchIsNotRights(t *testing.T) {
	r := &KerioAuthResult{
		Host: "10.146.100.14", Port: 4040,
		LoginUser: "Admin", Role: "BuiltinAdmin", IsAdmin: true,
		Product: "Kerio Connect", Version: "10.0.0",
		CertsChecked: true, CertsAPIAvailable: false,
		CertsErrorKind: "method",
		CertsError:     "Ни один из интерфейсов сертификатов Kerio не ответил как ожидалось",
	}
	r.step("login", "Вход администратора (Session.login)", "ok", "ok", "")
	r.step("rights", "Права администратора", "ok", "роль BuiltinAdmin", "")
	r.step("certs", "API сертификатов Kerio (Certificates)", "warn", r.CertsError, "")
	r.OK = true
	r.finalize(time.Now())

	if !r.OK {
		t.Fatalf("вердикт не должен быть провальным: %q", r.Verdict)
	}
	if strings.Contains(r.Verdict, "не хватает") {
		t.Fatalf("ложное «нет прав» вернулось: %q", r.Verdict)
	}
	if !strings.Contains(r.Verdict, "Права подтверждены") {
		t.Fatalf("в вердикте нет подтверждения прав: %q", r.Verdict)
	}
}

// TestAuthVerdictRealRightsFailure — а вот явный отказ Kerio должен остаться
// красным вердиктом с планом устранения.
func TestAuthVerdictRealRightsFailure(t *testing.T) {
	r := &KerioAuthResult{Host: "h", Port: 4040, LoginUser: "info", Role: "user"}
	r.step("login", "Вход администратора (Session.login)", "ok", "ok", "")
	r.step("rights", "Права администратора", "fail", "роль не административная", "")
	r.cause(kerioAuthCause("rights"))
	r.OK = false
	r.finalize(time.Now())
	if r.OK {
		t.Fatal("отказ в правах не должен давать зелёный вердикт")
	}
	if len(r.Causes) == 0 || r.Causes[0].Severity != "block" {
		t.Fatalf("ожидалась блокирующая причина, получено %+v", r.Causes)
	}
}

func TestParseKerioCertList(t *testing.T) {
	raw := json.RawMessage(`{"certificates":[{"id":"c1","name":"mail.example.com",` +
		`"subjectHostNames":["mail.example.com"],"type":"ActiveCertificate",` +
		`"fingerprint":"AA:BB","fingerprintSha256":"AA:BB:CC",` +
		`"validPeriod":{"validFromDate":"2026-01-01","validToDate":"2027-01-01"}}]}`)
	certs, ok := parseKerioCertList(raw)
	if !ok || len(certs) != 1 {
		t.Fatalf("список не разобран: ok=%v certs=%+v", ok, certs)
	}
	c := certs[0]
	if c.Fingerprint != "AA:BB:CC" {
		t.Errorf("ожидался SHA-256 отпечаток, получено %q", c.Fingerprint)
	}
	if !c.Active {
		t.Error("сертификат с type=ActiveCertificate должен считаться активным")
	}
	if c.ValidTo != "2027-01-01" || len(c.HostNames) != 1 {
		t.Errorf("поля сертификата потерялись: %+v", c)
	}

	if _, ok := parseKerioCertList(json.RawMessage(`{"error":"x"}`)); ok {
		t.Error("объект без поля certificates не должен считаться списком")
	}
	empty, ok := parseKerioCertList(json.RawMessage(`{"certificates":[],"totalItems":0}`))
	if !ok || len(empty) != 0 {
		t.Errorf("пустой список — это успех (0 сертификатов), получено ok=%v len=%d", ok, len(empty))
	}
}

func TestKerioCertListCandidatesCoverBothInterfaces(t *testing.T) {
	var haveModern, haveLegacy bool
	for _, c := range kerioCertListCandidates() {
		switch c.Iface {
		case "Certificates":
			haveModern = true
			if c.Method != "Certificates.get" {
				t.Errorf("у Certificates ожидался метод get, получено %q", c.Method)
			}
		case "ConnectCertificate":
			haveLegacy = true
			if c.Method != "ConnectCertificate.get" {
				t.Errorf("у ConnectCertificate ожидался метод get, получено %q", c.Method)
			}
		default:
			t.Errorf("неизвестный интерфейс %q", c.Iface)
		}
		if c.Note == "" {
			t.Errorf("у варианта %s нет пояснения для интерфейса", c.Method)
		}
	}
	if !haveModern || !haveLegacy {
		t.Fatalf("должны проверяться оба интерфейса: modern=%v legacy=%v", haveModern, haveLegacy)
	}
}

// TestCertProbeEndpointAndUI — кнопка «Проверить API сертификатов» должна быть
// в интерфейсе и на сервере, иначе совет «пришлите отчёт» невыполним.
func TestCertProbeEndpointAndUI(t *testing.T) {
	mainSrc := readRepoFile(t, "main.go")
	for _, want := range []string{"/api/kerio/cert-probe", "ProbeKerioCertificateAPI"} {
		if !strings.Contains(mainSrc, want) {
			t.Errorf("main.go: нет %q", want)
		}
	}
	ui := readRepoFile(t, "ui/index.html")
	for _, want := range []string{`id="kerioCertProbeBtn"`, "/api/kerio/cert-probe", "kerioCertProbeLast", "Скопировать отчёт по API"} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui/index.html: нет %q", want)
		}
	}
}

// TestServiceRestartButtonWired — кнопка «Перезапустить службу» должна быть
// не только нарисована, но и подключена к обработчику: в 4.9.1 разметка была,
// а клик ничего не делал.
func TestServiceRestartButtonWired(t *testing.T) {
	ui := readRepoFile(t, "ui/index.html")
	if !strings.Contains(ui, `id="kerioRestartServiceBtn"`) {
		t.Fatal("ui/index.html: нет кнопки kerioRestartServiceBtn")
	}
	if !strings.Contains(ui, "controlKerioService('restart')") {
		t.Error("ui/index.html: клик по кнопке службы не подключён к controlKerioService")
	}
	if !strings.Contains(ui, "/api/kerio/service") {
		t.Error("ui/index.html: кнопка службы не обращается к /api/kerio/service")
	}
	mainSrc := readRepoFile(t, "main.go")
	for _, want := range []string{"/api/kerio/service", "PlatformControlKerioService", "PlatformKerioServiceName"} {
		if !strings.Contains(mainSrc, want) {
			t.Errorf("main.go: нет %q", want)
		}
	}
}
