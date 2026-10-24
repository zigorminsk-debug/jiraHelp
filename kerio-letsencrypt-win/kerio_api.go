package main

// ============================================================================
// KERIO CONNECT ADMIN API CLIENT + CONNECTION DIAGNOSTICS (v4.3)
//
// Реализует официальный протокол Kerio Connect Admin JSON-RPC 2.0
// (https://<host>:4040/admin/api/jsonrpc/) с точностью до деталей, которые
// описаны в документации GFI и в официальной библиотеке
// "Kerio APIs Client Library for PHP" 1.4.0.234:
//   * Session.login -> result.token + Set-Cookie SESSION_CONNECT_WEBADMIN;
//   * каждый следующий вызов обязан содержать и cookie, и заголовок X-Token;
//   * Content-Type / Accept = application/json-rpc; charset=UTF-8;
//   * загрузка файла — POST /admin/api/jsonrpc/upload/ с multipart-частью
//     name="unknown"; filename="newFile.bin"  (именно так, а НЕ name="newFile.bin");
//   * ответ загрузки: {"result":{"fileUpload":{"id":"..."}}}.
// ============================================================================

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	kerioAdminPort      = 4040
	kerioAdminPath      = "/admin/api/jsonrpc/"
	kerioUploadPath     = "/admin/api/jsonrpc/upload/"
	kerioClientUserAgent = "KerioCertManager/4.3 (Windows)"
)

// KerioEndpoint — адрес административного JSON-RPC интерфейса Kerio Connect.
type KerioEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (e KerioEndpoint) HostPort() string {
	port := e.Port
	if port <= 0 {
		port = kerioAdminPort
	}
	return net.JoinHostPort(e.Host, strconv.Itoa(port))
}

func (e KerioEndpoint) BaseURL() string  { return "https://" + e.HostPort() }
func (e KerioEndpoint) RPCURL() string   { return e.BaseURL() + kerioAdminPath }
func (e KerioEndpoint) UploadURL() string { return e.BaseURL() + kerioUploadPath }

// NormalizeKerioHost приводит пользовательский ввод к паре host/port.
// Понимает "https://10.0.0.5:4040/admin", "mail.leend.by", "127.0.0.1".
func NormalizeKerioHost(raw string, defPort int) (string, int) {
	port := defPort
	if port <= 0 {
		port = kerioAdminPort
	}
	s := strings.TrimSpace(raw)
	if s == "" {
		return "127.0.0.1", port
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "https://") {
		s = s[len("https://"):]
	} else if strings.HasPrefix(lower, "http://") {
		s = s[len("http://"):]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		if n, cerr := strconv.Atoi(p); cerr == nil && n > 0 && n < 65536 {
			port = n
		}
		s = h
	}
	s = strings.Trim(strings.TrimSpace(s), "[]")
	if s == "" {
		s = "127.0.0.1"
	}
	return s, port
}

// ---------------------------------------------------------------------------
// Ошибки
// ---------------------------------------------------------------------------

// KerioAPIError — типизированная ошибка с готовым русским объяснением и
// пошаговым исправлением. Kind: dns|tcp|tls|http|protocol|rpc|auth|rights|otp|locked|method
type KerioAPIError struct {
	Kind    string
	Method  string
	Code    int
	Message string
	Fix     string
	Raw     string
}

func (e *KerioAPIError) Error() string { return e.Message }

func kerioErr(kind, method, msg, fix string) *KerioAPIError {
	return &KerioAPIError{Kind: kind, Method: method, Message: msg, Fix: fix}
}

func kerioErrKind(err error) string {
	var ke *KerioAPIError
	if errors.As(err, &ke) {
		return ke.Kind
	}
	return ""
}

func kerioErrFix(err error) string {
	var ke *KerioAPIError
	if errors.As(err, &ke) {
		return ke.Fix
	}
	return ""
}

// ---------------------------------------------------------------------------
// HTTP-транспорт
// ---------------------------------------------------------------------------

func kerioHTTPClient(timeout time.Duration) *http.Client {
	var jar cookiejar.Jar
	if j, err := cookiejar.New(nil); err == nil {
		jar = *j
	}
	transport := &http.Transport{
		// Никаких прокси: админка Kerio почти всегда во внутренней сети.
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // самоподписанный сертификат Kerio — норма
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		},
		DialContext:       (&net.Dialer{Timeout: 6 * time.Second, KeepAlive: 0}).DialContext,
		DisableKeepAlives: true, // Kerio отдаёт "Connection: close" — не переиспользуем сокеты
		ForceAttemptHTTP2: false,
		// Jetty в старых сборках Kerio нестабильно работает с HTTP/2
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return &http.Client{
		Transport: transport,
		Jar:       &jar,
		Timeout:   timeout,
		// Не идём по редиректам: Kerio отправляет 302 на страницу логина,
		// и Go иначе превратит POST в GET и вернёт HTML вместо JSON.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type kerioRawResponse struct {
	Status      int
	Server      string
	Location    string
	ContentType string
	Body        []byte
}

// KerioClient — состояние одной сессии администратора Kerio Connect.
type KerioClient struct {
	Endpoint KerioEndpoint
	Token    string
	User     string
	Seq      int
	Log      LogFunc
	client   *http.Client
}

func NewKerioClient(ep KerioEndpoint) *KerioClient {
	if ep.Port <= 0 {
		ep.Port = kerioAdminPort
	}
	ep.Host = strings.TrimSpace(ep.Host)
	if ep.Host == "" {
		ep.Host = "127.0.0.1"
	}
	return &KerioClient{Endpoint: ep, client: kerioHTTPClient(30 * time.Second)}
}

func (c *KerioClient) logf(level, msg string) {
	if c.Log != nil {
		c.Log(level, msg)
	}
}

func (c *KerioClient) do(method, url, contentType string, body []byte, extra map[string]string) (*kerioRawResponse, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, kerioErr("protocol", "", "не удалось собрать HTTP-запрос: "+err.Error(), "")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json-rpc, application/json")
	req.Header.Set("User-Agent", kerioClientUserAgent)
	req.Header.Set("Connection", "close")
	if c.Token != "" {
		req.Header.Set("X-Token", c.Token)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	req.Close = true

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, c.transportError(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return &kerioRawResponse{
		Status:      resp.StatusCode,
		Server:      resp.Header.Get("Server"),
		Location:    resp.Header.Get("Location"),
		ContentType: resp.Header.Get("Content-Type"),
		Body:        data,
	}, nil
}

func (c *KerioClient) transportError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return kerioErr("tcp", "", fmt.Sprintf("таймаут подключения к %s. Хост не отвечает.", c.Endpoint.HostPort()),
			"1) Проверьте, что с этого компьютера открывается https://"+c.Endpoint.HostPort()+"/admin/ в браузере.\n"+
				"2) Если вы вне офиса — сначала подключите VPN (порт 4040 НЕ публикуется в интернет).\n"+
				"3) Проверьте Windows Firewall на сервере Kerio и правило NAT/маршрут до внутренней сети.\n"+
				"4) Укажите внутренний IP сервера Kerio, например 10.x.x.x, а не внешний домен.")
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return kerioErr("dns", "", fmt.Sprintf("DNS не может разрешить имя \"%s\" (%s).", c.Endpoint.Host, dnsErr.Err),
			"1) Проверьте имя на опечатки.\n"+
				"2) Укажите IP-адрес сервера Kerio вместо имени — это исключает проблемы Split-DNS.\n"+
				"3) Если используется внутренний домен, убедитесь, что он резолвится через внутренний DNS/VPN.")
	}
	low := strings.ToLower(err.Error())
	switch {
	case strings.Contains(low, "connection refused"):
		return kerioErr("tcp", "", fmt.Sprintf("Порт %d на %s закрыт: сервер активно отклонил подключение.", c.Endpoint.Port, c.Endpoint.Host),
			"1) Служба Kerio Connect (KerioMailServer) остановлена — запустите её (services.msc).\n"+
				"2) Админка Kerio слушает другой порт — посмотрите его в Kerio Connect: Configuration → Services → Web Administration (обычно 4040).\n"+
				"3) Порт 4040 заблокирован Windows Firewall на сервере — разрешите входящие TCP 4040 из вашей подсети.\n"+
				"4) Вы указали не тот сервер — уточните IP у администратора Kerio.")
	case strings.Contains(low, "no route to host"), strings.Contains(low, "network is unreachable"):
		return kerioErr("tcp", "", fmt.Sprintf("Нет маршрута до %s — сеть недоступна.", c.Endpoint.Host),
			"1) Подключите VPN к офисной сети.\n2) Проверьте, что компьютер находится в той же подсети, что и сервер Kerio.")
	case strings.Contains(low, "certificate"), strings.Contains(low, "x509"):
		return kerioErr("tls", "", "Ошибка TLS-сертификата Kerio: "+err.Error(),
			"Откройте https://"+c.Endpoint.HostPort()+"/admin/ в браузере и примите сертификат Kerio Connect.")
	case strings.Contains(low, "tls"), strings.Contains(low, "handshake"), strings.Contains(low, "protocol version"):
		return kerioErr("tls", "", "TLS-рукопожатие с Kerio не удалось: "+err.Error(),
			"1) В Kerio Connect включите TLS 1.2 (Configuration → SSL Certificates / Services → HTTPS).\n"+
				"2) Проверьте, что на порту 4040 именно Kerio Connect, а не прокси/антивирус.\n"+
				"3) Отключите SSL-инспекцию в антивирусе/файрволе для внутренней сети.")
	case strings.Contains(low, "eof"):
		return kerioErr("protocol", "", "Kerio закрыл соединение без ответа (EOF).",
			"1) Скорее всего порт 4040 обслуживает не Kerio Connect (прокси, балансировщик, Kerio Control).\n"+
				"2) Проверьте адрес https://"+c.Endpoint.HostPort()+"/admin/ в браузере.\n"+
				"3) Отключите перехват TLS антивирусом.")
	}
	return kerioErr("tcp", "", fmt.Sprintf("не удалось подключиться к %s: %v", c.Endpoint.HostPort(), err),
		"Проверьте адрес, порт и доступность сервера Kerio из этой сети.")
}

func (c *KerioClient) httpStatusError(method string, r *kerioRawResponse) error {
	snippet := truncateText(string(r.Body), 220)
	switch r.Status {
	case http.StatusUnauthorized:
		return &KerioAPIError{Kind: "auth", Method: method, Code: r.Status,
			Message: fmt.Sprintf("HTTP 401 Unauthorized от Kerio (%s).", c.Endpoint.HostPort()),
			Fix:     "Kerio требует авторизацию. Проверьте логин/пароль администратора Kerio Connect (не пользователя домена).",
			Raw:     snippet}
	case http.StatusForbidden:
		return &KerioAPIError{Kind: "rights", Method: method, Code: r.Status,
			Message: "HTTP 403 Forbidden: Kerio отклонил запрос.",
			Fix:     "1) Учётка не является администратором Kerio Connect.\n2) Kerio ограничивает доступ к админке по IP — добавьте IP этого компьютера в разрешённые.",
			Raw:     snippet}
	case http.StatusNotFound:
		return &KerioAPIError{Kind: "protocol", Method: method, Code: r.Status,
			Message: "HTTP 404 Not Found: по адресу " + c.Endpoint.RPCURL() + " нет JSON-RPC API Kerio.",
			Fix:     "1) Порт занят другим продуктом — это может быть Kerio Control (порт 4081), а не Kerio Connect.\n2) Проверьте, что адрес заканчивается на /admin/api/jsonrpc/ с косой чертой в конце.",
			Raw:     snippet}
	case http.StatusMethodNotAllowed:
		return &KerioAPIError{Kind: "protocol", Method: method, Code: r.Status, Message: "HTTP 405 Method Not Allowed.", Raw: snippet,
			Fix: "По этому адресу работает не Kerio Connect Admin API. Проверьте порт (Kerio Connect — 4040, Kerio Control — 4081)."}
	}
	return &KerioAPIError{Kind: "http", Method: method, Code: r.Status,
		Message: fmt.Sprintf("Kerio вернул HTTP %d.", r.Status),
		Fix:     "Проверьте журнал ошибок на сервере Kerio Connect и повторите попытку.",
		Raw:     snippet}
}

func truncateText(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r", " "))
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------------------------------------------------------------------------
// JSON-RPC
// ---------------------------------------------------------------------------

func (c *KerioClient) rpc(method string, params any) (json.RawMessage, error) {
	c.Seq++
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      c.Seq,
		"method":  method,
	}
	if params != nil {
		payload["params"] = params
	}
	if c.Token != "" {
		payload["token"] = c.Token
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, kerioErr("protocol", method, "не удалось сериализовать JSON-RPC запрос: "+err.Error(), "")
	}

	resp, err := c.do(http.MethodPost, c.Endpoint.RPCURL(), "application/json-rpc; charset=UTF-8", body, nil)
	if err != nil {
		var ke *KerioAPIError
		if errors.As(err, &ke) && ke.Method == "" {
			ke.Method = method
		}
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, c.httpStatusError(method, resp)
	}

	trimmed := bytes.TrimSpace(resp.Body)
	if len(trimmed) == 0 {
		return nil, &KerioAPIError{Kind: "protocol", Method: method,
			Message: fmt.Sprintf("Kerio вернул пустой ответ на %s.", method),
			Fix:     "Обычно это неверный адрес API (нужен /admin/api/jsonrpc/) или запрос перехвачен прокси/антивирусом."}
	}
	if trimmed[0] == '<' {
		hint := "Kerio вернул HTML-страницу вместо JSON — подключение попало на страницу входа, а не в Admin API."
		if resp.Location != "" {
			hint += " Редирект: " + resp.Location
		}
		return nil, &KerioAPIError{Kind: "protocol", Method: method, Message: hint,
			Fix: "1) Порт/адрес админки указан неверно: нужен https://<host>:4040/admin/api/jsonrpc/ (косая черта в конце обязательна).\n" +
				"2) Если это Kerio Control — у него порт 4081 и другой набор методов.\n" +
				"3) Если перед Kerio стоит reverse-proxy — проверьте, что он пропускает POST /admin/api/jsonrpc/ без редиректа.",
			Raw: truncateText(string(trimmed), 240)}
	}

	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, &KerioAPIError{Kind: "protocol", Method: method,
			Message: fmt.Sprintf("Ответ Kerio не является корректным JSON-RPC (%s): %v", method, err),
			Fix:     "Скорее всего на порту отвечает не Kerio Connect или трафик искажает антивирус/прокси.",
			Raw:     truncateText(string(trimmed), 240)}
	}
	if env.Error != nil {
		return nil, classifyKerioMessage(method, env.Error.Code, env.Error.Message)
	}
	// Некоторые методы Kerio (например remove/import) возвращают список ошибок внутри result.
	if len(env.Result) > 0 {
		var inner struct {
			Errors []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		if json.Unmarshal(env.Result, &inner) == nil && len(inner.Errors) > 0 && strings.TrimSpace(inner.Errors[0].Message) != "" {
			return nil, classifyKerioMessage(method, inner.Errors[0].Code, inner.Errors[0].Message)
		}
	}
	return env.Result, nil
}

// classifyKerioMessage переводит сообщения Kerio в понятные причины и подсказки.
func classifyKerioMessage(method string, code int, message string) *KerioAPIError {
	msg := strings.TrimSpace(message)
	low := strings.ToLower(msg)
	e := &KerioAPIError{Kind: "rpc", Method: method, Code: code, Message: msg}
	switch {
	case strings.Contains(low, "invalid user"), strings.Contains(low, "invalid password"),
		strings.Contains(low, "wrong password"), strings.Contains(low, "authentication failed"),
		strings.Contains(low, "invalid username"), strings.Contains(low, "bad credentials"),
		code == 1000, code == 1001:
		e.Kind = "auth"
		e.Message = "Неверный логин или пароль администратора Kerio Connect: " + msg
		e.Fix = "1) Логин мастер-администратора по умолчанию — admin (БЕЗ @домена и без пробелов).\n" +
			"2) Пароль — тот же, что вы вводите на https://<сервер>:4040/admin/ (учётка администратора Kerio, а не почтового ящика).\n" +
			"3) Проверьте раскладку клавиатуры и Caps Lock; скопируйте пароль из менеджера паролей.\n" +
			"4) Если пароль содержит кириллицу — временно смените его на латиницу в Kerio.\n" +
			"5) Для дополнительных администраторов логин указывается как user@domain."
	case strings.Contains(low, "two-factor"), strings.Contains(low, "two factor"),
		strings.Contains(low, "otp"), strings.Contains(low, "one-time"),
		strings.Contains(low, "verification code"), strings.Contains(low, "2fa"):
		e.Kind = "otp"
		e.Message = "Для этой учётной записи включена двухфакторная аутентификация (2FA): " + msg
		e.Fix = "JSON-RPC Admin API Kerio Connect не поддерживает вход с одноразовым кодом.\n" +
			"1) Создайте отдельного администратора БЕЗ 2FA специально для API: Kerio Connect → Configuration → Administration → Administrators → Add (например kerioapi).\n" +
			"2) Укажите его логин/пароль в этой программе.\n" +
			"3) Не используйте для API личную учётку с 2FA."
	case strings.Contains(low, "access denied"), strings.Contains(low, "permission"), strings.Contains(low, "not allowed"),
		strings.Contains(low, "privilege"), strings.Contains(low, "forbidden"), code == 1003:
		e.Kind = "rights"
		e.Message = "Учётная запись не имеет прав администратора Kerio Connect: " + msg
		e.Fix = "1) Войдите в Kerio Connect → Configuration → Administration → Administrators и проверьте, что учётка есть в списке администраторов.\n" +
			"2) Пользователь домена (например info@leend.by) администратором НЕ является — нужен администратор Kerio Connect.\n" +
			"3) Убедитесь, что у администратора есть право изменять SSL-сертификаты (полный администратор, не делегированный с ограничениями)."
	case strings.Contains(low, "too many"), strings.Contains(low, "blocked"), strings.Contains(low, "locked"),
		strings.Contains(low, "banned"):
		e.Kind = "locked"
		e.Message = "Kerio временно заблокировал вход с этого IP: " + msg
		e.Fix = "Kerio Connect включает защиту от подбора паролей. Подождите 10–30 минут и повторите.\n" +
			"Если блокировка повторяется — проверьте правильность пароля в веб-админке Kerio."
	case strings.Contains(low, "method not found"), code == -32601:
		e.Kind = "method"
		e.Message = "Метод " + method + " не поддерживается этим сервером: " + msg
		e.Fix = "Похоже, это не Kerio Connect (например Kerio Control на 4081) или очень старая версия Kerio Connect без ConnectCertificate API.\n" +
			"Проверьте версию: Kerio Connect 8.5+ поддерживает ConnectCertificate.*"
	case strings.Contains(low, "invalid params"), code == -32602:
		e.Kind = "protocol"
		e.Message = "Kerio отклонил параметры вызова " + method + ": " + msg
		e.Fix = "Обновите программу до последней версии — формат вызова отличается в этой сборке Kerio."
	case strings.Contains(low, "csrf"), strings.Contains(low, "token"):
		e.Kind = "protocol"
		e.Message = "Kerio отклонил сессию (CSRF/X-Token): " + msg
		e.Fix = "Программа заново авторизуется автоматически. Если ошибка повторяется — проверьте, что между программой и Kerio нет прокси, который вырезает cookie."
	}
	if e.Fix == "" {
		e.Fix = "Полный текст ошибки Kerio приведён выше. Проверьте права администратора и версию Kerio Connect."
	}
	return e
}

// ---------------------------------------------------------------------------
// Высокоуровневые операции
// ---------------------------------------------------------------------------

func kerioLoginVariants(user, domainHint string) []string {
	u := strings.TrimSpace(user)
	if u == "" {
		u = "admin"
	}
	out := []string{u}
	if !strings.Contains(u, "@") {
		d := strings.TrimPrefix(strings.TrimSpace(domainHint), "@")
		if d != "" {
			out = append(out, u+"@"+d)
		}
	}
	if !strings.EqualFold(u, "admin") {
		out = append(out, "admin")
	}
	seen := map[string]bool{}
	res := make([]string, 0, len(out))
	for _, v := range out {
		key := strings.ToLower(v)
		if seen[key] {
			continue
		}
		seen[key] = true
		res = append(res, v)
	}
	return res
}

// Login выполняет Session.login с перебором вариантов имени администратора.
func (c *KerioClient) Login(user, password, domainHint string) error {
	var lastErr error
	for _, u := range kerioLoginVariants(user, domainHint) {
		raw, err := c.rpc("Session.login", map[string]any{
			"userName": u,
			"password": password,
			"application": map[string]any{
				"name":    "KerioCertManager",
				"vendor":  "CSL.BY",
				"version": "4.3",
			},
		})
		if err != nil {
			lastErr = err
			kind := kerioErrKind(err)
			if kind == "auth" {
				continue // возможно, нужен формат user@domain
			}
			return err
		}
		var res struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(raw, &res)
		if strings.TrimSpace(res.Token) == "" {
			return &KerioAPIError{Kind: "protocol", Method: "Session.login",
				Message: "Kerio принял login, но не вернул token (CSRF).",
				Fix:     "Проверьте, что запросы идут на /admin/api/jsonrpc/ и cookie сессии не вырезается прокси.",
				Raw:     truncateText(string(raw), 200)}
		}
		c.Token = res.Token
		c.User = u
		return nil
	}
	if lastErr == nil {
		lastErr = kerioErr("auth", "Session.login", "не удалось войти в Kerio Connect", "")
	}
	return lastErr
}

type KerioWhoAmI struct {
	LoginName string `json:"loginName"`
	FullName  string `json:"fullName"`
	Role      string `json:"role"`
	IsAdmin   bool   `json:"isAdmin"`
}

func (c *KerioClient) WhoAmI() (KerioWhoAmI, error) {
	var out KerioWhoAmI
	raw, err := c.rpc("Session.whoAmI", nil)
	if err != nil {
		return out, err
	}
	var parsed struct {
		UserDetails struct {
			LoginName string `json:"loginName"`
			FullName  string `json:"fullName"`
			IsAdmin   bool   `json:"isAdmin"`
			EffectiveRole struct {
				UserRole string `json:"userRole"`
			} `json:"effectiveRole"`
		} `json:"userDetails"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return out, nil
	}
	out.LoginName = parsed.UserDetails.LoginName
	out.FullName = parsed.UserDetails.FullName
	out.Role = parsed.UserDetails.EffectiveRole.UserRole
	out.IsAdmin = parsed.UserDetails.IsAdmin ||
		strings.Contains(strings.ToLower(out.Role), "admin")
	return out, nil
}

type KerioProductInfo struct {
	Product     string `json:"product"`
	Version     string `json:"version"`
	Major       int    `json:"major"`
	Minor       int    `json:"minor"`
	Revision    int    `json:"revision"`
	APIVersion  int    `json:"apiVersion"`
}

func (c *KerioClient) ProductVersion() (KerioProductInfo, error) {
	var out KerioProductInfo
	raw, err := c.rpc("Version.getProductVersion", nil)
	if err != nil {
		return out, err
	}
	var parsed struct {
		ProductVersion struct {
			ProductName   string `json:"productName"`
			Major         int    `json:"major"`
			Minor         int    `json:"minor"`
			Revision      int    `json:"revision"`
			DisplayNumber string `json:"displayNumber"`
		} `json:"productVersion"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return out, nil
	}
	pv := parsed.ProductVersion
	out.Product = pv.ProductName
	out.Version = pv.DisplayNumber
	if out.Version == "" {
		out.Version = fmt.Sprintf("%d.%d.%d", pv.Major, pv.Minor, pv.Revision)
	}
	out.Major, out.Minor, out.Revision = pv.Major, pv.Minor, pv.Revision
	if apiRaw, aerr := c.rpc("Version.getApiVersion", nil); aerr == nil {
		var api struct {
			APIVersion int `json:"apiVersion"`
		}
		if json.Unmarshal(apiRaw, &api) == nil {
			out.APIVersion = api.APIVersion
		}
	}
	return out, nil
}

// KerioRemoteCertInfo — сертификат на сервере Kerio.
type KerioRemoteCertInfo struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	HostNames    []string `json:"hostNames"`
	IssuerName   string   `json:"issuerName"`
	ValidFrom    string   `json:"validFrom"`
	ValidTo      string   `json:"validTo"`
	Active       bool     `json:"active"`
	Type         string   `json:"type"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	KeyID        string   `json:"keyId,omitempty"`
	SourceIface  string   `json:"interface,omitempty"`
}

type kerioCertListParsed struct {
	Certificates []struct {
		Id               string   `json:"id"`
		Name             string   `json:"name"`
		SubjectHostNames []string `json:"subjectHostNames"`
		Fingerprint      string   `json:"fingerprint"`
		KeyId            string   `json:"keyId"`
		Issuer           []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"issuer"`
		Subject []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"subject"`
		ValidPeriod struct {
			ValidFromDate string `json:"validFromDate"`
			ValidToDate   string `json:"validToDate"`
		} `json:"validPeriod"`
		Active   bool   `json:"active"`
		IsActive bool   `json:"isActive"`
		Type     string `json:"type"`
	} `json:"certificates"`
}

// ListCertificates возвращает сертификаты Kerio и имя использованного интерфейса
// (ConnectCertificate для серверных сертификатов, Certificates для WebAdmin).
func (c *KerioClient) ListCertificates() ([]KerioRemoteCertInfo, string, error) {
	iface := "ConnectCertificate"
	raw, err := c.rpc("ConnectCertificate.get", nil)
	if err != nil {
		if kerioErrKind(err) != "method" {
			return nil, iface, err
		}
		iface = "Certificates"
		raw, err = c.rpc("Certificates.get", nil)
		if err != nil {
			if kerioErrKind(err) == "protocol" {
				raw, err = c.rpc("Certificates.get", map[string]any{"query": map[string]any{"fields": []string{}}})
			}
			if err != nil {
				return nil, iface, err
			}
		}
	}
	var parsed kerioCertListParsed
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, iface, &KerioAPIError{Kind: "protocol", Method: iface + ".get",
			Message: "не удалось разобрать список сертификатов Kerio: " + err.Error(),
			Raw:     truncateText(string(raw), 240)}
	}
	out := make([]KerioRemoteCertInfo, 0, len(parsed.Certificates))
	for _, crt := range parsed.Certificates {
		var issuerCN, subjCN string
		for _, kv := range crt.Issuer {
			if strings.EqualFold(kv.Name, "CN") && issuerCN == "" {
				issuerCN = kv.Value
			}
			if strings.EqualFold(kv.Name, "O") && issuerCN == "" {
				issuerCN = kv.Value
			}
		}
		for _, kv := range crt.Subject {
			if strings.EqualFold(kv.Name, "CN") {
				subjCN = kv.Value
				break
			}
		}
		hosts := crt.SubjectHostNames
		if len(hosts) == 0 && subjCN != "" {
			hosts = []string{subjCN}
		}
		name := crt.Name
		if name == "" {
			name = subjCN
		}
		active := crt.Active || crt.IsActive || strings.EqualFold(crt.Type, "ActiveCertificate")
		out = append(out, KerioRemoteCertInfo{
			ID:          crt.Id,
			Name:        name,
			HostNames:   hosts,
			IssuerName:  issuerCN,
			ValidFrom:   crt.ValidPeriod.ValidFromDate,
			ValidTo:     crt.ValidPeriod.ValidToDate,
			Active:      active,
			Type:        crt.Type,
			Fingerprint: crt.Fingerprint,
			KeyID:       crt.KeyId,
			SourceIface: iface,
		})
	}
	return out, iface, nil
}

// UploadFile загружает файл в Kerio.
// ВАЖНО: официальный формат — часть multipart с name="unknown" и
// filename="newFile.bin" (так делает Kerio APIs Client Library for PHP 1.4.0.234).
// Если сервер не принимает такой формат, пробуем альтернативные варианты,
// которые встречаются в других клиентах Kerio.
func (c *KerioClient) UploadFile(displayName string, content []byte) (string, error) {
	type variant struct {
		Field    string
		FileName string
	}
	variants := []variant{
		{"unknown", "newFile.bin"}, // официальный формат Kerio
		{"file", "newFile.bin"},
		{"newFile", "newFile.bin"},
		{"file", displayName},
	}
	var lastErr error
	for _, v := range variants {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, v.Field, v.FileName))
		h.Set("Content-Type", "application/octet-stream")
		part, err := mw.CreatePart(h)
		if err != nil {
			return "", err
		}
		if _, err := part.Write(content); err != nil {
			return "", err
		}
		_ = mw.Close()

		resp, err := c.do(http.MethodPost, c.Endpoint.UploadURL(), mw.FormDataContentType(), buf.Bytes(),
			map[string]string{"Accept": "*/*"})
		if err != nil {
			return "", err
		}
		if resp.Status != http.StatusOK {
			lastErr = c.httpStatusError("upload", resp)
			continue
		}
		trimmed := bytes.TrimSpace(resp.Body)
		if len(trimmed) == 0 || trimmed[0] == '<' {
			lastErr = &KerioAPIError{Kind: "protocol", Method: "upload",
				Message: "Kerio вернул не JSON при загрузке файла.",
				Fix:     "Проверьте адрес https://<host>:4040/admin/api/jsonrpc/upload/ — его обслуживает сам Kerio Connect.",
				Raw:     truncateText(string(trimmed), 200)}
			continue
		}
		var parsed struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(trimmed, &parsed); err != nil {
			lastErr = &KerioAPIError{Kind: "protocol", Method: "upload",
				Message: "некорректный ответ Kerio на загрузку файла: " + err.Error(),
				Raw:     truncateText(string(trimmed), 240)}
			continue
		}
		if parsed.Error != nil {
			return "", classifyKerioMessage("upload", parsed.Error.Code, parsed.Error.Message)
		}
		// result: {"fileUpload":{"id":"..."}} | {"id":"..."} | "id"
		var nested struct {
			FileUpload struct {
				Id string `json:"id"`
			} `json:"fileUpload"`
			Id string `json:"id"`
		}
		var asString string
		if json.Unmarshal(parsed.Result, &asString) == nil && asString != "" {
			return asString, nil
		}
		if json.Unmarshal(parsed.Result, &nested) == nil {
			if nested.FileUpload.Id != "" {
				return nested.FileUpload.Id, nil
			}
			if nested.Id != "" {
				return nested.Id, nil
			}
		}
		lastErr = &KerioAPIError{Kind: "protocol", Method: "upload",
			Message: "Kerio не вернул fileId загруженного файла.",
			Fix:     "Сервер Kerio принял запрос, но не отдал идентификатор файла. Проверьте версию Kerio Connect (нужна 8.5+).",
			Raw:     truncateText(string(trimmed), 240)}
	}
	if lastErr == nil {
		lastErr = kerioErr("protocol", "upload", "не удалось загрузить файл в Kerio", "")
	}
	return "", lastErr
}

func (c *KerioClient) Logout() {
	if c.Token == "" {
		return
	}
	_, _ = c.rpc("Session.logout", nil)
	c.Token = ""
}

// ---------------------------------------------------------------------------
// Диагностика подключения
// ---------------------------------------------------------------------------

type KerioDiagStep struct {
	Key    string `json:"key"`
	Title  string `json:"title"`
	Status string `json:"status"` // ok | warn | fail | skip
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

type KerioEndpointProbe struct {
	Endpoint KerioEndpoint `json:"endpoint"`
	TCP      bool          `json:"tcp"`
	TLS      bool          `json:"tls"`
	HTTP     int           `json:"http"`
	Product  string        `json:"product"`
	Note     string        `json:"note"`
}

type KerioDiagResult struct {
	OK         bool                 `json:"ok"`
	Host       string               `json:"host"`
	Port       int                  `json:"port"`
	URL        string               `json:"url"`
	Steps      []KerioDiagStep      `json:"steps"`
	Verdict    string               `json:"verdict"`
	Fixes      []string             `json:"fixes"`
	Product    string               `json:"product,omitempty"`
	Version    string               `json:"version,omitempty"`
	LoginUser  string               `json:"loginUser,omitempty"`
	Role       string               `json:"role,omitempty"`
	Interface  string               `json:"interface,omitempty"`
	Certs      []KerioRemoteCertInfo `json:"certs"`
	Candidates []KerioEndpointProbe `json:"candidates,omitempty"`
}

func (r *KerioDiagResult) step(key, title, status, detail, fix string) {
	r.Steps = append(r.Steps, KerioDiagStep{Key: key, Title: title, Status: status, Detail: detail, Fix: fix})
}

func (r *KerioDiagResult) fail(key, title string, err error) {
	var ke *KerioAPIError
	fix := ""
	if errors.As(err, &ke) {
		fix = ke.Fix
	}
	r.step(key, title, "fail", err.Error(), fix)
	if fix != "" {
		r.Fixes = append(r.Fixes, splitFixes(fix)...)
	}
	r.OK = false
}

func splitFixes(fix string) []string {
	var out []string
	for _, line := range strings.Split(fix, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// DiagnoseKerioConnection выполняет пошаговую проверку подключения к Kerio Connect
// и возвращает точную причину сбоя с готовыми инструкциями.
func DiagnoseKerioConnection(host string, port int, user, password, domainHint string, probeUpload bool) KerioDiagResult {
	res := KerioDiagResult{Steps: []KerioDiagStep{}, Fixes: []string{}, Certs: []KerioRemoteCertInfo{}}
	h, p := NormalizeKerioHost(host, port)
	res.Host, res.Port = h, p
	ep := KerioEndpoint{Host: h, Port: p}
	res.URL = ep.RPCURL()

	// 1. Параметры
	detail := fmt.Sprintf("Сервер: %s, порт %d, адрес API: %s, администратор: %s", h, p, res.URL, user)
	if strings.EqualFold(user, "") {
		detail += " (логин не указан — будет использован admin)"
	}
	res.step("params", "Параметры подключения", "ok", detail, "")
	if ip := net.ParseIP(h); ip == nil {
		res.step("host-kind", "Тип адреса", "warn",
			fmt.Sprintf("Указано имя хоста \"%s\". Если это внешнее имя (например mail.example.by), порт 4040 обычно закрыт из интернета.", h),
			"Админка Kerio Connect (:4040) по умолчанию доступна только из локальной сети/VPN. Укажите внутренний IP сервера (например 10.x.x.x) или запустите программу на самом сервере с адресом 127.0.0.1.")
	}

	// 2. DNS
	var ips []string
	if ip := net.ParseIP(h); ip != nil {
		ips = []string{ip.String()}
		res.step("dns", "Разрешение имени", "ok", "Указан IP-адрес — DNS не требуется: "+ip.String(), "")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, h)
		cancel()
		if err != nil {
			res.fail("dns", "Разрешение имени", kerioErr("dns", "",
				fmt.Sprintf("Не удалось разрешить имя \"%s\": %v", h, err),
				"1) Проверьте имя на опечатки.\n2) Укажите IP-адрес сервера Kerio.\n3) Внутреннее имя должно резолвиться через внутренний DNS/VPN."))
			res.skipRest("dns")
			res.finalize()
			return res
		}
		for _, a := range addrs {
			ips = append(ips, a.IP.String())
		}
		sort.Strings(ips)
		detail = fmt.Sprintf("%s → %s", h, strings.Join(ips, ", "))
		status := "ok"
		for _, a := range addrs {
			if a.IP.IsLoopback() && !strings.EqualFold(h, "localhost") {
				status = "warn"
			}
		}
		res.step("dns", "Разрешение имени", status, detail, "")
		if status == "warn" {
			res.step("dns-loopback", "Проверка DNS", "warn",
				"Имя разрешается в 127.0.0.1 — Kerio должен быть установлен на этом же компьютере.",
				"Если Kerio Connect стоит на другом сервере — укажите его IP-адрес вручную.")
		}
	}

	// 3. TCP
	tcpAddr := ep.HostPort()
	conn, err := net.DialTimeout("tcp", tcpAddr, 5*time.Second)
	if err != nil {
		res.fail("tcp", "TCP-порт "+strconv.Itoa(p), kerioErr("tcp", "",
			fmt.Sprintf("Порт %d недоступен на %s: %v", p, h, err),
			"1) Убедитесь, что Kerio Connect запущен и админка включена: Configuration → Services → Web Administration (порт 4040).\n"+
				"2) Разрешите входящий TCP 4040 в Windows Firewall на сервере Kerio для вашей подсети.\n"+
				"3) Порт 4040 НЕ должен публиковаться в интернет — подключайтесь из локальной сети или через VPN.\n"+
				"4) Если Kerio на другом сервере — укажите его внутренний IP, а не внешний домен."))
		res.skipRest("tcp")
		res.finalize()
		return res
	}
	_ = conn.Close()
	res.step("tcp", "TCP-порт "+strconv.Itoa(p), "ok", "Порт открыт: "+tcpAddr+" принимает соединения.", "")

	// 4. TLS
	tlsConn, tlsErr := tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second}, "tcp", tcpAddr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         h,
	})
	if tlsErr != nil {
		res.fail("tls", "TLS-рукопожатие", kerioErr("tls", "",
			fmt.Sprintf("TLS-соединение с %s не установлено: %v", tcpAddr, tlsErr),
			"1) На порту 4040 должен работать именно Kerio Connect (а не прокси/антивирус).\n"+
				"2) В Kerio включите поддержку TLS 1.2: Configuration → SSL Certificates.\n"+
				"3) Отключите SSL-инспекцию антивируса/файрвола для внутренней сети."))
		res.skipRest("tls")
		res.finalize()
		return res
	}
	st := tlsConn.ConnectionState()
	_ = tlsConn.Close()
	tlsInfo := fmt.Sprintf("%s, шифр %s", tlsVersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		selfSigned := leaf.Issuer.String() == leaf.Subject.String()
		tlsInfo += fmt.Sprintf("; сертификат CN=%s, издатель %s, действует до %s", leaf.Subject.CommonName, leaf.Issuer.CommonName, leaf.NotAfter.Format("02.01.2006"))
		if selfSigned {
			tlsInfo += " (самоподписанный — для Kerio это норма)"
		}
		if len(leaf.DNSNames) > 0 {
			tlsInfo += "; SAN: " + strings.Join(leaf.DNSNames, ", ")
		}
	}
	status := "ok"
	if st.Version < tls.VersionTLS12 {
		status = "warn"
	}
	res.step("tls", "TLS-рукопожатие", status, tlsInfo,
		"Kerio использует устаревший TLS 1.0/1.1. Включите TLS 1.2 в Kerio Connect — современные клиенты (включая Outlook) могут отказываться работать.")

	// 5. HTTP /admin/
	httpCli := kerioHTTPClient(10 * time.Second)
	if resp, herr := httpCli.Get(ep.BaseURL() + "/admin/"); herr == nil {
		_ = resp.Body.Close()
		code := resp.StatusCode
		server := resp.Header.Get("Server")
		prod := detectKerioProduct(server)
		if prod != "" {
			res.Product = prod
		}
		loc := resp.Header.Get("Location")
		detail = fmt.Sprintf("GET %s/admin/ → HTTP %d", ep.BaseURL(), code)
		if server != "" {
			detail += "; Server: " + server
		}
		if loc != "" {
			detail += "; редирект: " + loc
		}
		switch {
		case code == 200 || code == 302 || code == 301:
			res.step("http", "Веб-админка Kerio", "ok", detail, "")
		case code == 404:
			res.step("http", "Веб-админка Kerio", "warn", detail,
				"Страница /admin/ не найдена. Проверьте порт: Kerio Connect — 4040, Kerio Control — 4081, Kerio Operator — 4021.")
		default:
			res.step("http", "Веб-админка Kerio", "warn", detail,
				"Сервер отвечает нестандартно. Проверьте, что это Kerio Connect и что перед ним нет reverse-proxy.")
		}
	} else if herr != nil {
		res.step("http", "Веб-админка Kerio", "warn", "не удалось получить /admin/: "+herr.Error(), "")
	}

	// 6. Login
	cli := NewKerioClient(ep)
	if err := cli.Login(user, password, domainHint); err != nil {
		res.fail("login", "Вход администратора (Session.login)", err)
		res.skipRest("login")
		res.finalize()
		return res
	}
	res.LoginUser = cli.User
	res.step("login", "Вход администратора (Session.login)", "ok",
		fmt.Sprintf("Успешный вход: %s. Получен X-Token и cookie SESSION_CONNECT_WEBADMIN.", cli.User), "")

	// 7. Права
	if who, werr := cli.WhoAmI(); werr == nil {
		role := who.Role
		if role == "" {
			role = "неизвестна"
		}
		if who.IsAdmin {
			res.step("rights", "Права администратора", "ok",
				fmt.Sprintf("Роль: %s (пользователь %s). Полные права администратора подтверждены.", role, who.LoginName), "")
			res.Role = role
		} else {
			res.step("rights", "Права администратора", "fail",
				fmt.Sprintf("Учётка %s вошла, но роль \"%s\" не является административной.", who.LoginName, role),
				"1) Добавьте учётку в администраторы: Kerio Connect → Configuration → Administration → Administrators.\n"+
					"2) Используйте мастер-администратора (обычно admin), а не пользователя домена.\n"+
					"3) Делегированный администратор без прав на SSL-сертификаты не сможет их установить.")
			res.Fixes = append(res.Fixes, splitFixes(res.Steps[len(res.Steps)-1].Fix)...)
			res.OK = false
			res.skipRest("rights")
			res.finalize()
			return res
		}
	} else {
		res.step("rights", "Права администратора", "warn", "не удалось вызвать Session.whoAmI: "+werr.Error(), "")
	}

	// 8. Версия продукта
	if pv, verr := cli.ProductVersion(); verr == nil {
		res.Product = strings.TrimSpace(pv.Product)
		res.Version = pv.Version
		if res.Product == "" {
			res.Product = "Kerio Connect"
		}
		status := "ok"
		fix := ""
		if !strings.Contains(strings.ToLower(res.Product), "connect") {
			status = "warn"
			fix = "Обнаружен продукт \"" + res.Product + "\". Программа рассчитана на Kerio Connect (порт 4040). Для Kerio Control используйте порт 4081."
		}
		res.step("version", "Версия продукта", status,
			fmt.Sprintf("%s %s (API v%d)", res.Product, res.Version, pv.APIVersion), fix)
	} else {
		res.step("version", "Версия продукта", "warn", "не удалось получить версию: "+verr.Error(), "")
	}

	// 9. Сертификаты
	certs, iface, cerr := cli.ListCertificates()
	if cerr != nil {
		res.fail("certs", "Список сертификатов ("+iface+".get)", cerr)
	} else {
		res.Interface = iface
		res.Certs = certs
		activeName := "нет активного"
		for _, crt := range certs {
			if crt.Active {
				activeName = crt.Name
				if activeName == "" {
					activeName = crt.ID
				}
				break
			}
		}
		res.step("certs", "Список сертификатов ("+iface+".get)", "ok",
			fmt.Sprintf("Интерфейс %s: сертификатов %d, активный — %s.", iface, len(certs), activeName), "")
	}

	// 10. Загрузка файла (проверка upload-канала, нужного для установки)
	if probeUpload {
		probe := []byte("KerioCertManager connectivity probe\n")
		if id, uerr := cli.UploadFile("probe.txt", probe); uerr != nil {
			res.fail("upload", "Загрузка файла в Kerio (upload/)", uerr)
		} else {
			res.step("upload", "Загрузка файла в Kerio (upload/)", "ok",
				"Канал загрузки файлов работает, fileId: "+id+". Установка сертификата через API возможна.", "")
		}
	}

	cli.Logout()
	res.OK = true
	for _, s := range res.Steps {
		if s.Status == "fail" {
			res.OK = false
		}
	}
	res.finalize()
	return res
}

func (r *KerioDiagResult) skipRest(afterKey string) {
	titles := map[string]string{
		"dns":   "TCP-порт / TLS / API",
		"tcp":   "TLS / API",
		"tls":   "API Kerio (JSON-RPC)",
		"login": "Проверка прав и сертификатов",
		"rights": "Проверка сертификатов",
	}
	t := titles[afterKey]
	if t == "" {
		t = "Остальные проверки"
	}
	r.step("skipped", "Пропущено", "skip", "Проверки после шага \""+afterKey+"\" не выполнялись: "+t+".", "")
}

func (r *KerioDiagResult) finalize() {
	if r.OK {
		if r.Version != "" {
			r.Verdict = fmt.Sprintf("✅ Подключение к %s %s работает. Вход выполнен как %s (%s).", r.Product, r.Version, r.LoginUser, r.Role)
		} else {
			r.Verdict = "✅ Подключение к Kerio Connect работает, вход администратора выполнен."
		}
		return
	}
	for _, s := range r.Steps {
		if s.Status == "fail" {
			r.Verdict = "❌ " + s.Title + ": " + s.Detail
			break
		}
	}
	if r.Verdict == "" {
		r.Verdict = "⚠️ Подключение выполнено частично — см. предупреждения ниже."
	}
	// дедупликация подсказок
	seen := map[string]bool{}
	uniq := make([]string, 0, len(r.Fixes))
	for _, f := range r.Fixes {
		if !seen[f] {
			seen[f] = true
			uniq = append(uniq, f)
		}
	}
	r.Fixes = uniq
	if len(r.Fixes) == 0 {
		r.Fixes = append(r.Fixes, "Откройте https://"+net.JoinHostPort(r.Host, strconv.Itoa(r.Port))+"/admin/ в браузере на этом компьютере и проверьте, что админка Kerio открывается и вход работает.")
	}
}


func detectKerioProduct(server string) string {
	low := strings.ToLower(server)
	switch {
	case strings.Contains(low, "kerio connect"):
		return "Kerio Connect"
	case strings.Contains(low, "kerio control"):
		return "Kerio Control"
	case strings.Contains(low, "kerio operator"):
		return "Kerio Operator"
	case strings.Contains(low, "kerio"):
		return "Kerio"
	}
	return ""
}

// DiscoverKerioCandidates ищет доступные админки Kerio среди вероятных адресов:
// указанный хост, localhost, локальные IPv4-адреса машины, домен и MX.
func DiscoverKerioCandidates(hostHint, domain string) []KerioEndpointProbe {
	cand := map[string]KerioEndpoint{}
	add := func(host string, port int) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		key := strings.ToLower(host) + ":" + strconv.Itoa(port)
		cand[key] = KerioEndpoint{Host: host, Port: port}
	}

	h, p := NormalizeKerioHost(hostHint, kerioAdminPort)
	add(h, p)
	add("127.0.0.1", kerioAdminPort)
	add("localhost", kerioAdminPort)
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, aerr := ifc.Addrs()
			if aerr != nil {
				continue
			}
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					if v4 := ipnet.IP.To4(); v4 != nil {
						add(v4.String(), kerioAdminPort)
					}
				}
			}
		}
	}
	if d := strings.TrimSpace(domain); d != "" {
		add(d, kerioAdminPort)
		add("mail."+d, kerioAdminPort)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if mxs, err := net.DefaultResolver.LookupMX(ctx, d); err == nil {
			for _, mx := range mxs {
				add(strings.TrimSuffix(mx.Host, "."), kerioAdminPort)
			}
		}
		cancel()
	}

	keys := make([]string, 0, len(cand))
	for k := range cand {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	probes := make([]KerioEndpointProbe, 0, len(keys))
	for _, k := range keys {
		ep := cand[k]
		probe := KerioEndpointProbe{Endpoint: ep}
		conn, err := net.DialTimeout("tcp", ep.HostPort(), 1500*time.Millisecond)
		if err != nil {
			probe.Note = "порт закрыт/недоступен"
			probes = append(probes, probe)
			continue
		}
		probe.TCP = true
		_ = conn.Close()
		tlsConn, terr := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", ep.HostPort(), &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			ServerName:         ep.Host,
		})
		if terr == nil {
			probe.TLS = true
			_ = tlsConn.Close()
		}
		cli := kerioHTTPClient(5 * time.Second)
		if resp, herr := cli.Get(ep.BaseURL() + "/admin/"); herr == nil {
			probe.HTTP = resp.StatusCode
			probe.Product = detectKerioProduct(resp.Header.Get("Server"))
			_ = resp.Body.Close()
		}
		probe.Note = "TCP открыт"
		if probe.TLS {
			probe.Note += ", TLS ок"
		}
		if probe.HTTP != 0 {
			probe.Note += fmt.Sprintf(", /admin/ → HTTP %d", probe.HTTP)
		}
		probes = append(probes, probe)
	}
	return probes
}
