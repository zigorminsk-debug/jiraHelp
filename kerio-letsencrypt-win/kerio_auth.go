package main

// kerio_auth.go — карточка «Вход под администратором Kerio Connect».
//
// Зачем отдельно от DiagnoseKerioConnection: диагностика отвечает на вопрос
// «почему не работает вся цепочка до сертификатов» (9 шагов, включая загрузку
// файла). А здесь нужен быстрый и очень конкретный ответ на один вопрос:
//
//	«Этот логин и пароль вообще подходят администратору Kerio?»
//
// Поэтому проверка устроена так:
//  1. быстро отсекаем сетевые причины (DNS, порт, TLS, веб-админка);
//  2. пробуем вход по всем разумным вариантам имени (admin, admin@домен, …)
//     и запоминаем результат КАЖДОЙ попытки;
//  3. при успехе показываем, кто именно вошёл, его роль, версию Kerio, есть ли
//     права на сертификаты и жива ли сессия (token + cookie);
//  4. при неудаче собираем список причин с пошаговым устранением — не общими
//     словами, а под конкретную ошибку Kerio (неверный пароль, 2FA, блокировка
//     после подбора, учётка не администратор, вход почтовым ящиком и т.д.).

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// KerioLoginCheckRequest — то, что приходит из карточки.
type KerioLoginCheckRequest struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	Password   string `json:"password"`
	Domain     string `json:"domain"`
	ProbeCerts bool   `json:"probeCerts"`
}

// KerioAuthAttempt — результат одной попытки входа (по одному варианту логина).
type KerioAuthAttempt struct {
	Login     string `json:"login"`
	OK        bool   `json:"ok"`
	ErrorKind string `json:"errorKind,omitempty"`
	Error     string `json:"error,omitempty"`
	Fix       string `json:"fix,omitempty"`
	Note      string `json:"note,omitempty"`
}

// KerioAuthCheck — один шаг проверки (для наглядности в UI).
type KerioAuthCheck struct {
	Key    string `json:"key"`
	Title  string `json:"title"`
	Status string `json:"status"` // ok | warn | fail | skip
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// KerioAuthCause — причина неудачи + готовый план устранения.
type KerioAuthCause struct {
	Code        string   `json:"code"`
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	Severity    string   `json:"severity"` // block | warn
	Steps       []string `json:"steps"`
	// Где проверить руками (подсказка «глазами администратора»).
	CheckWhere string `json:"checkWhere,omitempty"`
	// Anchor — якорь подробного раздела инструкции (кнопка «Как исправить
	// по шагам» в интерфейсе). Пусто, если отдельного раздела нет.
	Anchor string `json:"anchor,omitempty"`
}

// KerioAuthResult — ответ карточке.
type KerioAuthResult struct {
	OK       bool   `json:"ok"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	URL      string `json:"url"`
	WebAdmin string `json:"webAdmin"`
	User     string `json:"user"`

	LoginUser  string `json:"loginUser,omitempty"`
	Product    string `json:"product,omitempty"`
	Version    string `json:"version,omitempty"`
	APIVersion int    `json:"apiVersion,omitempty"`
	Role       string `json:"role,omitempty"`
	IsAdmin    bool   `json:"isAdmin"`
	FullName   string `json:"fullName,omitempty"`

	TokenMasked string `json:"tokenMasked,omitempty"`
	TokenLen    int    `json:"tokenLen,omitempty"`
	CookieOK    bool   `json:"cookieOk"`
	SessionOK   bool   `json:"sessionOk"`
	SessionNote string `json:"sessionNote,omitempty"`

	CertsChecked   bool   `json:"certsChecked"`
	CertsCount     int    `json:"certsCount"`
	CertsInterface string `json:"certsInterface,omitempty"`
	CertsError     string `json:"certsError,omitempty"`
	CanManageCerts bool   `json:"canManageCerts"`

	ElapsedMS int64              `json:"elapsedMs"`
	Attempts  []KerioAuthAttempt `json:"attempts"`
	Checks    []KerioAuthCheck   `json:"checks"`
	Causes    []KerioAuthCause   `json:"causes"`
	Verdict   string             `json:"verdict"`
	Summary   string             `json:"summary,omitempty"`
}

func (r *KerioAuthResult) step(key, title, status, detail, fix string) {
	r.Checks = append(r.Checks, KerioAuthCheck{Key: key, Title: title, Status: status, Detail: detail, Fix: fix})
}

func (r *KerioAuthResult) cause(c KerioAuthCause) {
	for _, ex := range r.Causes {
		if ex.Code == c.Code {
			return // не дублируем одинаковые причины
		}
	}
	r.Causes = append(r.Causes, c)
}

// maskToken показывает только края токена: токен — это фактически пароль сессии.
func maskToken(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	if len(t) <= 12 {
		return "••••"
	}
	return t[:4] + "…" + t[len(t)-4:]
}

// looksLikeEmail отлавливает самую частую ошибку: вместо администратора
// Kerio пытаются войти почтовым ящиком (info@company.by).
func looksLikeEmail(s string) bool {
	s = strings.TrimSpace(s)
	return strings.Contains(s, "@") && strings.Contains(strings.SplitN(s, "@", 2)[1], ".")
}

// hasNonASCII — пароль с кириллицей часто «ломается» при копировании/раскладке.
func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

// CheckKerioAdminLogin — основная операция карточки.
func CheckKerioAdminLogin(req KerioLoginCheckRequest) KerioAuthResult {
	started := time.Now()
	h, p := NormalizeKerioHost(req.Host, req.Port)
	res := KerioAuthResult{
		Host:     h,
		Port:     p,
		User:     strings.TrimSpace(req.User),
		Attempts: []KerioAuthAttempt{},
		Checks:   []KerioAuthCheck{},
		Causes:   []KerioAuthCause{},
	}
	ep := KerioEndpoint{Host: h, Port: p}
	res.URL = ep.RPCURL()
	res.WebAdmin = ep.BaseURL() + "/admin/"
	if res.User == "" {
		res.User = "admin"
	}

	// --- 1. Параметры -------------------------------------------------------
	params := fmt.Sprintf("Сервер %s, порт %d, администратор «%s». Пароль %s.", h, p, res.User, maskPasswordHint(req.Password))
	paramsStatus := "ok"
	paramsFix := ""
	if strings.TrimSpace(req.Password) == "" {
		paramsStatus = "fail"
		paramsFix = "Введите пароль администратора Kerio Connect — тот же, что на " + res.WebAdmin + ". Программа его не сохраняет."
		res.cause(kerioAuthCause("empty-password"))
	} else if strings.TrimSpace(req.Password) != req.Password {
		paramsStatus = "warn"
		paramsFix = "В пароле есть пробелы в начале или в конце — при копировании из письма/менеджера паролей они попадают случайно. Уберите их и попробуйте снова."
		res.cause(kerioAuthCause("spaces-in-password"))
	}
	res.step("params", "Параметры входа", paramsStatus, params, paramsFix)

	if looksLikeEmail(res.User) {
		res.step("user-format", "Формат логина", "warn",
			fmt.Sprintf("«%s» выглядит как почтовый ящик. Администратор Kerio Connect обычно входит по короткому имени (admin, kerioapi), а не по адресу ящика.", res.User),
			"Пользователь домена (info@company.by) администратором НЕ является. Нужен администратор из Configuration → Administration → Administrators.")
		res.cause(kerioAuthCause("email-as-admin"))
	}
	if hasNonASCII(req.Password) {
		res.step("password-charset", "Символы пароля", "warn",
			"В пароле есть символы вне латиницы (кириллица и т. п.).",
			"JSON-RPC Kerio ожидает UTF-8; старые сборки и прокси могут искажать такие пароли. Если вход не проходит — временно смените пароль администратора на латиницу с цифрами.")
		res.cause(kerioAuthCause("non-ascii-password"))
	}

	if paramsStatus == "fail" {
		res.finalize(started)
		return res
	}

	// --- 2. DNS -------------------------------------------------------------
	if ip := net.ParseIP(h); ip != nil {
		res.step("dns", "Разрешение имени", "ok", "Указан IP-адрес — DNS не нужен: "+ip.String(), "")
	} else if h == "localhost" {
		res.step("dns", "Разрешение имени", "ok", "localhost — локальный компьютер.", "")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, h)
		cancel()
		if err != nil {
			res.step("dns", "Разрешение имени", "fail",
				fmt.Sprintf("Имя «%s» не разрешается в IP: %v", h, err),
				"1) Проверьте имя на опечатки.\n2) Укажите внутренний IP сервера Kerio (например 10.0.0.5).\n3) Внутренние имена вида kerio.corp обычно видны только через VPN/внутренний DNS.")
			res.cause(KerioAuthCause{
				Code: "dns", Title: "Имя сервера не найдено в DNS", Severity: "block",
				Explanation: "Компьютер не знает, по какому IP искать Kerio Connect: сервер недоступен ещё до попытки входа, пароль тут ни при чём.",
				Steps: []string{
					"Подставьте IP-адрес сервера вместо имени: он виден в Kerio WebAdmin на самом сервере или командой `ping mail.компания.by` в рабочей сети.",
					"Если сервер доступен только по имени — проверьте, что компьютер в той же сети, а для внешних адресов включён VPN.",
					"Проверьте DNS вручную: `nslookup " + h + "` — в ответе должен быть внутренний адрес сервера.",
					"Если Kerio в другой подсети — уточните у сетевого администратора актуальный IP.",
				},
			})
			res.finalize(started)
			return res
		}
		var list []string
		for _, a := range addrs {
			list = append(list, a.IP.String())
		}
		res.step("dns", "Разрешение имени", "ok", fmt.Sprintf("%s → %s", h, strings.Join(list, ", ")), "")
	}

	// --- 3. TCP -------------------------------------------------------------
	addr := ep.HostPort()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		res.step("tcp", "TCP-порт "+fmt.Sprint(p), "fail",
			fmt.Sprintf("Порт %d на %s не отвечает: %v", p, h, err),
			"1) Kerio Connect должен быть запущен; админка включается в Configuration → Services → Web Administration (порт 4040).\n"+
				"2) Разрешите входящий TCP "+fmt.Sprint(p)+" в файрволе на сервере Kerio для вашей подсети.\n"+
				"3) Порт 4040 нельзя держать открытым в интернет — работайте из локальной сети или через VPN.")
		res.cause(KerioAuthCause{
			Code: "tcp", Title: "Порт Admin API недоступен", Severity: "block",
			Explanation: fmt.Sprintf("До %s невозможно дозвониться по TCP %d: за время ожидания никто не принял соединение. Пароль и логин проверить не удалось — сервер не ответил.", addr, p),
			Steps: []string{
				"Проверьте, что Kerio Connect запущен на сервере (в Windows — служба KerioMailServer, на Linux — systemctl status kerio-connect).",
				"Откройте с этого компьютера https://" + addr + "/admin/ в браузере: если страница не открывается, проблема сетевая, а не в пароле.",
				"Проверьте файрвол на сервере Kerio: должен быть разрешён входящий TCP " + fmt.Sprint(p) + " из вашей подсети.",
				"Убедитесь, что указан внутренний адрес сервера: снаружи 4040 обычно закрыт — нужен VPN.",
				"Если порт изменён в Kerio (Configuration → Services → Web Administration), укажите в программе именно его.",
			},
			CheckWhere: "на сервере Kerio: `netstat -an | find \":4040\"` (Windows) или `ss -lntp | grep 4040` (Linux)",
		})
		res.finalize(started)
		return res
	}
	_ = conn.Close()
	res.step("tcp", "TCP-порт "+fmt.Sprint(p), "ok", "Порт открыт: "+addr+" принимает соединения.", "")

	// --- 4. TLS -------------------------------------------------------------
	tlsConn, tlsErr := tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // самоподписанный сертификат Kerio — норма
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         h,
	})
	if tlsErr != nil {
		res.step("tls", "TLS-рукопожатие", "fail",
			fmt.Sprintf("TLS до %s не поднялся: %v", addr, tlsErr),
			"1) На порту должен отвечать именно Kerio Connect, а не прокси/антивирус.\n"+
				"2) Отключите SSL-инспекцию антивируса/файрвола для внутренней сети.\n"+
				"3) В Kerio включите TLS 1.2 (Configuration → SSL Certificates).")
		res.cause(KerioAuthCause{
			Code: "tls", Title: "Защищённое соединение не устанавливается", Severity: "block",
			Explanation: "Порт открыт, но договориться о шифровании (TLS) не удалось. Так бывает, когда на порту 4040 слушает не Kerio, либо трафик проверяет антивирус/прокси с SSL-инспекцией.",
			Steps: []string{
				"Откройте https://" + addr + "/admin/ в браузере: если видите «соединение не защищено» с чужим сертификатом — на порту не Kerio.",
				"Отключите в антивирусе проверку HTTPS (SSL/TLS scanning) для внутренней сети и повторите.",
				"Уточните, не стоит ли перед Kerio reverse-proxy (nginx/IIS ARR): он должен проксировать именно /admin/api/jsonrpc/.",
				"Проверьте, что порт не занят другим продуктом Kerio: Kerio Control — 4081, Kerio Operator — 4021.",
			},
		})
		res.finalize(started)
		return res
	}
	st := tlsConn.ConnectionState()
	_ = tlsConn.Close()
	tlsDetail := fmt.Sprintf("%s, шифр %s", tlsVersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		tlsDetail += fmt.Sprintf("; сертификат CN=%s, действует до %s", leaf.Subject.CommonName, leaf.NotAfter.Format("02.01.2006"))
		if leaf.Issuer.String() == leaf.Subject.String() {
			tlsDetail += " (самоподписанный — для админки Kerio это норма)"
		}
	}
	tlsStatus := "ok"
	if st.Version < tls.VersionTLS12 {
		tlsStatus = "warn"
	}
	res.step("tls", "TLS-рукопожатие", tlsStatus, tlsDetail,
		"Kerio работает на устаревшем TLS 1.0/1.1 — включите TLS 1.2 в Configuration → SSL Certificates.")

	// --- 5. Веб-админка -----------------------------------------------------
	if httpCli := kerioHTTPClient(8 * time.Second); httpCli != nil {
		if resp, herr := httpCli.Get(ep.BaseURL() + "/admin/"); herr == nil {
			code := resp.StatusCode
			server := resp.Header.Get("Server")
			_ = resp.Body.Close()
			detail := fmt.Sprintf("GET /admin/ → HTTP %d", code)
			if server != "" {
				detail += "; Server: " + server
			}
			switch {
			case code == 200 || code == 301 || code == 302:
				res.step("webadmin", "Веб-админка Kerio", "ok", detail, "")
			case code == 404:
				res.step("webadmin", "Веб-админка Kerio", "warn", detail,
					"Страница /admin/ не найдена. Проверьте порт: Kerio Connect — 4040, Kerio Control — 4081, Kerio Operator — 4021.")
				res.cause(kerioAuthCause("wrong-product"))
			default:
				res.step("webadmin", "Веб-админка Kerio", "warn", detail,
					"Сервер отвечает нестандартно — возможно, это не Kerio Connect или перед ним reverse-proxy.")
			}
		} else {
			res.step("webadmin", "Веб-админка Kerio", "warn", "не удалось открыть /admin/: "+herr.Error(), "")
		}
	}

	// --- 6. Вход по вариантам логина ---------------------------------------
	cli := NewKerioClient(ep)
	var lastErr error
	loggedIn := false
	for _, u := range kerioLoginVariants(res.User, req.Domain) {
		token, aerr := cli.loginOnce(u, req.Password)
		if aerr != nil {
			lastErr = aerr
			att := KerioAuthAttempt{Login: u, OK: false, ErrorKind: kerioErrKind(aerr), Error: aerr.Error(), Fix: kerioErrFix(aerr)}
			if looksLikeEmail(u) {
				att.Note = "Вариант с доменом в логине — для дополнительных администраторов Kerio."
			}
			res.Attempts = append(res.Attempts, att)
			if kerioErrKind(aerr) == "auth" {
				continue // возможно, нужен формат user@domain — пробуем дальше
			}
			break // 2FA, блокировка, права и т. п. — дальше перебирать бессмысленно
		}
		att := KerioAuthAttempt{Login: u, OK: true, Note: "Вход выполнен, получен X-Token."}
		if !strings.EqualFold(u, res.User) {
			att.Note = fmt.Sprintf("Вошли как «%s» (введённый логин «%s» Kerio не принял).", u, res.User)
		}
		res.Attempts = append(res.Attempts, att)
		cli.Token, cli.User = token, u
		res.LoginUser = u
		loggedIn = true
		break
	}

	if !loggedIn {
		err := lastErr
		if err == nil {
			err = kerioErr("auth", "Session.login", "Kerio не принял логин и пароль", "")
		}
		kind := kerioErrKind(err)
		res.step("login", "Вход администратора (Session.login)", "fail", err.Error(), kerioErrFix(err))
		// Причины: сначала по типу ошибки, затем — общие подсказки.
		res.cause(kerioAuthCause(kind))
		if kind == "auth" {
			res.cause(kerioAuthCause("auth-common"))
		}
		res.finalize(started)
		return res
	}

	res.step("login", "Вход администратора (Session.login)", "ok",
		fmt.Sprintf("Успешный вход: «%s». Kerio вернул X-Token (%d символов) и cookie сессии.", res.LoginUser, len(cli.Token)), "")

	// --- 7. Сессия: token + cookie (ловит прокси, режущий cookie) -----------
	res.TokenLen = len(cli.Token)
	res.TokenMasked = maskToken(cli.Token)
	if u, perr := url.Parse(ep.RPCURL()); perr == nil {
		for _, ck := range cli.client.Jar.Cookies(u) {
			if strings.Contains(strings.ToUpper(ck.Name), "SESSION") {
				res.CookieOK = true
				break
			}
		}
	}
	res.SessionOK = res.TokenLen > 0
	if !res.CookieOK {
		res.SessionNote = "Kerio не вернул cookie SESSION_CONNECT_WEBADMIN — сессия может оборваться на следующем запросе (прокси/антивирус вырезает cookie)."
		res.step("session", "Сессия (X-Token + cookie)", "warn", res.SessionNote,
			"Проверьте, что между программой и Kerio нет прокси, который фильтрует заголовки. Вход обычно всё равно работает.")
		res.cause(kerioAuthCause("cookie"))
	} else {
		res.step("session", "Сессия (X-Token + cookie)", "ok",
			"X-Token: "+res.TokenMasked+" …; cookie SESSION_CONNECT_WEBADMIN получен.", "")
	}

	// --- 8. Права администратора -------------------------------------------
	if who, werr := cli.WhoAmI(); werr == nil {
		res.LoginUser = firstNonEmpty(who.LoginName, res.LoginUser)
		res.FullName = who.FullName
		res.Role = who.Role
		res.IsAdmin = who.IsAdmin
		if who.IsAdmin {
			role := firstNonEmpty(who.Role, "admin")
			res.step("rights", "Права администратора", "ok",
				fmt.Sprintf("Роль: %s. Полные права администратора подтверждены.", role), "")
		} else if strings.TrimSpace(who.Role) == "" && strings.TrimSpace(who.LoginName) == "" {
			res.step("rights", "Права администратора", "warn",
				"Kerio не сообщил роль (Session.whoAmI недоступен в этой сборке) — права проверим на списке сертификатов.", "")
		} else {
			res.step("rights", "Права администратора", "fail",
				fmt.Sprintf("Учётка «%s» вошла, но роль «%s» не административная.", who.LoginName, firstNonEmpty(who.Role, "неизвестна")),
				"1) Kerio Connect → Configuration → Administration → Administrators — добавьте учётку.\n"+
					"2) Используйте мастер-администратора (обычно admin), а не пользователя домена.\n"+
					"3) Делегированный администратор без права на SSL-сертификаты не сможет их устанавливать.")
			res.cause(kerioAuthCause("rights"))
		}
	} else {
		res.step("rights", "Права администратора", "warn", "не удалось вызвать Session.whoAmI: "+werr.Error(), "")
	}

	// --- 9. Версия продукта -------------------------------------------------
	if pv, verr := cli.ProductVersion(); verr == nil {
		res.Product = firstNonEmpty(strings.TrimSpace(pv.Product), "Kerio Connect")
		res.Version = pv.Version
		res.APIVersion = pv.APIVersion
		status, fix := "ok", ""
		if !strings.Contains(strings.ToLower(res.Product), "connect") {
			status = "warn"
			fix = "Обнаружен продукт «" + res.Product + "». Программа рассчитана на Kerio Connect (4040); для Kerio Control используйте 4081."
			res.cause(kerioAuthCause("wrong-product"))
		}
		res.step("version", "Версия продукта", status,
			fmt.Sprintf("%s %s (API v%d)", res.Product, res.Version, pv.APIVersion), fix)
	} else {
		res.step("version", "Версия продукта", "warn", "не удалось получить версию: "+verr.Error(), "")
	}

	// --- 10. Права на сертификаты (реальная проверка, а не «на словах») -----
	if req.ProbeCerts {
		res.CertsChecked = true
		if certs, iface, cerr := cli.ListCertificates(); cerr != nil {
			res.CertsInterface = iface
			res.CertsError = cerr.Error()
			res.step("certs", "Доступ к SSL-сертификатам ("+iface+".get)", "fail", cerr.Error(), kerioErrFix(cerr))
			res.cause(kerioAuthCause("certs"))
		} else {
			res.CanManageCerts = true
			res.CertsInterface = iface
			res.CertsCount = len(certs)
			res.step("certs", "Доступ к SSL-сертификатам ("+iface+".get)", "ok",
				fmt.Sprintf("Список сертификатов прочитан: %d шт. Значит, вход подходит и для установки сертификатов.", len(certs)), "")
		}
	} else {
		res.step("certs", "Доступ к SSL-сертификатам", "skip",
			"Проверка списка сертификатов отключена галочкой в карточке.", "")
	}

	cli.Logout()
	res.OK = true
	for _, c := range res.Checks {
		if c.Status == "fail" {
			res.OK = false
		}
	}
	res.finalize(started)
	return res
}

// finalize собирает итоговый вердикт и краткое резюме.
func (r *KerioAuthResult) finalize(started time.Time) {
	r.ElapsedMS = time.Since(started).Milliseconds()

	loginOK := false
	for _, c := range r.Checks {
		if c.Key == "login" && c.Status == "ok" {
			loginOK = true
		}
	}

	var blockCause *KerioAuthCause
	for i := range r.Causes {
		if r.Causes[i].Severity == "block" {
			blockCause = &r.Causes[i]
			break
		}
	}

	switch {
	case loginOK && r.OK:
		role := firstNonEmpty(r.Role, "администратор")
		prod := strings.TrimSpace(r.Product + " " + r.Version)
		r.Verdict = fmt.Sprintf("✅ Вход выполнен: %s (%s). Пароль администратора верный.", r.LoginUser, role)
		if prod != "" {
			r.Verdict += " Сервер: " + prod + "."
		}
		if r.CertsChecked && r.CanManageCerts {
			r.Verdict += fmt.Sprintf(" Права на сертификаты есть (видно %d).", r.CertsCount)
		}
	case loginOK && !r.OK:
		r.Verdict = "⚠️ Логин и пароль верные, но прав администратора или доступа к сертификатам не хватает — см. причины ниже."
		r.OK = false
	default:
		title := "вход не выполнен"
		if blockCause != nil {
			title = blockCause.Title
		}
		r.Verdict = "❌ Не удалось войти под администратором Kerio Connect: " + title + "."
		r.OK = false
	}

	// Короткое резюме для журнала и тоста.
	parts := []string{}
	if r.LoginUser != "" {
		parts = append(parts, "вошли как "+r.LoginUser)
	}
	if r.Role != "" {
		parts = append(parts, "роль "+r.Role)
	}
	if r.Version != "" {
		parts = append(parts, "Kerio "+r.Version)
	}
	if r.CertsChecked && r.CanManageCerts {
		parts = append(parts, fmt.Sprintf("сертификатов %d", r.CertsCount))
	}
	if len(parts) > 0 {
		r.Summary = strings.Join(parts, ", ")
	}
}

// maskPasswordHint не показывает пароль, но подсказывает, что с ним не так.
func maskPasswordHint(pw string) string {
	if strings.TrimSpace(pw) == "" {
		return "не указан"
	}
	n := len([]rune(pw))
	kind := "только латиница/цифры"
	if hasNonASCII(pw) {
		kind = "есть нелатинские символы"
	}
	return fmt.Sprintf("указан (%d симв., %s), в файлы не сохраняется", n, kind)
}

// ---------------------------------------------------------------------------
// База причин: что именно сказать администратору и что ему сделать
// ---------------------------------------------------------------------------

func kerioAuthCause(code string) KerioAuthCause {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "empty-password":
		return KerioAuthCause{
			Code: "empty-password", Title: "Пароль не введён", Severity: "block",
			Explanation: "Kerio не принимает пустой пароль, поэтому проверять нечего — даже не подключались к серверу.",
			Steps: []string{
				"Введите пароль администратора Kerio Connect в поле карточки — программа его не сохраняет и никуда не отправляет, кроме самого Kerio.",
				"Пароль тот же, что вы вводите на https://<сервер>:4040/admin/.",
				"Если пароль хранится в менеджере паролей — вставляйте его, а не набирайте руками.",
			},
		}
	case "spaces-in-password":
		return KerioAuthCause{
			Code: "spaces-in-password", Title: "Пробелы в начале или конце пароля", Severity: "warn",
			Explanation: "При копировании пароля из письма, чата или веб-страницы легко захватить пробел — для Kerio это уже другой пароль.",
			Steps: []string{
				"Удалите пробелы по краям пароля и повторите проверку.",
				"Если пароль вводился копированием — попробуйте набрать последние 3 символа вручную (проверка раскладки).",
				"Посмотрите на длину пароля в подсказке под полем: лишний символ сразу видно по числу знаков.",
			},
		}
	case "email-as-admin":
		return KerioAuthCause{
			Code: "email-as-admin", Title: "Вход выполняется почтовым ящиком, а не администратором", Severity: "warn",
			Explanation: "В Kerio Connect это разные вещи: обычный ящик (info@company.by) не имеет доступа к админке :4040.",
			Steps: []string{
				"Откройте Kerio WebAdmin → Configuration → Administration → Administrators и посмотрите список администраторов.",
				"Используйте логин из первой колонки (обычно admin или короткое имя вида kerioapi).",
				"Дополнительный администратор входит как user@domain только если он создан в списке администраторов, а не как почтовый ящик.",
				"Если нужного администратора нет — создайте отдельную учётку без 2FA (Configuration → Administration → Administrators → Add).",
			},
			CheckWhere: "Kerio WebAdmin → Configuration → Administration → Administrators",
		}
	case "non-ascii-password":
		return KerioAuthCause{
			Code: "non-ascii-password", Title: "В пароле есть нелатинские символы", Severity: "warn",
			Explanation: "Старые сборки Kerio и промежуточные прокси иногда искажают национальные символы в пароле.",
			Steps: []string{
				"Если вход не проходит — временно смените пароль администратора на латиницу с цифрами и спецсимволами.",
				"После проверки смените пароль обратно, если это требует политика безопасности.",
				"Проверьте, что пароль набирается в той же языковой раскладке, в которой задавался.",
			},
		}
	case "auth":
		return KerioAuthCause{
			Code: "auth", Title: "Неверный логин или пароль администратора", Severity: "block",
			Explanation: "Kerio дошёл до проверки учётных данных и отклонил их (ответ Invalid user name or password). Сервер доступен, дело именно в паре логин/пароль.",
			Steps: []string{
				"Проверьте тот же пароль в браузере: откройте https://<сервер>:4040/admin/ и войдите вручную. Если вход не проходит и там — восстановите пароль администратора Kerio.",
				"Проверьте раскладку клавиатуры и Caps Lock: пароль чувствителен к регистру.",
				"Попробуйте логин admin без домена, а если учётка дополнительная — в формате user@домен.",
				"Убедитесь, что вводится пароль Kerio Connect, а не домена Active Directory и не пароль почтового ящика.",
				"Скопируйте пароль из менеджера паролей заново: «лишний» символ в конце — самая частая причина.",
			},
			CheckWhere: "https://<сервер>:4040/admin/ — вход в веб-админку тем же паролем",
		}
	case "auth-common":
		return KerioAuthCause{
			Code: "auth-common", Title: "Если пароль точно верный — где искать причину", Severity: "warn",
			Explanation: "Иногда Kerio отвечает «неверный пароль» и в других случаях: заблокированная учётка, устаревшая сессия, ограничение по IP.",
			Steps: []string{
				"Посмотрите журнал безопасности Kerio: WebAdmin → Logs → Security (там видно причину отказа и IP).",
				"Проверьте, не задано ли для администратора ограничение «разрешённые IP-адреса» в его свойствах.",
				"Подождите 10–30 минут после нескольких неудачных попыток: Kerio включает защиту от подбора.",
				"Если администраторов несколько и вход нужен для автоматизации — создайте отдельную учётку для API без 2FA.",
			},
			CheckWhere: "Kerio WebAdmin → Logs → Security",
		}
	case "otp":
		return KerioAuthCause{
			Code: "otp", Title: "У администратора включена двухфакторная аутентификация (2FA)", Severity: "block",
			Explanation: "JSON-RPC Admin API Kerio не умеет принимать одноразовый код, поэтому вход с 2FA из программы " +
				"невозможен — даже с верным паролем. Нужна учётка без 2FA.",
			Steps: []string{
				"Создайте отдельную учётку для программы: в веб-админке https://<сервер>:4040/admin/ откройте " +
					"Accounts → Users → Add, задайте имя (например kerioapi) и пароль.",
				"В её свойствах откройте вкладку Rights и в разделе «Server administration» выберите " +
					"Whole server read/write → OK. Без этого установка сертификатов через API не сработает.",
				"Не включайте для этой учётки двухфакторную аутентификацию: настройка 2FA находится в клиенте " +
					"Kerio Connect (Settings → Two-factor authentication) — для служебной учётки оставьте её выключенной.",
				"Укажите в карточке логин вида kerioapi@ваш.домен и пароль этой учётки вместо личной.",
			},
			CheckWhere: "Kerio WebAdmin → Accounts → Users → служебная учётка → Rights; 2FA — в клиенте Kerio Connect, Settings",
			Anchor:     "461-вход-есть-а-ssl-сертификаты-не-читаются",
		}
	case "rights":
		return KerioAuthCause{
			Code: "rights", Title: "Учётка не является администратором Kerio Connect", Severity: "block",
			Explanation: "Пароль подошёл, но Kerio считает эту учётную запись обычным пользователем: " +
				"административных прав у неё нет вовсе, поэтому в админке ей доступен только собственный ящик.",
			Steps: []string{
				"Откройте веб-админку https://<сервер>:4040/admin/ и войдите любой учёткой с полными правами.",
				"Accounts → Users → двойной клик по нужной учётке → вкладка Rights → в разделе «Server administration» " +
					"выберите Whole server read/write → OK. Права действуют сразу, перезапуск Kerio не нужен.",
				"Если эта учётка — обычный почтовый ящик и админом быть не должна, заведите отдельную: " +
					"Accounts → Users → Add → имя kerioapi и пароль → вкладка Rights → Whole server read/write → OK.",
				"Повторите проверку в программе — в отчёте роль должна стать «administrator».",
			},
			CheckWhere: "Kerio WebAdmin → Accounts → Users → учётка → вкладка Rights → Server administration",
			Anchor:     "461-вход-есть-а-ssl-сертификаты-не-читаются",
		}
	case "locked":
		return KerioAuthCause{
			Code: "locked", Title: "Kerio временно блокирует вход (защита от подбора)", Severity: "block",
			Explanation: "После нескольких неудачных попыток Kerio Connect блокирует вход с этого IP-адреса на время. Пароль при этом может быть уже верным.",
			Steps: []string{
				"Подождите 10–30 минут и повторите проверку (Kerio снимает блокировку автоматически).",
				"Не нажимайте «Проверить вход» подряд много раз — каждая неудача продлевает блокировку.",
				"Посмотрите IpBanList: WebAdmin → Configuration → Security → IP Addresses (или Logs → Security).",
				"Если блокировка сработала из-за чужого IP — смените пароль администратора и проверьте журналы на попытки подбора.",
			},
			CheckWhere: "Kerio WebAdmin → Configuration → Security / Logs → Security",
		}
	case "dns":
		return KerioAuthCause{
			Code: "dns", Title: "Имя сервера не найдено в DNS", Severity: "block",
			Explanation: "Компьютер не знает, по какому IP искать Kerio Connect: сервер недоступен ещё до попытки входа.",
			Steps: []string{
				"Подставьте IP-адрес сервера вместо имени — так проверка не зависит от DNS.",
				"Проверьте разрешение имени командой `nslookup <имя>`: в ответе должен быть внутренний адрес.",
				"Для внутренних имён убедитесь, что включён VPN или используется внутренний DNS-сервер.",
			},
		}
	case "tcp":
		return KerioAuthCause{
			Code: "tcp", Title: "Порт Admin API недоступен", Severity: "block",
			Explanation: "Соединение по TCP не устанавливается: сервер не принял запрос. Логин и пароль проверить не удалось.",
			Steps: []string{
				"Откройте https://<сервер>:4040/admin/ в браузере на этом компьютере — страница должна открываться.",
				"Проверьте, что Kerio Connect запущен (Windows: служба KerioMailServer; Linux: systemctl status kerio-connect).",
				"Разрешите входящий TCP 4040 в файрволе сервера и не публикуйте его в интернет — работайте через VPN.",
			},
		}
	case "tls":
		return KerioAuthCause{
			Code: "tls", Title: "Защищённое соединение не устанавливается", Severity: "block",
			Explanation: "Порт открыт, но договориться о шифровании (TLS) не удалось — вероятно, на порту отвечает не Kerio.",
			Steps: []string{
				"Откройте https://<сервер>:4040/admin/ в браузере и посмотрите, тот ли это продукт Kerio.",
				"Отключите проверку HTTPS (SSL inspection) в антивирусе/файрволе для внутренней сети.",
				"Включите TLS 1.2 в Kerio: Configuration → SSL Certificates.",
			},
		}
	case "cookie":
		return KerioAuthCause{
			Code: "cookie", Title: "Прокси вырезает cookie сессии", Severity: "warn",
			Explanation: "Kerio выдал токен, но cookie SESSION_CONNECT_WEBADMIN не дошёл — обычно так делает прокси, антивирус с проверкой HTTPS или фильтр на стороне шлюза.",
			Steps: []string{
				"Отключите проверку HTTPS (SSL inspection) в антивирусе для адреса сервера Kerio.",
				"Если между компьютером и Kerio есть прокси — добавьте адрес сервера в исключения (Kerio Admin API не должен проходить через фильтры).",
				"Проверьте работу без прокси: временно запустите программу на самом сервере Kerio с адресом 127.0.0.1.",
			},
		}
	case "certs":
		return KerioAuthCause{
			Code: "certs", Title: "Учётка вошла, но у неё нет прав на SSL-сертификаты", Severity: "block",
			Explanation: "Пароль верный — Kerio пустил вас в админку. Отказ пришёл позже, на чтении списка " +
				"сертификатов: у этой учётной записи уровень доступа ниже «весь сервер, чтение и запись». " +
				"Так бывает у администратора домена и у обычного почтового ящика — почтой управляют, а SSL нет.",
			Steps: []string{
				"Самый быстрый способ — встроенная учётка Admin. Войдите в веб-админку https://<сервер>:4040/admin/, " +
					"откройте Configuration → Administration Settings, поставьте галочку «Enable built-in administrator account», " +
					"задайте пароль и нажмите Apply. В карточке укажите логин Admin и этот пароль: у встроенной учётки всегда " +
					"права «весь сервер, чтение и запись», и она не занимает лицензию.",
				"Или выдайте права своей учётке: Accounts → Users → двойной клик по учётке → вкладка Rights → " +
					"в разделе «Server administration» выберите Whole server read/write (не «<домен> accounts» и не " +
					"«Whole server read only») → OK. Перезапуск Kerio не нужен, права действуют сразу.",
				"Проверьте глазами: в веб-админке должен открываться раздел Configuration → SSL Certificates. " +
					"Если раздела нет или он пуст — прав на сервер у учётки всё ещё нет.",
				"Вернитесь в программу и нажмите «🔓 Проверить вход» ещё раз. В блоке «Что проверено» появится " +
					"«Сертификаты: доступ есть, найдено N», а в зелёной плашке — «права на сертификаты есть».",
				"Если полные права давать не хотите — устанавливайте сертификат файловым методом: скопируйте файлы " +
					"в папку sslcert прямо на сервере (раздел 4.1 инструкции), права администратора Kerio для этого не нужны. " +
					"Для Kerio Control (4081) и Kerio Operator (4021) API другой — эта программа их не настраивает.",
			},
			CheckWhere: "Kerio WebAdmin → Accounts → Users → ваша учётка → вкладка Rights → «Server administration» = Whole server read/write",
			Anchor:     "461-вход-есть-а-ssl-сертификаты-не-читаются",
		}
	case "wrong-product":
		return KerioAuthCause{
			Code: "wrong-product", Title: "Похоже, это не Kerio Connect", Severity: "warn",
			Explanation: "Порт отвечает, но набор методов или страница /admin/ не совпадают с Kerio Connect.",
			Steps: []string{
				"Проверьте номер порта: Kerio Connect — 4040, Kerio Control — 4081, Kerio Operator — 4021.",
				"Откройте https://<сервер>:<порт>/admin/ и посмотрите на заголовок страницы: там название продукта.",
				"Если перед Kerio стоит reverse-proxy, он должен проксировать /admin/api/jsonrpc/ без изменений.",
			},
		}
	case "protocol", "method":
		return KerioAuthCause{
			Code: "protocol", Title: "Сервер отвечает не по протоколу Admin API", Severity: "block",
			Explanation: "Ответ пришёл, но это не JSON-RPC Kerio Admin API: обычно так бывает при неверном адресе, редиректе на страницу входа или вмешательстве прокси.",
			Steps: []string{
				"Проверьте, что запросы идут на https://<сервер>:4040/admin/api/jsonrpc/ (именно этот путь).",
				"Откройте этот адрес в браузере: должно появиться сообщение об ошибке JSON-RPC, а не HTML-страница входа.",
				"Отключите на время проверки SSL-инспекцию антивируса и корпоративный прокси.",
			},
		}
	default:
		return KerioAuthCause{
			Code: "unknown", Title: "Вход не выполнен — что проверить по порядку", Severity: "block",
			Explanation: "Kerio не дал однозначной причины. Пройдите проверку сверху вниз — на каком шаге появится первая ошибка, там и причина.",
			Steps: []string{
				"Откройте https://<сервер>:4040/admin/ в браузере на этом компьютере и войдите вручную тем же логином и паролем.",
				"Если браузер тоже не пускает — проблема в учётке Kerio (пароль/права/2FA), а не в программе.",
				"Если браузер пускает, а программа нет — проверьте, что в поле адреса указан именно тот сервер и порт 4040.",
				"Запустите полную диагностику кнопкой «🩺 Диагностика подключения к Kerio» — она покажет шаг, на котором всё ломается.",
			},
			CheckWhere: "https://<сервер>:4040/admin/ — ручной вход тем же паролем",
		}
	}
}
