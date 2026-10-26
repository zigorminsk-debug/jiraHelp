package main

// lan_access.go — «Пульт» для Android: доступ к программе с телефона по Wi-Fi.
//
// Зачем отдельный слушатель. Основной интерфейс программы слушает только
// 127.0.0.1 (порт 17840) — снаружи к нему подключиться нельзя, и это
// правильно: через API можно выпускать сертификаты и менять настройки Kerio.
// Но телефону нужен доступ по локальной сети.
//
// Поэтому здесь второй, отдельный HTTP-слушатель на 0.0.0.0, и он:
//   - включается только по кнопке (по умолчанию всё закрыто);
//   - требует код доступа (6 цифр), который показывает программа на ПК;
//   - ставит cookie после первого входа с кодом, чтобы страница работала
//     как обычное приложение, без повторного ввода;
//   - пускает без кода только /api/ping (проверка «сервер жив»), чтобы
//     телефон мог найти программу в сети.
//
// Код не хранится на диске: при каждом включении пунта генерируется новый.
// Так утёкший код не работает после перезапуска программы.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	lanCookieName  = "kcm_lan_code"
	lanCodeHeader  = "X-KCM-Code"
	lanDefaultPort = 17840
)

// LanRemoteInfo — состояние пунта для интерфейса программы.
type LanRemoteInfo struct {
	Enabled   bool     `json:"enabled"`
	Code      string   `json:"code,omitempty"`
	Port      int      `json:"port,omitempty"`
	URLs      []string `json:"urls,omitempty"`
	StartedAt string   `json:"startedAt,omitempty"`
	Error     string   `json:"error,omitempty"`
	Hint      string   `json:"hint,omitempty"`
}

var (
	lanMu       sync.Mutex
	lanServer   *http.Server
	lanListener net.Listener
	lanCode     string
	lanPort     int
	lanStarted  time.Time
)

// newLanAccessCode генерирует 6 цифр — их легко продиктовать и ввести
// одной рукой на телефоне.
func newLanAccessCode() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Крайне маловероятно; всё равно не оставляем пустой код.
		return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return fmt.Sprintf("%06d", n%1000000)
}

// lanURLs перечисляет адреса, по которым телефон в той же сети увидит программу.
// Порядок: сначала «человеческие» сети (192.168.x, 10.x), потом остальные —
// так первая строка в интерфейсе почти всегда правильная.
func lanURLs(port int) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var private, other []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, aerr := iface.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			u := fmt.Sprintf("http://%s:%d/", ip4.String(), port)
			if ip4.IsPrivate() {
				private = append(private, u)
			} else {
				other = append(other, u)
			}
		}
	}
	sort.Strings(private)
	sort.Strings(other)
	return append(private, other...)
}

// StartLanRemote открывает пунт: слушатель на всех интерфейсах + код доступа.
// Повторный вызов возвращает уже запущенный пунт (идемпотентно).
func StartLanRemote(preferredPort int) (LanRemoteInfo, error) {
	lanMu.Lock()
	defer lanMu.Unlock()
	if lanServer != nil {
		return lanInfoLocked(), nil
	}
	if preferredPort <= 0 || preferredPort > 65535 {
		preferredPort = lanDefaultPort
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", preferredPort))
	if err != nil {
		// Порт занят (например, копией программы) — берём любой свободный.
		ln, err = net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			return LanRemoteInfo{Error: "не удалось открыть сетевой порт: " + err.Error()}, err
		}
	}

	code := newLanAccessCode()
	srv := &http.Server{
		Handler:           lanGuard(buildRouter(), code),
		ReadHeaderTimeout: 15 * time.Second,
	}

	lanServer, lanListener = srv, ln
	lanCode = code
	lanPort = ln.Addr().(*net.TCPAddr).Port
	lanStarted = time.Now()

	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			logHub.Emit("warning", "Пульт для телефона остановлен: "+serveErr.Error())
		}
	}()

	info := lanInfoLocked()
	logHub.Emit("success", fmt.Sprintf("Пульт для телефона включён: %s код %s",
		firstNonEmpty(info.URLs...), info.Code))
	return info, nil
}

// StopLanRemote закрывает пунт и забывает код.
func StopLanRemote() {
	lanMu.Lock()
	srv, ln := lanServer, lanListener
	lanServer, lanListener, lanCode, lanPort = nil, nil, "", 0
	lanStarted = time.Time{}
	lanMu.Unlock()

	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
	if ln != nil {
		_ = ln.Close()
	}
	logHub.Emit("info", "Пульт для телефона выключен: телефон больше не может подключиться к программе.")
}

// LanRemoteState — текущее состояние пунта (для интерфейса).
func LanRemoteState() LanRemoteInfo {
	lanMu.Lock()
	defer lanMu.Unlock()
	return lanInfoLocked()
}

// RefreshLanCode меняет код доступа, не выключая пунт: старый код сразу
// перестаёт работать, а уже открытая на телефоне страница продолжит работать
// только после повторного входа (cookie хранит старый код).
func RefreshLanCode() LanRemoteInfo {
	lanMu.Lock()
	defer lanMu.Unlock()
	if lanServer == nil {
		return lanInfoLocked()
	}
	lanCode = newLanAccessCode()
	logHub.Emit("info", "Код доступа для телефона изменён: "+lanCode)
	return lanInfoLocked()
}

func lanInfoLocked() LanRemoteInfo {
	if lanServer == nil {
		return LanRemoteInfo{
			Enabled: false,
			Hint:    "Нажмите «Включить пульт», чтобы телефон в той же сети Wi-Fi мог открыть программу.",
		}
	}
	return LanRemoteInfo{
		Enabled:   true,
		Code:      lanCode,
		Port:      lanPort,
		URLs:      lanURLs(lanPort),
		StartedAt: lanStarted.Format("15:04"),
		Hint: "Подключите телефон к той же сети Wi-Fi и введите адрес и код в приложении " +
			"KerioCertManager Mobile. Если Windows спросит про доступ к сети — разрешите для частных сетей.",
	}
}

// codeMatches сравнивает код за постоянное время: код — это фактически
// пароль к полному API программы.
func codeMatches(got, want string) bool {
	got, want = strings.TrimSpace(got), strings.TrimSpace(want)
	if want == "" || got == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// lanGuard — «шлюз» пунта: без кода не пускает никуда, кроме /api/ping.
func lanGuard(next http.Handler, code string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/ping":
			next.ServeHTTP(w, r)

		case codeMatches(r.Header.Get(lanCodeHeader), code):
			next.ServeHTTP(w, r)

		case hasLanCookie(r, code):
			next.ServeHTTP(w, r)

		case codeMatches(r.URL.Query().Get("code"), code):
			// Код в адресе — только для первого входа: ставим cookie и
			// убираем код из строки браузера, чтобы он не осел в истории.
			http.SetCookie(w, &http.Cookie{
				Name:     lanCookieName,
				Value:    code,
				Path:     "/",
				MaxAge:   7 * 24 * 3600,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			target := *r.URL
			q := target.Query()
			q.Del("code")
			target.RawQuery = q.Encode()
			http.Redirect(w, r, target.String(), http.StatusSeeOther)

		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(lanLoginPage(r.URL.Path)))
		}
	})
}

func hasLanCookie(r *http.Request, code string) bool {
	ck, err := r.Cookie(lanCookieName)
	if err != nil {
		return false
	}
	return codeMatches(ck.Value, code)
}

// lanLoginPage — страница ввода кода. Нужна, когда программу открыли в
// браузере телефона (или в WebView без кода), а не через приложение.
func lanLoginPage(path string) string {
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	return `<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KerioCertManager — код доступа</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
 background:#0b1220;color:#e2e8f0;font:16px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;padding:24px}
.card{width:100%;max-width:380px;background:#131c2e;border:1px solid #253048;border-radius:16px;padding:22px}
h1{font-size:18px;margin:0 0 6px}
p{color:#93a4c3;font-size:13.5px;margin:0 0 16px}
input{width:100%;box-sizing:border-box;padding:14px;border-radius:10px;border:1px solid #2c3a55;
 background:#0f172a;color:#e2e8f0;font-size:22px;letter-spacing:6px;text-align:center}
button{width:100%;margin-top:12px;padding:14px;border:0;border-radius:10px;background:#2563eb;color:#fff;
 font-size:15px;font-weight:700}
small{display:block;margin-top:14px;color:#64748b;font-size:12px}
</style></head><body><form class="card" method="get" action="` + html.EscapeString(path) + `">
<h1>📱 KerioCertManager</h1>
<p>Введите код доступа из 6 цифр — он показан в программе на компьютере
в карточке «Android-пульт».</p>
<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000" autofocus>
<button type="submit">Открыть программу</button>
<small>Код действует, пока включён пульт. Выключите его на компьютере, когда закончите.</small>
</form></body></html>`
}

// ---------------------------------------------------------------------------
// HTTP-маршруты для интерфейса
// ---------------------------------------------------------------------------

func registerLanRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/mobile/remote", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "remote": LanRemoteState()})
	})

	mux.HandleFunc("/api/mobile/remote/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		var body struct {
			Port int `json:"port"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		info, err := StartLanRemote(body.Port)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error(), "remote": info})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "remote": info})
	})

	mux.HandleFunc("/api/mobile/remote/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		StopLanRemote()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "remote": LanRemoteState()})
	})

	mux.HandleFunc("/api/mobile/remote/code", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "remote": RefreshLanCode()})
	})
}

// hexCode — вспомогательная функция для тестов: превращает случайные байты
// в строку без неоднозначных символов.
func hexCode(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }
