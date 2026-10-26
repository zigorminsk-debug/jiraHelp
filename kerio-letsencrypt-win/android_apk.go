package main

// android_apk.go — «Скачать APK для телефона» на вкладке установки в Kerio.
//
// Зачем: приложение для Android лежит в релизах GitHub, и чтобы поставить его
// на телефон, администратору приходится искать релиз в браузере. Здесь одна
// кнопка: программа спрашивает GitHub, скачивает APK последней версии рядом
// с программой (или в «Загрузки»), показывает имя файла, размер и SHA-256 и
// открывает папку — дальше файл перекидывается на телефон любым способом.
//
// Дополнительно, если включён «Android-пульт», телефон в той же сети может
// скачать файл напрямую с компьютера: GET /api/mobile/apk (код доступа —
// тот же, что и для пульта).
//
// Важные решения:
//   - источник — только официальные релизы этого репозитория;
//   - берётся релиз с тегом vX.Y.Z (служебные kerio-latest и antispam-db-latest
//     игнорируются, иначе можно скачать не то);
//   - файл проверяется по двум признакам: он действительно APK (ZIP, «PK») и,
//     если GitHub отдал digest, совпадает SHA-256;
//   - список релизов кэшируется на 10 минут, чтобы кнопка не упиралась в
//     ограничение GitHub по частоте запросов.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// androidApkMaxSize — предохранитель: APK сейчас ~40 КБ, но пусть будет запас.
const androidApkMaxSize = 60 << 20

// androidApkRemoteTTL — как долго помним ответ GitHub про последний релиз.
const androidApkRemoteTTL = 10 * time.Minute

var androidApkNameRe = regexp.MustCompile(`(?i)^keriocertmanager-mobile-.*\.apk$`)

// AndroidApkState — состояние кнопки (уходит в интерфейс как JSON).
type AndroidApkState struct {
	OK             bool   `json:"ok"`
	MobileVersion  string `json:"mobileVersion"`
	DesktopVersion string `json:"desktopVersion"`
	Size           int64  `json:"size"`
	DownloadURL    string `json:"downloadUrl"`
	PageURL        string `json:"pageUrl"`
	Downloaded     bool   `json:"downloaded"`
	FileSeen       bool   `json:"fileSeen"`
	FilePath       string `json:"filePath"`
	FileName       string `json:"fileName"`
	FileSize       int64  `json:"fileSize"`
	FileSHA256     string `json:"fileSha256"`
	SavedAt        string `json:"savedAt"`
	Folder         string `json:"folder"`
	PhoneURL       string `json:"phoneUrl"`
	Message        string `json:"message,omitempty"`
	Error          string `json:"error,omitempty"`
}

var (
	androidApkMu       sync.Mutex
	androidApkCached   AndroidApkState
	androidApkCachedAt time.Time
)

// androidApkDir — куда складывать APK. «Загрузки» понятнее для человека,
// а если их нет — папка программы.
func androidApkDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		downloads := filepath.Join(home, "Downloads")
		if st, serr := os.Stat(downloads); serr == nil && st.IsDir() {
			return downloads
		}
	}
	dir := filepath.Join(DefaultCertsRoot(), "android")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// pickAndroidApkAsset ищет APK-файл в релизе.
func pickAndroidApkAsset(rel *githubRelease) (githubAsset, bool) {
	for _, a := range rel.Assets {
		if androidApkNameRe.MatchString(strings.TrimSpace(a.Name)) {
			return a, true
		}
	}
	return githubAsset{}, false
}

// pickNewestAndroidRelease — самый свежий релиз, в котором есть APK.
// Просто «последний релиз» не подходит: в репозитории бывают релизы без
// мобильного файла.
func pickNewestAndroidRelease(releases []githubRelease) (*githubRelease, githubAsset, bool) {
	var best *githubRelease
	var bestAsset githubAsset
	var bestVer [3]int
	for i := range releases {
		rel := &releases[i]
		if rel.Draft || rel.Prerelease {
			continue
		}
		maj, min, pat, ok := parseVersion(rel.TagName)
		if !ok {
			continue // kerio-latest, antispam-db-latest и прочие служебные теги
		}
		asset, hasAPK := pickAndroidApkAsset(rel)
		if !hasAPK {
			continue
		}
		ver := [3]int{maj, min, pat}
		if best == nil || greater3(ver, bestVer) {
			best, bestAsset, bestVer = rel, asset, ver
		}
	}
	if best == nil {
		return nil, githubAsset{}, false
	}
	return best, bestAsset, true
}

// fetchAndroidApkRelease спрашивает GitHub про последний релиз с APK.
func fetchAndroidApkRelease(ctx context.Context) (*githubRelease, githubAsset, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updateAPIURL(), nil)
	if err != nil {
		return nil, githubAsset{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "KerioCertManager/"+appVersion+" (Windows)")

	resp, err := updateHTTPClient().Do(req)
	if err != nil {
		return nil, githubAsset{}, fmt.Errorf("нет связи с GitHub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, githubAsset{}, fmt.Errorf("GitHub временно ограничил запросы (HTTP %d) — повторите позже", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, githubAsset{}, fmt.Errorf("GitHub ответил HTTP %d", resp.StatusCode)
	}

	var releases []githubRelease
	if err := decodeJSONLimited(resp.Body, &releases); err != nil {
		return nil, githubAsset{}, fmt.Errorf("не удалось разобрать ответ GitHub: %w", err)
	}
	rel, asset, ok := pickNewestAndroidRelease(releases)
	if !ok {
		return nil, githubAsset{}, fmt.Errorf("в релизах пока нет файла приложения для Android")
	}
	return rel, asset, nil
}

// findDownloadedApk ищет уже скачанный APK и считает его SHA-256.
func findDownloadedApk(dir string) (string, int64, string, string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", 0, "", ""
	}
	var bestPath string
	var bestTime time.Time
	for _, e := range entries {
		if e.IsDir() || !androidApkNameRe.MatchString(e.Name()) {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		if info.ModTime().After(bestTime) {
			bestTime, bestPath = info.ModTime(), filepath.Join(dir, e.Name())
		}
	}
	if bestPath == "" {
		return "", 0, "", ""
	}
	st, serr := os.Stat(bestPath)
	if serr != nil {
		return "", 0, "", ""
	}
	sum, herr := sha256File(bestPath)
	if herr != nil {
		sum = ""
	}
	return bestPath, st.Size(), sum, st.ModTime().Format("2006-01-02 15:04")
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// phoneDownloadURL — адрес, по которому телефон в той же сети скачает APK
// прямо с компьютера (только пока включён пульт).
func phoneDownloadURL() string {
	info := LanRemoteState()
	if !info.Enabled || len(info.URLs) == 0 {
		return ""
	}
	base := strings.TrimSuffix(info.URLs[0], "/")
	return base + "/api/mobile/apk?code=" + info.Code
}

// AndroidApkStatus собирает состояние для интерфейса. Сеть спрашивается не
// чаще, чем раз в 10 минут (кроме force).
func AndroidApkStatus(ctx context.Context, force bool) AndroidApkState {
	androidApkMu.Lock()
	cached, cachedAt := androidApkCached, androidApkCachedAt
	androidApkMu.Unlock()

	state := cached
	if force || state.MobileVersion == "" || time.Since(cachedAt) > androidApkRemoteTTL {
		rel, asset, err := fetchAndroidApkRelease(ctx)
		if err != nil {
			state = AndroidApkState{OK: false, Error: err.Error()}
		} else {
			state = AndroidApkState{
				OK:             true,
				MobileVersion:  strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v"),
				DesktopVersion: appVersion,
				Size:           asset.Size,
				DownloadURL:    asset.URL,
				PageURL:        rel.HTMLURL,
			}
		}
		androidApkMu.Lock()
		androidApkCached, androidApkCachedAt = state, time.Now()
		androidApkMu.Unlock()
	}

	state.DesktopVersion = appVersion
	state.Folder = androidApkDir()
	path, size, sum, savedAt := findDownloadedApk(state.Folder)
	if path != "" {
		state.FileSeen = true
		state.FilePath = path
		state.FileName = filepath.Base(path)
		state.FileSize = size
		state.FileSHA256 = sum
		state.SavedAt = savedAt
	}
	state.Downloaded = state.FileSeen
	state.PhoneURL = phoneDownloadURL()
	return state
}

// DownloadAndroidApk скачивает APK последней версии и возвращает состояние.
func DownloadAndroidApk(ctx context.Context) (AndroidApkState, error) {
	rel, asset, err := fetchAndroidApkRelease(ctx)
	if err != nil {
		return AndroidApkState{OK: false, Error: err.Error()}, err
	}

	dir := androidApkDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return AndroidApkState{OK: false, Error: err.Error()}, fmt.Errorf("не удалось создать папку для APK: %w", err)
	}
	dest := filepath.Join(dir, asset.Name)

	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if rerr != nil {
		return AndroidApkState{OK: false, Error: rerr.Error()}, rerr
	}
	req.Header.Set("User-Agent", "KerioCertManager/"+appVersion+" (Windows)")

	resp, derr := updateHTTPClient().Do(req)
	if derr != nil {
		return AndroidApkState{OK: false, Error: derr.Error()}, fmt.Errorf("не удалось скачать APK: %w", derr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("сервер отдал HTTP %d вместо файла", resp.StatusCode)
		return AndroidApkState{OK: false, Error: msg}, fmt.Errorf("%s", msg)
	}
	if resp.ContentLength > androidApkMaxSize {
		msg := fmt.Sprintf("файл слишком большой (%d байт)", resp.ContentLength)
		return AndroidApkState{OK: false, Error: msg}, fmt.Errorf("%s", msg)
	}

	tmp := dest + ".part"
	out, oerr := os.Create(tmp)
	if oerr != nil {
		return AndroidApkState{OK: false, Error: oerr.Error()}, fmt.Errorf("не удалось создать файл: %w", oerr)
	}
	h := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, androidApkMaxSize+1))
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return AndroidApkState{OK: false, Error: copyErr.Error()}, fmt.Errorf("ошибка загрузки: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return AndroidApkState{OK: false, Error: closeErr.Error()}, fmt.Errorf("ошибка записи: %w", closeErr)
	}
	if written > androidApkMaxSize {
		_ = os.Remove(tmp)
		msg := "файл больше допустимого размера"
		return AndroidApkState{OK: false, Error: msg}, fmt.Errorf("%s", msg)
	}

	// APK — это ZIP-архив, он всегда начинается с «PK».
	head := make([]byte, 2)
	if f, ferr := os.Open(tmp); ferr == nil {
		_, _ = f.Read(head)
		_ = f.Close()
	}
	if string(head) != "PK" {
		_ = os.Remove(tmp)
		msg := "скачанный файл не похож на APK — загрузка отменена"
		return AndroidApkState{OK: false, Error: msg}, fmt.Errorf("%s", msg)
	}

	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return AndroidApkState{OK: false, Error: err.Error()}, fmt.Errorf("не удалось сохранить APK: %w", err)
	}

	sum := hex.EncodeToString(h.Sum(nil))
	expected := sha256FromDigest(asset.Digest)
	if expected != "" && !strings.EqualFold(sum, expected) {
		_ = os.Remove(dest)
		msg := fmt.Sprintf("SHA-256 не совпал: получено %s, ожидалось %s — файл удалён", sum[:16], expected[:16])
		return AndroidApkState{OK: false, Error: msg}, fmt.Errorf("%s", msg)
	}

	androidApkMu.Lock()
	androidApkCachedAt = time.Time{} // в следующий раз перечитаем с GitHub
	androidApkMu.Unlock()

	logHub.Emit("success", fmt.Sprintf("APK для телефона сохранён: %s (%s)", dest, humanSize(int64(written))))

	state := AndroidApkState{
		OK:             true,
		MobileVersion:  strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v"),
		DesktopVersion: appVersion,
		Size:           asset.Size,
		DownloadURL:    asset.URL,
		PageURL:        rel.HTMLURL,
		Folder:         dir,
		FilePath:       dest,
		FileName:       filepath.Base(dest),
		FileSize:       int64(written),
		FileSHA256:     sum,
		FileSeen:       true,
		Downloaded:     true,
		SavedAt:        time.Now().Format("2006-01-02 15:04"),
		PhoneURL:       phoneDownloadURL(),
		Message:        "APK сохранён. Перекиньте файл на телефон и откройте его — Android предложит установку.",
	}
	return state, nil
}

// OpenAndroidApkFolder открывает проводник с выделенным APK.
func OpenAndroidApkFolder() error {
	dir := androidApkDir()
	path, _, _, _ := findDownloadedApk(dir)
	switch runtime.GOOS {
	case "windows":
		if path != "" {
			return exec.Command("explorer.exe", "/select,", path).Start()
		}
		return exec.Command("explorer.exe", dir).Start()
	case "darwin":
		if path != "" {
			return exec.Command("open", "-R", path).Start()
		}
		return exec.Command("open", dir).Start()
	default:
		return exec.Command("xdg-open", dir).Start()
	}
}

// humanSize — «41,4 КБ» для сообщений в интерфейсе и журнале.
func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f МБ", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f КБ", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d Б", n)
	}
}

// ---------------------------------------------------------------------------
// HTTP-маршруты
// ---------------------------------------------------------------------------

func registerAndroidApkRoutes(mux *http.ServeMux) {
	// GET /api/android/apk — что за версия и есть ли уже скачанный файл.
	mux.HandleFunc("/api/android/apk", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		force := r.URL.Query().Get("force") != ""
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		state := AndroidApkStatus(ctx, force)
		writeJSON(w, http.StatusOK, map[string]any{"ok": state.OK, "apk": state})
	})

	// POST /api/android/apk/download — скачать APK последней версии.
	mux.HandleFunc("/api/android/apk/download", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		logHub.Emit("info", "Скачиваю APK приложения для Android с GitHub…")
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		state, err := DownloadAndroidApk(ctx)
		if err != nil {
			logHub.Emit("error", "APK не скачан: "+err.Error())
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error(), "apk": state})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "apk": state, "message": state.Message})
	})

	// POST /api/android/apk/open — показать файл в проводнике.
	mux.HandleFunc("/api/android/apk/open", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		if err := OpenAndroidApkFolder(); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("не удалось открыть папку: %w", err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "folder": androidApkDir()})
	})

	// GET /api/mobile/apk — отдать APK телефону в той же сети.
	// Маршрут попадает под код доступа пульта (lanGuard), поэтому без кода
	// файл не скачать.
	mux.HandleFunc("/api/mobile/apk", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		path, _, _, _ := findDownloadedApk(androidApkDir())
		if path == "" {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"ok":    false,
				"error": "APK ещё не скачан на компьютере — нажмите «Скачать APK» в программе.",
			})
			return
		}
		w.Header().Set("Content-Type", "application/vnd.android.package-archive")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(path)+"\"")
		http.ServeFile(w, r, path)
	})
}

// decodeJSONLimited — разбор JSON с ограничением размера ответа.
func decodeJSONLimited(body io.Reader, v any) error {
	return json.NewDecoder(io.LimitReader(body, 8<<20)).Decode(v)
}
