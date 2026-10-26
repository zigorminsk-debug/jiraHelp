package main

// updater.go — проверка и установка обновлений программы.
//
// Зачем: программа живёт на серверах, где её никто не открывает «просто так»,
// поэтому о новой версии нужно узнавать самим. При запуске (не чаще раза в
// несколько часов) программа спрашивает GitHub-релизы этого репозитория,
// сравнивает версии и, если появилась новая, показывает в шапке заметную
// плашку «Доступно обновление». Установка — одна кнопка: скачать, сверить
// SHA-256 с тем, что отдал GitHub, подменить файл и перезапуститься.
//
// Важные решения:
//   - источник — официальные релизы репозитория (не сторонний сервер);
//   - теги вида `antispam-db-latest`, `kerio-latest` игнорируются, берутся
//     только `vX.Y.Z`;
//   - целостность проверяется по SHA-256 из поля digest релиза (GitHub считает
//     его на своей стороне) — если хеш не совпал, файл не устанавливается;
//   - обновление можно отложить («Пропустить эту версию») и вообще выключить
//     автопроверку в настройках;
//   - на не-Windows файл просто сохраняется рядом: там обновление ставит
//     администратор (сервис/systemd), программа не подменяет себя.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	updateRepoOwner = "zigorminsk-debug"
	updateRepoName  = "jiraHelp"
	// updateCheckInterval — как часто проверять обновления в фоне.
	updateCheckInterval = 6 * time.Hour
	// updateMaxSize — предохранитель: .exe программы весит ~11 МБ.
	updateMaxSize = 80 << 20
)

// githubRelease — элемент ответа GitHub API (только нужные поля).
// githubAsset — файл, приложенный к релизу. Digest приходит в виде
// "sha256:…" и позволяет проверить целостность без отдельного файла контрольных сумм.
type githubAsset struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"`
}

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	PublishedAt string        `json:"published_at"`
	Body        string        `json:"body"`
	HTMLURL     string        `json:"html_url"`
	Assets      []githubAsset `json:"assets"`
}

// UpdateInfo — состояние обновления (уходит в UI как JSON).
type UpdateInfo struct {
	OK          bool   `json:"ok"`
	Current     string `json:"current"`
	Latest      string `json:"latest"`
	Available   bool   `json:"available"`
	Skipped     bool   `json:"skipped"`
	PublishedAt string `json:"publishedAt"`
	Notes       string `json:"notes"`
	PageURL     string `json:"pageUrl"`
	ExeURL      string `json:"exeUrl"`
	ExeSize     int64  `json:"exeSize"`
	ExeSHA256   string `json:"exeSha256"`
	SetupURL    string `json:"setupUrl"`
	SetupSize   int64  `json:"setupSize"`
	ZipURL      string `json:"zipUrl"`
	CheckedAt   string `json:"checkedAt"`
	AutoCheck   bool   `json:"autoCheck"`
	Error       string `json:"error,omitempty"`
}

var updateVersionRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

// parseVersion разбирает «4.6.0» или «v4.6.0» в три числа.
func parseVersion(v string) (int, int, int, bool) {
	m := updateVersionRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0, 0, 0, false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return major, minor, patch, true
}

// compareVersions возвращает −1, 0 или 1 (как strings.Compare для версий).
func compareVersions(a, b string) int {
	amaj, amin, apat, aok := parseVersion(a)
	bmaj, bmin, bpat, bok := parseVersion(b)
	switch {
	case !aok && !bok:
		return 0
	case !aok:
		return -1
	case !bok:
		return 1
	}
	if amaj != bmaj {
		if amaj < bmaj {
			return -1
		}
		return 1
	}
	if amin != bmin {
		if amin < bmin {
			return -1
		}
		return 1
	}
	if apat != bpat {
		if apat < bpat {
			return -1
		}
		return 1
	}
	return 0
}

// updateAPIURL — адрес списка релизов (переопределяется в тестах через env).
func updateAPIURL() string {
	if v := strings.TrimSpace(os.Getenv("KCM_UPDATE_API")); v != "" {
		return v
	}
	return fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?per_page=40", updateRepoOwner, updateRepoName)
}

func updateHTTPClient() *http.Client {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	return &http.Client{Timeout: 25 * time.Second, Transport: transport}
}

// sha256FromDigest превращает «sha256:abcd…» из GitHub API в «abcd…».
func sha256FromDigest(digest string) string {
	d := strings.TrimSpace(digest)
	d = strings.TrimPrefix(strings.ToLower(d), "sha256:")
	if len(d) != 64 {
		return ""
	}
	for _, r := range d {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return ""
		}
	}
	return d
}

// pickNewestRelease выбирает релиз с максимальной версией среди vX.Y.Z.
func pickNewestRelease(releases []githubRelease) *githubRelease {
	var best *githubRelease
	var bestVer [3]int
	for i := range releases {
		rel := &releases[i]
		if rel.Draft || rel.Prerelease {
			continue
		}
		maj, min, pat, ok := parseVersion(rel.TagName)
		if !ok {
			continue // antispam-db-latest, kerio-latest и прочие служебные теги
		}
		ver := [3]int{maj, min, pat}
		if best == nil || greater3(ver, bestVer) {
			best = rel
			bestVer = ver
		}
	}
	return best
}

func greater3(a, b [3]int) bool {
	if a[0] != b[0] {
		return a[0] > b[0]
	}
	if a[1] != b[1] {
		return a[1] > b[1]
	}
	return a[2] > b[2]
}

// releaseToUpdateInfo переводит релиз GitHub в структуру для UI.
func releaseToUpdateInfo(rel *githubRelease, current string, skipped bool) UpdateInfo {
	info := UpdateInfo{
		OK:          true,
		Current:     current,
		Latest:      strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v"),
		PublishedAt: rel.PublishedAt,
		Notes:       trimReleaseNotes(rel.Body),
		PageURL:     rel.HTMLURL,
		Skipped:     skipped,
		CheckedAt:   time.Now().Format("2006-01-02 15:04:05"),
	}
	info.Available = compareVersions(info.Latest, current) > 0

	for _, a := range rel.Assets {
		name := strings.ToLower(a.Name)
		switch {
		case strings.HasSuffix(name, ".exe") && strings.Contains(name, "setup"):
			info.SetupURL = a.URL
			info.SetupSize = a.Size
		case strings.HasSuffix(name, ".exe") && strings.HasPrefix(name, "keriocertmanager"):
			info.ExeURL = a.URL
			info.ExeSize = a.Size
			info.ExeSHA256 = sha256FromDigest(a.Digest)
		case strings.HasSuffix(name, ".zip"):
			info.ZipURL = a.URL
		}
	}
	return info
}

// trimReleaseNotes обрезает длинное описание релиза для показа в карточке.
func trimReleaseNotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 4000 {
		s = s[:4000] + "…"
	}
	return s
}

// FetchLatestRelease спрашивает GitHub и возвращает самый свежий релиз.
func FetchLatestRelease(ctx context.Context) (*UpdateInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updateAPIURL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "KerioCertManager/"+appVersion+" (Windows)")

	resp, err := updateHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("нет связи с GitHub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("GitHub временно ограничил запросы (HTTP %d) — повторите позже", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub ответил HTTP %d", resp.StatusCode)
	}

	var releases []githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&releases); err != nil {
		return nil, fmt.Errorf("не удалось разобрать ответ GitHub: %w", err)
	}
	rel := pickNewestRelease(releases)
	if rel == nil {
		return nil, fmt.Errorf("в репозитории не найдено ни одного релиза с версией вида vX.Y.Z")
	}
	info := releaseToUpdateInfo(rel, appVersion, false)
	if info.ExeURL == "" {
		return nil, fmt.Errorf("в релизе %s нет файла KerioCertManager.exe", rel.TagName)
	}
	return &info, nil
}

// CheckForUpdate — проверка с учётом пропущенной версии.
func CheckForUpdate(ctx context.Context, certsDir string) (UpdateInfo, error) {
	settings := LoadSavedUISettings(certsDir)
	info, err := FetchLatestRelease(ctx)
	if err != nil {
		return UpdateInfo{
			OK:        false,
			Current:   appVersion,
			Error:     err.Error(),
			CheckedAt: time.Now().Format("2006-01-02 15:04:05"),
			AutoCheck: settings.AutoCheckUpdates,
		}, err
	}
	info.AutoCheck = settings.AutoCheckUpdates
	info.Skipped = settings.SkippedVersion != "" && compareVersions(info.Latest, settings.SkippedVersion) == 0
	return *info, nil
}

// updateCertsDir — папка настроек (обычно рядом с .exe).
func updateCertsDir() string { return DefaultCertsRoot() }

// ShouldAutoCheck — пора ли проверять обновления в фоне.
func ShouldAutoCheck(certsDir string) bool {
	settings := LoadSavedUISettings(certsDir)
	if !settings.AutoCheckUpdates {
		return false
	}
	if settings.LastUpdateCheck == "" {
		return true
	}
	t, err := time.Parse("2006-01-02 15:04:05", settings.LastUpdateCheck)
	if err != nil {
		return true
	}
	return time.Since(t) > updateCheckInterval
}

// markUpdateChecked сохраняет время проверки и (опционально) пропущенную версию.
func markUpdateChecked(certsDir, skippedVersion string) {
	settings := LoadSavedUISettings(certsDir)
	settings.LastUpdateCheck = time.Now().Format("2006-01-02 15:04:05")
	if skippedVersion != "" {
		settings.SkippedVersion = skippedVersion
	}
	_ = SaveUISettings(certsDir, settings)
}

// ---------------------------------------------------------------------------
// Загрузка и установка
// ---------------------------------------------------------------------------

// DownloadUpdate скачивает новый .exe во временный файл рядом с программой и
// проверяет SHA-256. Возвращает путь к готовому файлу.
func DownloadUpdate(info UpdateInfo, progress func(string)) (string, error) {
	if info.ExeURL == "" {
		return "", fmt.Errorf("в данных обновления нет ссылки на файл программы")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	tmpDir := filepath.Join(dir, "update-tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		// Каталог программы может быть защищён — тогда качаем в системный temp.
		tmpDir = filepath.Join(os.TempDir(), "KerioCertManager-update")
		if err2 := os.MkdirAll(tmpDir, 0o755); err2 != nil {
			return "", fmt.Errorf("не удалось создать папку для загрузки: %w", err2)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, info.ExeURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "KerioCertManager/"+appVersion+" (Windows)")

	resp, err := updateHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("не удалось скачать обновление: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("сервер отдал HTTP %d вместо файла", resp.StatusCode)
	}
	if resp.ContentLength > updateMaxSize {
		return "", fmt.Errorf("файл обновления слишком большой (%d байт)", resp.ContentLength)
	}

	dest := filepath.Join(tmpDir, "KerioCertManager-"+info.Latest+".exe")
	out, err := os.Create(dest)
	if err != nil {
		return "", fmt.Errorf("не удалось создать файл обновления: %w", err)
	}

	h := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, updateMaxSize+1))
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(dest)
		return "", fmt.Errorf("ошибка загрузки: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(dest)
		return "", fmt.Errorf("ошибка записи файла обновления: %w", closeErr)
	}
	if written > updateMaxSize {
		_ = os.Remove(dest)
		return "", fmt.Errorf("файл обновления больше допустимого размера")
	}

	got := hex.EncodeToString(h.Sum(nil))
	if info.ExeSHA256 != "" && !strings.EqualFold(got, info.ExeSHA256) {
		_ = os.Remove(dest)
		return "", fmt.Errorf("SHA-256 не совпал: получено %s, ожидалось %s — обновление отменено",
			got[:16], info.ExeSHA256[:16])
	}
	// Минимальная проверка, что это действительно Windows-программа.
	head := make([]byte, 2)
	if f, err := os.Open(dest); err == nil {
		_, _ = f.Read(head)
		_ = f.Close()
	}
	if string(head) != "MZ" {
		_ = os.Remove(dest)
		return "", fmt.Errorf("скачанный файл не является исполняемым файлом Windows")
	}
	if progress != nil {
		progress(dest)
	}
	return dest, nil
}

// ApplyUpdate подменяет текущий файл программы новым и перезапускает её.
// Возвращает признак «программа перезапускается» — UI должен закрыть окно.
func ApplyUpdate(info UpdateInfo, progress func(string)) (string, error) {
	newExe, err := DownloadUpdate(info, progress)
	if err != nil {
		return "", err
	}

	cur, err := os.Executable()
	if err != nil {
		return newExe, fmt.Errorf("обновление скачано в %s, но путь к программе не определён: %w", newExe, err)
	}
	cur, _ = filepath.Abs(cur)

	if resolved, err := filepath.EvalSymlinks(cur); err == nil && resolved != "" {
		cur = resolved
	}

	if !strings.EqualFold(filepath.Ext(cur), ".exe") {
		return newExe, fmt.Errorf("автоматическая подмена доступна только для KerioCertManager.exe; новый файл сохранён: %s", newExe)
	}

	// Резервная копия текущей версии и подмена файла.
	backup := cur + ".old"
	_ = os.Remove(backup)
	if err := os.Rename(cur, backup); err != nil {
		return newExe, fmt.Errorf("не удалось заменить программу (возможно, нет прав на папку): %w\nНовый файл: %s", err, newExe)
	}
	if err := copyFile(newExe, cur); err != nil {
		_ = os.Rename(backup, cur) // возвращаем как было
		return newExe, fmt.Errorf("не удалось записать новую версию: %w", err)
	}
	_ = os.Remove(newExe)

	// Перезапуск с теми же аргументами.
	if err := startDetached(cur, os.Args[1:]); err != nil {
		return cur, fmt.Errorf("новая версия установлена, но перезапуск не удался: %w (запустите программу вручную)", err)
	}
	return cur, nil
}

// CleanupOldBinaries удаляет остатки прошлых обновлений (*.old) и папку
// update-tmp — вызывается при старте.
func CleanupOldBinaries() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	if matches, err := filepath.Glob(filepath.Join(dir, "*.exe.old")); err == nil {
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
	_ = os.RemoveAll(filepath.Join(dir, "update-tmp"))
}

// releaseNotesForUI — короткая сводка релиза для карточки обновления.
func releaseNotesForUI(notes string) []string {
	var out []string
	for _, line := range strings.Split(notes, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "```") {
			continue
		}
		line = strings.TrimLeft(line, "#>*-• ")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "---") {
			continue
		}
		if len(line) > 220 {
			line = line[:220] + "…"
		}
		out = append(out, line)
		if len(out) >= 12 {
			break
		}
	}
	return out
}

// sortReleasesByVersion — вспомогательное для тестов и отладки.
func sortReleasesByVersion(rels []githubRelease) []githubRelease {
	out := append([]githubRelease(nil), rels...)
	sort.SliceStable(out, func(i, j int) bool {
		return compareVersions(out[i].TagName, out[j].TagName) > 0
	})
	return out
}

// copyFile копирует файл с сохранением прав (используется при подмене .exe).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}
