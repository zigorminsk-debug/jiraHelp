package main

// ============================================================================
// v4.4 — АВТООБНОВЛЯЕМАЯ АНТИСПАМ-БАЗА KCM (GitHub → Kerio Connect)
//
// Что делает модуль:
//   1. Скачивает manifest.json базы с GitHub Releases (с зеркалами на raw-ветке).
//   2. Проверяет SHA-256 каждого файла перед установкой.
//   3. Показывает предпросмотр: какие правила добавятся/исчезнут, сколько очков.
//   4. Ставит kerio-antispam.cf в plugins/spamassassin/rules Kerio Connect.
//   5. Делает резервную копию, умеет откатываться и удалять базу.
//   6. Ставит задачу Планировщика Windows для автообновления.
//   7. Проверяет конкретное письмо по локальным спискам базы (dry-run).
// ============================================================================

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	mimeqp "mime/quotedprintable"
)

const (
	antiSpamTaskName     = "KerioCertManager_AntiSpamDB"
	antiSpamRepoSlug     = "zigorminsk-debug/jiraHelp"
	antiSpamReleaseTag   = "antispam-db-latest"
	antiSpamBranch       = "antispam-db"
	antiSpamRuleFileName = "kerio-antispam.cf"
	antiSpamMaxAssetSize = 48 * 1024 * 1024
)

var antiSpamListFiles = []string{
	"spam-domains.txt",
	"phishing-links.txt",
	"spam-emails.txt",
	"scam-subjects.txt",
	"scam-phrases-ru.txt",
	"threat-ips.txt",
	"allowlist.txt",
}

// AntiSpamManifest — формат manifest.json, который генерирует antispam-db/tools/build_db.py
type AntiSpamManifest struct {
	Schema           int               `json:"schema"`
	Version          string            `json:"version"`
	GeneratedAt      string            `json:"generatedAt"`
	MinClientVersion string            `json:"minClientVersion"`
	Counts           map[string]int    `json:"counts"`
	Files            []string          `json:"files"`
	SHA256           map[string]string `json:"sha256"`
	Sizes            map[string]int    `json:"sizes"`
	RuleFile         string            `json:"ruleFile"`
	Credits          []string          `json:"credits"`
	License          string            `json:"license"`
	Sources          []AntiSpamSource  `json:"sources"`
	SourcesOk        int               `json:"sourcesOk"`
	SourcesFailed    int               `json:"sourcesFailed"`
}

// AntiSpamSource — состояние одного источника базы (из manifest.json).
type AntiSpamSource struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped"`
	Count   int    `json:"count"`
	Role    string `json:"role"`
	Credit  string `json:"credit"`
	Error   string `json:"error"`
}

func (m AntiSpamManifest) RuleSHA() string {
	if m.SHA256 == nil {
		return ""
	}
	return m.SHA256[antiSpamRuleFileName]
}

func (m AntiSpamManifest) RuleSize() int {
	if m.Sizes == nil {
		return 0
	}
	return m.Sizes[antiSpamRuleFileName]
}

// ---------------------------------------------------------------------------
// Состояние установки
// ---------------------------------------------------------------------------

type AntiSpamHistoryEntry struct {
	When    string `json:"when"`
	Action  string `json:"action"`
	Version string `json:"version"`
	Note    string `json:"note"`
}

type AntiSpamState struct {
	Version           string                 `json:"version"`
	InstalledAt       string                 `json:"installedAt"`
	RulePath          string                 `json:"rulePath"`
	RulesDir          string                 `json:"rulesDir"`
	KerioDir          string                 `json:"kerioDir"`
	RuleSHA           string                 `json:"ruleSha256"`
	RuleSize          int                    `json:"ruleSize"`
	Counts            map[string]int         `json:"counts"`
	AutoUpdate        bool                   `json:"autoUpdate"`
	IntervalHours     int                    `json:"intervalHours"`
	LastCheckAt       string                 `json:"lastCheckAt"`
	LastRemoteVersion string                 `json:"lastRemoteVersion"`
	LastError         string                 `json:"lastError"`
	ListsDir          string                 `json:"listsDir"`
	History           []AntiSpamHistoryEntry `json:"history"`
}

var antiSpamStateMu sync.Mutex

func antiSpamDir(certsDir string) string {
	return filepath.Join(certsDir, "antispam")
}

func antiSpamStatePath(certsDir string) string {
	return filepath.Join(antiSpamDir(certsDir), "state.json")
}

func antiSpamListsDir(certsDir string) string {
	return filepath.Join(antiSpamDir(certsDir), "lists")
}

func antiSpamBackupDir(certsDir string) string {
	return filepath.Join(antiSpamDir(certsDir), "backup")
}

func LoadAntiSpamState(certsDir string) AntiSpamState {
	antiSpamStateMu.Lock()
	defer antiSpamStateMu.Unlock()
	return loadAntiSpamStateLocked(certsDir)
}

func loadAntiSpamStateLocked(certsDir string) AntiSpamState {
	var st AntiSpamState
	if b, err := os.ReadFile(antiSpamStatePath(certsDir)); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.IntervalHours <= 0 {
		st.IntervalHours = 12
	}
	if st.Counts == nil {
		st.Counts = map[string]int{}
	}
	return st
}

func SaveAntiSpamState(certsDir string, st AntiSpamState) error {
	antiSpamStateMu.Lock()
	defer antiSpamStateMu.Unlock()
	return saveAntiSpamStateLocked(certsDir, st)
}

func saveAntiSpamStateLocked(certsDir string, st AntiSpamState) error {
	_ = os.MkdirAll(antiSpamDir(certsDir), 0o755)
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := antiSpamStatePath(certsDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, antiSpamStatePath(certsDir))
}

func antiSpamAppendHistory(st *AntiSpamState, action, version, note string) {
	st.History = append(st.History, AntiSpamHistoryEntry{
		When:    time.Now().Format("2006-01-02 15:04:05"),
		Action:  action,
		Version: version,
		Note:    note,
	})
	if len(st.History) > 40 {
		st.History = st.History[len(st.History)-40:]
	}
}

// ---------------------------------------------------------------------------
// Определение каталогов Kerio Connect
// ---------------------------------------------------------------------------

// Поиск каталогов Kerio и SpamAssassin вынесен в kerio_paths.go: там полная
// цепочка (служба → реестр → стандартные пути → обход дерева) и отчёт
// «что проверено» для интерфейса.

// ---------------------------------------------------------------------------
// Разбор файла правил и статистика
// ---------------------------------------------------------------------------

type AntiSpamRuleGroup struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Score string `json:"score"`
	Count int    `json:"count"`
}

var antiSpamRuleGroupMeta = []struct {
	Prefix string
	Key    string
	Label  string
	Score  string
}{
	{"KCM_SPAM_FROM_DOMAIN_", "domains", "Домены отправителей (From)", "+3.2"},
	{"KCM_SPAM_FROM_EMAIL_", "emails", "Конкретные адреса отправителей", "+4.5"},
	{"KCM_SCAM_SUBJECT_", "subjects", "Шаблоны мотивов в теме письма", "+1.8"},
	{"KCM_SCAM_PHRASE_", "phrases", "Фразы мошеннических писем в теле", "+1.5"},
	{"KCM_PHISH_URL_", "urls", "Домены фишинговых ссылок", "+2.5"},
	{"KCM_SPAM_SRC_IP_", "ips", "IP/CIDR источников в Received", "+3.0"},
	{"KCM_ALLOW_FROM_", "allowlist", "Белый список (снижение очков)", "-6.0"},
}

var antiSpamRuleLineRe = regexp.MustCompile(`(?m)^(?:header|body|uri)\s+(\S+)`)
var antiSpamVersionRe = regexp.MustCompile(`(?m)^#\s*Версия базы:\s*([0-9A-Za-z._\-]+)`)

func parseAntiSpamRuleNames(data []byte) (string, map[string]int, int) {
	text := string(data)
	version := ""
	if m := antiSpamVersionRe.FindStringSubmatch(text); len(m) == 2 {
		version = m[1]
	}
	counts := map[string]int{}
	total := 0
	for _, m := range antiSpamRuleLineRe.FindAllStringSubmatch(text, -1) {
		name := m[1]
		total++
		for _, meta := range antiSpamRuleGroupMeta {
			if strings.HasPrefix(name, meta.Prefix) {
				counts[meta.Key]++
				break
			}
		}
	}
	return version, counts, total
}

func antiSpamGroupsFromCounts(counts map[string]int) []AntiSpamRuleGroup {
	out := make([]AntiSpamRuleGroup, 0, len(antiSpamRuleGroupMeta))
	for _, meta := range antiSpamRuleGroupMeta {
		out = append(out, AntiSpamRuleGroup{
			Key:   meta.Key,
			Label: meta.Label,
			Score: meta.Score,
			Count: counts[meta.Key],
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Статус
// ---------------------------------------------------------------------------

type AntiSpamStatus struct {
	OK                bool                   `json:"ok"`
	KerioDir          string                 `json:"kerioDir"`
	KerioDirSource    string                 `json:"kerioDirSource"`
	KerioCandidates   []string               `json:"kerioCandidates"`
	RulesDir          string                 `json:"rulesDir"`
	RulesDirExists    bool                   `json:"rulesDirExists"`
	RulesDirSource    string                 `json:"rulesDirSource"`
	RulePath          string                 `json:"rulePath"`
	Installed         bool                   `json:"installed"`
	Version           string                 `json:"version"`
	InstalledAt       string                 `json:"installedAt"`
	Size              int                    `json:"size"`
	SHA256            string                 `json:"sha256"`
	TotalRules        int                    `json:"totalRules"`
	Counts            map[string]int         `json:"counts"`
	Groups            []AntiSpamRuleGroup    `json:"groups"`
	ListsDir          string                 `json:"listsDir"`
	ListsAvailable    bool                   `json:"listsAvailable"`
	ListsFiles        int                    `json:"listsFiles"`
	Backups           int                    `json:"backups"`
	LastBackup        string                 `json:"lastBackup"`
	ServiceStatus     string                 `json:"serviceStatus"`
	AutoUpdate        bool                   `json:"autoUpdate"`
	IntervalHours     int                    `json:"intervalHours"`
	TaskScheduled     bool                   `json:"taskScheduled"`
	LastCheckAt       string                 `json:"lastCheckAt"`
	LastRemoteVersion string                 `json:"lastRemoteVersion"`
	LastError         string                 `json:"lastError"`
	History           []AntiSpamHistoryEntry `json:"history"`
	RepoURL           string                 `json:"repoUrl"`
	ReleaseURL        string                 `json:"releaseUrl"`
}

func GetAntiSpamStatus(certsDir string) AntiSpamStatus {
	settings := LoadSavedUISettings(certsDir)
	st := LoadAntiSpamState(certsDir)

	kerioDir, source := resolveKerioInstallDir(settings)
	// Только поиск существующей папки: статус не должен создавать каталоги.
	choice := ChooseRulesDir(settings, st, kerioDir, "", false)
	rulesDir := choice.Dir
	rulesDirExists := choice.Exists
	rulesDirSource := choice.Source
	if rulesDir == "" {
		rulesDirSource = "не найден"
	}
	if choice.KerioDir != "" && kerioDir == "" {
		kerioDir = choice.KerioDir
		source = choice.Source
	}

	rulePath := filepath.Join(rulesDir, antiSpamRuleFileName)
	if rulesDir == "" {
		rulePath = ""
	}
	if rulesDir == "" {
		// В статусе честно показываем, что автопоиск не дал результата, — админу
		// это экономит время: видно, что программа действительно искала.
		if n := len(kerioDirCandidates(settings)); n > 0 {
			rulesDirSource = fmt.Sprintf("не найден (найдено установок Kerio: %d)", n)
		} else {
			rulesDirSource = "не найден — Kerio Connect не обнаружен на этом компьютере"
		}
	}

	res := AntiSpamStatus{
		OK:                true,
		KerioDir:          kerioDir,
		KerioDirSource:    source,
		KerioCandidates:   kerioDirCandidates(settings),
		RulesDir:          rulesDir,
		RulesDirExists:    rulesDirExists,
		RulesDirSource:    rulesDirSource,
		RulePath:          rulePath,
		ListsDir:          antiSpamListsDir(certsDir),
		ServiceStatus:     PlatformKerioServiceStatus(),
		AutoUpdate:        st.AutoUpdate,
		IntervalHours:     st.IntervalHours,
		TaskScheduled:     PlatformQueryAntiSpamTask(),
		LastCheckAt:       st.LastCheckAt,
		LastRemoteVersion: st.LastRemoteVersion,
		LastError:         st.LastError,
		History:           st.History,
		Counts:            map[string]int{},
		RepoURL:           "https://github.com/" + antiSpamRepoSlug,
		ReleaseURL:        "https://github.com/" + antiSpamRepoSlug + "/releases/tag/" + antiSpamReleaseTag,
	}

	// Локальные списки для dry-run проверки письма
	if entries, err := os.ReadDir(antiSpamListsDir(certsDir)); err == nil {
		got := 0
		for _, e := range entries {
			for _, want := range antiSpamListFiles {
				if e.Name() == want {
					got++
				}
			}
		}
		res.ListsFiles = got
		// Старые базы не содержат phishing-links.txt — достаточно любого набора списков.
		res.ListsAvailable = got > 0
	}

	if backups, err := filepath.Glob(filepath.Join(antiSpamBackupDir(certsDir), "*.cf")); err == nil {
		res.Backups = len(backups)
		if len(backups) > 0 {
			sort.Strings(backups)
			res.LastBackup = filepath.Base(backups[len(backups)-1])
		}
	}

	if data, err := os.ReadFile(rulePath); err == nil && rulePath != "" {
		version, counts, total := parseAntiSpamRuleNames(data)
		sum := sha256.Sum256(data)
		res.Installed = true
		res.Version = version
		if version == "" && st.Version != "" {
			res.Version = st.Version
		}
		res.InstalledAt = st.InstalledAt
		res.Size = len(data)
		res.SHA256 = hex.EncodeToString(sum[:])
		res.TotalRules = total
		res.Counts = counts
		res.Groups = antiSpamGroupsFromCounts(counts)
	} else if st.Version != "" {
		res.Version = st.Version
		res.InstalledAt = st.InstalledAt
		res.Counts = st.Counts
		res.Groups = antiSpamGroupsFromCounts(st.Counts)
	}

	if len(res.Counts) == 0 {
		res.Groups = antiSpamGroupsFromCounts(map[string]int{})
	}
	return res
}

// ---------------------------------------------------------------------------
// Скачивание базы с GitHub
// ---------------------------------------------------------------------------

func antiSpamHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
}

func antiSpamManifestURLs() []string {
	if base := strings.TrimSpace(os.Getenv("KCM_ANTISPAM_DB_BASE")); base != "" {
		return []string{strings.TrimSuffix(base, "/") + "/manifest.json"}
	}
	return []string{
		// 1) Основной канал: GitHub Releases (обновляется ежедневным workflow)
		fmt.Sprintf("https://github.com/%s/releases/download/%s/manifest.json", antiSpamRepoSlug, antiSpamReleaseTag),
		// 2) Зеркало: ветка antispam-db (если релизы/API недоступны)
		fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/manifest.json", antiSpamRepoSlug, antiSpamBranch),
	}
}

func antiSpamHTTPGet(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "KerioCertManager/4.4 (+https://github.com/"+antiSpamRepoSlug+")")
	req.Header.Set("Accept", "*/*")
	resp, err := antiSpamHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d от %s", resp.StatusCode, url)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, antiSpamMaxAssetSize))
	if err != nil {
		return nil, err
	}
	return data, nil
}

type antiSpamRemote struct {
	Manifest AntiSpamManifest
	BaseURL  string
	Source   string
}

func fetchAntiSpamManifest() (*antiSpamRemote, error) {
	var errs []string
	for _, url := range antiSpamManifestURLs() {
		data, err := antiSpamHTTPGet(url)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		var m AntiSpamManifest
		if err := json.Unmarshal(data, &m); err != nil {
			errs = append(errs, "некорректный manifest.json: "+err.Error())
			continue
		}
		if strings.TrimSpace(m.Version) == "" {
			errs = append(errs, "в manifest.json нет поля version")
			continue
		}
		source := "GitHub Releases"
		if strings.Contains(url, "raw.githubusercontent.com") {
			source = "ветка " + antiSpamBranch
		}
		return &antiSpamRemote{
			Manifest: m,
			BaseURL:  strings.TrimSuffix(url, "/manifest.json"),
			Source:   source,
		}, nil
	}
	return nil, fmt.Errorf("не удалось получить базу с GitHub:\n  %s\n\nПроверьте интернет/прокси. Если GitHub недоступен — скачайте "+
		"kerio-antispam.cf вручную со страницы релиза и используйте «Импорт файла базы».", strings.Join(errs, "\n  "))
}

func verifyAndDownload(baseURL, name, wantSHA string) ([]byte, error) {
	url := strings.TrimSuffix(baseURL, "/") + "/" + name
	data, err := antiSpamHTTPGet(url)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if wantSHA != "" {
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, wantSHA) {
			return nil, fmt.Errorf("контрольная сумма %s не совпала (ожидалось %s, получено %s) — файл повреждён или подменён", name, wantSHA[:12]+"…", got[:12]+"…")
		}
	}
	return data, nil
}

// ---------------------------------------------------------------------------
// Сравнение версий (2026.10.24-0810)
// ---------------------------------------------------------------------------

func compareAntiSpamVersions(a, b string) int {
	pa := strings.FieldsFunc(a, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	pb := strings.FieldsFunc(b, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] == pb[i] {
			continue
		}
		var na, nb int
		_, ea := fmt.Sscanf(pa[i], "%d", &na)
		_, eb := fmt.Sscanf(pb[i], "%d", &nb)
		if ea == nil && eb == nil {
			if na < nb {
				return -1
			}
			return 1
		}
		if pa[i] < pb[i] {
			return -1
		}
		return 1
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Предпросмотр (dry-run)
// ---------------------------------------------------------------------------

type AntiSpamDiff struct {
	OldVersion   string         `json:"oldVersion"`
	NewVersion   string         `json:"newVersion"`
	OldTotal     int            `json:"oldTotal"`
	NewTotal     int            `json:"newTotal"`
	AddedCount   int            `json:"addedCount"`
	RemovedCount int            `json:"removedCount"`
	OldCounts    map[string]int `json:"oldCounts"`
	NewCounts    map[string]int `json:"newCounts"`
	SampleNew    []string       `json:"sampleNew"`
	Summary      string         `json:"summary"`
}

type AntiSpamPreview struct {
	OK            bool                `json:"ok"`
	Manifest      AntiSpamManifest    `json:"manifest"`
	Source        string              `json:"source"`
	DownloadedAt  string              `json:"downloadedAt"`
	RuleSize      int                 `json:"ruleSize"`
	RuleSHA       string              `json:"ruleSha256"`
	RulePath      string              `json:"rulePath"`
	RulesDir      string              `json:"rulesDir"`
	KerioDir      string              `json:"kerioDir"`
	BackupWillBe  bool                `json:"backupWillBeCreated"`
	RestartNeeded bool                `json:"restartNeeded"`
	UpToDate      bool                `json:"upToDate"`
	Diff          AntiSpamDiff        `json:"diff"`
	Groups        []AntiSpamRuleGroup `json:"groups"`
	Notes         []string            `json:"notes"`
}

func buildAntiSpamDiff(oldData, newData []byte) AntiSpamDiff {
	oldVersion, oldCounts, oldTotal := parseAntiSpamRuleNames(oldData)
	newVersion, newCounts, newTotal := parseAntiSpamRuleNames(newData)

	oldNames := map[string]bool{}
	for _, m := range antiSpamRuleLineRe.FindAllStringSubmatch(string(oldData), -1) {
		oldNames[m[1]] = true
	}
	newNames := map[string]bool{}
	var sample []string
	for _, m := range antiSpamRuleLineRe.FindAllStringSubmatch(string(newData), -1) {
		if !oldNames[m[1]] {
			if len(sample) < 12 {
				sample = append(sample, m[1])
			}
		}
		newNames[m[1]] = true
	}
	removed := 0
	for name := range oldNames {
		if !newNames[name] {
			removed++
		}
	}

	diff := AntiSpamDiff{
		OldVersion:   oldVersion,
		NewVersion:   newVersion,
		OldTotal:     oldTotal,
		NewTotal:     newTotal,
		AddedCount:   newTotal - (oldTotal - removed),
		RemovedCount: removed,
		OldCounts:    oldCounts,
		NewCounts:    newCounts,
		SampleNew:    sample,
	}
	if diff.AddedCount < 0 {
		diff.AddedCount = 0
	}
	diff.Summary = fmt.Sprintf("Правил было %d → станет %d (+%d новых, −%d удалённых)", oldTotal, newTotal, diff.AddedCount, removed)
	return diff
}

func PreviewAntiSpamInstall(certsDir string) (*AntiSpamPreview, error) {
	settings := LoadSavedUISettings(certsDir)
	st := LoadAntiSpamState(certsDir)
	remote, err := fetchAntiSpamManifest()
	if err != nil {
		return nil, err
	}
	ruleData, err := verifyAndDownload(remote.BaseURL, antiSpamRuleFileName, remote.Manifest.RuleSHA())
	if err != nil {
		return nil, err
	}

	// Предпросмотр ничего не создаёт: ищем только существующую папку правил.
	choice := ChooseRulesDir(settings, st, "", "", false)
	rulesDir := choice.Dir
	kerioDir := choice.KerioDir
	if kerioDir == "" {
		kerioDir, _ = resolveKerioInstallDir(settings)
	}
	rulePath := filepath.Join(rulesDir, antiSpamRuleFileName)
	if rulesDir == "" {
		rulePath = ""
	}

	var installed []byte
	if rulePath != "" {
		installed, _ = os.ReadFile(rulePath)
	}
	diff := buildAntiSpamDiff(installed, ruleData)
	_, counts, total := parseAntiSpamRuleNames(ruleData)

	preview := &AntiSpamPreview{
		OK:            true,
		Manifest:      remote.Manifest,
		Source:        remote.Source,
		DownloadedAt:  time.Now().Format("2006-01-02 15:04:05"),
		RuleSize:      len(ruleData),
		RuleSHA:       sha256Hex(ruleData),
		RulePath:      rulePath,
		RulesDir:      rulesDir,
		KerioDir:      kerioDir,
		BackupWillBe:  len(installed) > 0,
		RestartNeeded: len(installed) == 0 || len(installed) != len(ruleData) || sha256Hex(installed) != sha256Hex(ruleData),
		UpToDate:      strings.EqualFold(diff.OldVersion, remote.Manifest.Version) && diff.OldVersion != "",
		Diff:          diff,
		Groups:        antiSpamGroupsFromCounts(counts),
	}
	preview.Notes = append(preview.Notes, fmt.Sprintf("В новой базе %d правил SpamAssassin.", total))
	if remote.Manifest.RuleSize() > 0 {
		preview.Notes = append(preview.Notes, fmt.Sprintf("Размер файла правил: %.1f КБ.", float64(remote.Manifest.RuleSize())/1024))
	}
	if rulesDir == "" {
		preview.Notes = append(preview.Notes, "⚠️ Каталог SpamAssassin не найден: укажите папку установки Kerio Connect вручную.")
	} else if !preview.BackupWillBe {
		preview.Notes = append(preview.Notes, "База ещё не установлена — резервная копия не потребуется.")
	}
	if preview.RestartNeeded {
		preview.Notes = append(preview.Notes, "После установки требуется перезапуск службы Kerio MailServer (программа сделает это автоматически, если включена галочка).")
	}
	if m := remote.Manifest; len(m.Sources) > 0 {
		var failed, skipped []string
		for _, src := range m.Sources {
			if !src.Enabled || src.OK {
				continue
			}
			if src.Skipped {
				skipped = append(skipped, src.Name)
			} else {
				failed = append(failed, src.Name)
			}
		}
		note := fmt.Sprintf("Источники базы: %d активны", m.SourcesOk)
		if len(failed) > 0 {
			note += fmt.Sprintf(", %d недоступны (%s)", len(failed), strings.Join(failed, ", "))
		}
		if len(skipped) > 0 {
			note += fmt.Sprintf(", %d требуют ключа (%s)", len(skipped), strings.Join(skipped, ", "))
		}
		preview.Notes = append(preview.Notes, note+".")
	}
	return preview, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Установка / откат / удаление
// ---------------------------------------------------------------------------

type AntiSpamInstallOptions struct {
	KerioDir string `json:"kerioDir"`
	RulesDir string `json:"rulesDir"`
	Restart  bool   `json:"restart"`
	Version  string `json:"version"`
}

type AntiSpamInstallResult struct {
	OK           bool                `json:"ok"`
	Version      string              `json:"version"`
	Source       string              `json:"source"`
	RulePath     string              `json:"rulePath"`
	RuleSize     int                 `json:"ruleSize"`
	RuleSHA      string              `json:"ruleSha256"`
	TotalRules   int                 `json:"totalRules"`
	Counts       map[string]int      `json:"counts"`
	Groups       []AntiSpamRuleGroup `json:"groups"`
	ListsDir     string              `json:"listsDir"`
	BackupPath   string              `json:"backupPath"`
	Restarted    bool                `json:"restarted"`
	RestartError string              `json:"restartError"`
	Steps        []string            `json:"steps"`
	Warnings     []string            `json:"warnings"`
	InstalledAt  string              `json:"installedAt"`
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kcm-*"+filepath.Ext(path))
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	_ = tmp.Chmod(perm)
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func backupInstalledRule(certsDir, rulePath string) (string, error) {
	data, err := os.ReadFile(rulePath)
	if err != nil {
		return "", nil
	}
	version, _, _ := parseAntiSpamRuleNames(data)
	if version == "" {
		version = "unknown"
	}
	_ = os.MkdirAll(antiSpamBackupDir(certsDir), 0o755)
	name := fmt.Sprintf("kerio-antispam-%s-%s.cf", sanitizeFileToken(version), time.Now().Format("20060102-150405"))
	full := filepath.Join(antiSpamBackupDir(certsDir), name)
	if err := os.WriteFile(full, data, 0o644); err != nil {
		return "", err
	}
	return full, nil
}

func sanitizeFileToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "db"
	}
	return out
}

func InstallAntiSpamDB(certsDir string, opts AntiSpamInstallOptions) (*AntiSpamInstallResult, error) {
	res := &AntiSpamInstallResult{Counts: map[string]int{}, Steps: []string{}, Warnings: []string{}}
	settings := LoadSavedUISettings(certsDir)
	st := LoadAntiSpamState(certsDir)

	remote, err := fetchAntiSpamManifest()
	if err != nil {
		st.LastError = err.Error()
		_ = SaveAntiSpamState(certsDir, st)
		return nil, err
	}
	if opts.Version != "" && !strings.EqualFold(opts.Version, remote.Manifest.Version) {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("На GitHub уже новая версия %s (вы запрашивали %s) — устанавливаю актуальную.", remote.Manifest.Version, opts.Version))
	}
	res.Source = remote.Source

	ruleData, err := verifyAndDownload(remote.BaseURL, antiSpamRuleFileName, remote.Manifest.RuleSHA())
	if err != nil {
		st.LastError = err.Error()
		_ = SaveAntiSpamState(certsDir, st)
		return nil, err
	}
	res.Steps = append(res.Steps, fmt.Sprintf("1. База %s скачана с %s (%.1f КБ, SHA-256 подтверждён).",
		remote.Manifest.Version, remote.Source, float64(len(ruleData))/1024))

	// Куда ставить: учитываем и папку Kerio, и папку правил из полей ввода,
	// и сохранённый путь. create=true — разрешено создать папку rules.
	choice := ChooseRulesDir(settings, st, opts.KerioDir, opts.RulesDir, true)
	rulesDir := choice.Dir
	kerioDir := choice.KerioDir
	if kerioDir == "" {
		kerioDir, _ = resolveKerioInstallDir(settings)
	}
	if kerioDir == "" {
		kerioDir = st.KerioDir
	}
	if rulesDir == "" {
		err := RulesDirError(choice)
		st.LastError = err.Error()
		_ = SaveAntiSpamState(certsDir, st)
		return nil, err
	}
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		return nil, fmt.Errorf("нет доступа к %s: %w (запустите программу от имени Администратора)", rulesDir, err)
	}
	res.RulePath = filepath.Join(rulesDir, antiSpamRuleFileName)
	res.Steps = append(res.Steps, "2. Каталог правил Kerio: "+rulesDir)

	// Локальные списки для проверки письма (не критичны для работы антиспама)
	listsDir := antiSpamListsDir(certsDir)
	listErrors := 0
	downloaded := 0
	for _, name := range antiSpamListFiles {
		if len(remote.Manifest.Files) > 0 && !containsString(remote.Manifest.Files, name) {
			continue // файла нет в этой версии базы (например, старая схема без phishing-links.txt)
		}
		data, derr := verifyAndDownload(remote.BaseURL, name, remote.Manifest.SHA256[name])
		if derr != nil {
			listErrors++
			res.Warnings = append(res.Warnings, "список "+name+" не загружен: "+derr.Error())
			continue
		}
		if werr := writeFileAtomic(filepath.Join(listsDir, name), data, 0o644); werr != nil {
			res.Warnings = append(res.Warnings, "не удалось сохранить "+name+": "+werr.Error())
			continue
		}
		downloaded++
	}
	res.ListsDir = listsDir
	if listErrors == 0 {
		res.Steps = append(res.Steps, fmt.Sprintf("3. Локальные списки базы сохранены (%d файлов) для предварительной проверки писем.", downloaded))
	} else {
		res.Steps = append(res.Steps, "3. Локальные списки сохранены частично — проверка писем может быть неполной.")
	}

	// Резервная копия
	if backup, berr := backupInstalledRule(certsDir, res.RulePath); berr != nil {
		res.Warnings = append(res.Warnings, "резервная копия не создана: "+berr.Error())
	} else if backup != "" {
		res.BackupPath = backup
		res.Steps = append(res.Steps, "4. Резервная копия предыдущей базы: "+backup)
	} else {
		res.Steps = append(res.Steps, "4. Предыдущая база не найдена — резервная копия не требуется.")
	}

	// Проверка синтаксиса перед записью (ловит битый файл до установки)
	if err := validateAntiSpamRuleFile(ruleData); err != nil {
		err = fmt.Errorf("файл правил не прошёл проверку, установка отменена: %w", err)
		st.LastError = err.Error()
		_ = SaveAntiSpamState(certsDir, st)
		return nil, err
	}

	if err := writeFileAtomic(res.RulePath, ruleData, 0o644); err != nil {
		return nil, fmt.Errorf("не удалось записать %s: %w (нужны права Администратора)", res.RulePath, err)
	}
	written, err := os.ReadFile(res.RulePath)
	if err != nil {
		return nil, fmt.Errorf("файл записан, но не читается обратно: %w", err)
	}
	if sha256Hex(written) != sha256Hex(ruleData) {
		return nil, fmt.Errorf("файл записан с искажениями (контрольная сумма не совпала) — повторите установку")
	}
	res.Steps = append(res.Steps, "5. Файл "+antiSpamRuleFileName+" установлен и проверен по SHA-256.")

	version, counts, total := parseAntiSpamRuleNames(ruleData)
	res.Version = version
	if res.Version == "" {
		res.Version = remote.Manifest.Version
	}
	res.RuleSize = len(written)
	res.RuleSHA = sha256Hex(written)
	res.TotalRules = total
	res.Counts = counts
	res.Groups = antiSpamGroupsFromCounts(counts)

	st.Version = res.Version
	st.InstalledAt = time.Now().Format("2006-01-02 15:04:05")
	st.RulePath = res.RulePath
	st.RulesDir = rulesDir
	st.KerioDir = kerioDir
	st.RuleSHA = res.RuleSHA
	st.RuleSize = res.RuleSize
	st.Counts = counts
	st.ListsDir = listsDir
	st.LastCheckAt = st.InstalledAt
	st.LastRemoteVersion = remote.Manifest.Version
	st.LastError = ""
	antiSpamAppendHistory(&st, "install", res.Version, remote.Source+", правил: "+fmt.Sprintf("%d", total))
	if err := saveAntiSpamStateLocked(certsDir, st); err != nil {
		res.Warnings = append(res.Warnings, "состояние установки не сохранено: "+err.Error())
	}
	res.InstalledAt = st.InstalledAt

	if opts.Restart {
		if PlatformKerioServiceStatus() == "NOT_INSTALLED" {
			res.Warnings = append(res.Warnings, "служба KerioMailServer не найдена — перезапуск пропущен, правила применятся при следующем старте сервера")
		} else if rerr := PlatformControlKerioService("restart"); rerr != nil {
			res.RestartError = rerr.Error()
			res.Warnings = append(res.Warnings,
				"не удалось перезапустить KerioMailServer автоматически: "+rerr.Error()+
					". Перезапустите службу вручную (services.msc) или включите/выключите SURBL в Контент-фильтре и нажмите «Применить».")
		} else {
			res.Restarted = true
			res.Steps = append(res.Steps, "6. Служба Kerio MailServer перезапущена — правила активны.")
		}
	} else {
		res.Steps = append(res.Steps, "6. Перезапуск службы отключён: правила начнут работать после перезапуска Kerio MailServer.")
	}
	res.OK = true
	return res, nil
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

var antiSpamRuleSyntaxRe = regexp.MustCompile(`^(header|body|uri|describe|score|tflags)\s+\S+`)

func validateAntiSpamRuleFile(data []byte) error {
	text := string(data)
	if !strings.Contains(text, "KCM_") {
		return fmt.Errorf("в файле нет правил KCM")
	}
	if strings.Contains(text, "\x00") {
		return fmt.Errorf("файл содержит двоичные данные")
	}
	re := regexp.MustCompile(`/(?:[^/\\]|\\.)*/[a-z]*$`)
	lines := strings.Split(text, "\n")
	checked := 0
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !antiSpamRuleSyntaxRe.MatchString(line) {
			return fmt.Errorf("строка %d: неизвестная директива: %s", i+1, truncateText(line, 80))
		}
		if strings.HasPrefix(line, "header") || strings.HasPrefix(line, "body") || strings.HasPrefix(line, "uri") {
			if !re.MatchString(line) {
				return fmt.Errorf("строка %d: не закрыто регулярное выражение", i+1)
			}
			checked++
		}
	}
	if checked == 0 {
		return fmt.Errorf("в файле нет ни одного правила")
	}
	return nil
}

func RollbackAntiSpamDB(certsDir string, restart bool) (*AntiSpamInstallResult, error) {
	st := LoadAntiSpamState(certsDir)
	backups, err := filepath.Glob(filepath.Join(antiSpamBackupDir(certsDir), "*.cf"))
	if err != nil || len(backups) == 0 {
		return nil, fmt.Errorf("резервных копий нет — откатываться некуда")
	}
	sort.Strings(backups)
	latest := backups[len(backups)-1]
	data, err := os.ReadFile(latest)
	if err != nil {
		return nil, err
	}
	choice := ChooseRulesDir(LoadSavedUISettings(certsDir), st, st.KerioDir, "", true)
	rulesDir := choice.Dir
	if rulesDir == "" {
		return nil, RulesDirError(choice)
	}
	rulePath := filepath.Join(rulesDir, antiSpamRuleFileName)
	if _, err := os.Stat(rulePath); err == nil {
		_, _ = backupInstalledRule(certsDir, rulePath)
	}
	if err := writeFileAtomic(rulePath, data, 0o644); err != nil {
		return nil, err
	}
	version, counts, total := parseAntiSpamRuleNames(data)
	st.Version = version
	st.RulePath = rulePath
	st.RulesDir = rulesDir
	st.RuleSHA = sha256Hex(data)
	st.RuleSize = len(data)
	st.Counts = counts
	st.InstalledAt = time.Now().Format("2006-01-02 15:04:05")
	antiSpamAppendHistory(&st, "rollback", version, "восстановлено из "+filepath.Base(latest))
	if err := saveAntiSpamStateLocked(certsDir, st); err != nil {
		return nil, err
	}

	res := &AntiSpamInstallResult{
		OK:          true,
		Version:     version,
		Source:      "резервная копия " + filepath.Base(latest),
		RulePath:    rulePath,
		RuleSize:    len(data),
		RuleSHA:     st.RuleSHA,
		TotalRules:  total,
		Counts:      counts,
		Groups:      antiSpamGroupsFromCounts(counts),
		InstalledAt: st.InstalledAt,
		Warnings:    []string{},
		Steps:       []string{"1. Восстановлена резервная копия " + filepath.Base(latest), "2. Файл правил записан: " + rulePath},
	}
	if restart {
		if rerr := PlatformControlKerioService("restart"); rerr != nil {
			res.RestartError = rerr.Error()
			res.Warnings = append(res.Warnings, "KerioMailServer не перезапущен автоматически: "+rerr.Error())
		} else {
			res.Restarted = true
			res.Steps = append(res.Steps, "3. Служба Kerio MailServer перезапущена.")
		}
	}
	return res, nil
}

type AntiSpamRemoveResult struct {
	OK         bool     `json:"ok"`
	RulePath   string   `json:"rulePath"`
	BackupPath string   `json:"backupPath"`
	Steps      []string `json:"steps"`
	Restarted  bool     `json:"restarted"`
	Warnings   []string `json:"warnings"`
}

func RemoveAntiSpamDB(certsDir string, restart bool) (*AntiSpamRemoveResult, error) {
	st := LoadAntiSpamState(certsDir)
	rulePath := st.RulePath
	if rulePath == "" {
		if choice := ChooseRulesDir(LoadSavedUISettings(certsDir), st, st.KerioDir, "", false); choice.Dir != "" {
			rulePath = filepath.Join(choice.Dir, antiSpamRuleFileName)
		}
	}
	res := &AntiSpamRemoveResult{OK: true, RulePath: rulePath, Steps: []string{}, Warnings: []string{}}
	if rulePath == "" {
		return nil, fmt.Errorf("не удалось определить путь установленной базы — укажите каталог Kerio вручную")
	}
	if _, err := os.Stat(rulePath); err != nil {
		return nil, fmt.Errorf("файл базы не найден: %s", rulePath)
	}
	backup, berr := backupInstalledRule(certsDir, rulePath)
	if berr == nil && backup != "" {
		res.BackupPath = backup
		res.Steps = append(res.Steps, "1. Копия сохранена: "+backup)
	}
	if err := os.Remove(rulePath); err != nil {
		return nil, fmt.Errorf("не удалось удалить %s: %w (нужны права Администратора)", rulePath, err)
	}
	res.Steps = append(res.Steps, "2. Файл правил удалён: "+rulePath)

	st.Version = ""
	st.RulePath = ""
	st.RuleSHA = ""
	st.RuleSize = 0
	st.Counts = map[string]int{}
	antiSpamAppendHistory(&st, "remove", "", "база удалена")
	if err := saveAntiSpamStateLocked(certsDir, st); err != nil {
		res.Warnings = append(res.Warnings, "состояние не сохранено: "+err.Error())
	}
	if restart {
		if rerr := PlatformControlKerioService("restart"); rerr != nil {
			res.Warnings = append(res.Warnings, "KerioMailServer не перезапущен автоматически: "+rerr.Error())
		} else {
			res.Restarted = true
			res.Steps = append(res.Steps, "3. Служба Kerio MailServer перезапущена — база отключена.")
		}
	} else {
		res.Steps = append(res.Steps, "3. Перезапустите Kerio MailServer, чтобы база перестала применяться.")
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Импорт файла базы вручную (GitHub недоступен / закрытый контур)
// ---------------------------------------------------------------------------

func ImportAntiSpamRuleFile(certsDir, srcPath string, restart bool) (*AntiSpamInstallResult, error) {
	srcPath = strings.TrimSpace(srcPath)
	if srcPath == "" {
		return nil, fmt.Errorf("не указан путь к файлу базы")
	}
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать %s: %w", srcPath, err)
	}
	if err := validateAntiSpamRuleFile(data); err != nil {
		return nil, fmt.Errorf("файл не похож на базу KCM: %w", err)
	}
	settings := LoadSavedUISettings(certsDir)
	st := LoadAntiSpamState(certsDir)
	choice := ChooseRulesDir(settings, st, "", "", true)
	rulesDir := choice.Dir
	if rulesDir == "" {
		return nil, RulesDirError(choice)
	}
	kerioDir := choice.KerioDir
	if kerioDir == "" {
		kerioDir, _ = resolveKerioInstallDir(settings)
	}
	if kerioDir == "" {
		kerioDir = st.KerioDir
	}
	rulePath := filepath.Join(rulesDir, antiSpamRuleFileName)
	res := &AntiSpamInstallResult{
		OK:       true,
		Source:   "локальный файл " + filepath.Base(srcPath),
		RulePath: rulePath,
		Warnings: []string{},
		Steps:    []string{"1. Файл прочитан: " + srcPath},
	}
	if backup, berr := backupInstalledRule(certsDir, rulePath); berr == nil && backup != "" {
		res.BackupPath = backup
		res.Steps = append(res.Steps, "2. Резервная копия: "+backup)
	}
	if err := writeFileAtomic(rulePath, data, 0o644); err != nil {
		return nil, fmt.Errorf("не удалось записать %s: %w (нужны права Администратора)", rulePath, err)
	}
	written, err := os.ReadFile(rulePath)
	if err != nil || sha256Hex(written) != sha256Hex(data) {
		return nil, fmt.Errorf("файл записан с искажениями — повторите импорт")
	}
	version, counts, total := parseAntiSpamRuleNames(data)
	res.Version = version
	if res.Version == "" {
		res.Version = "local"
	}
	res.RuleSize = len(written)
	res.RuleSHA = sha256Hex(written)
	res.TotalRules = total
	res.Counts = counts
	res.Groups = antiSpamGroupsFromCounts(counts)
	res.InstalledAt = time.Now().Format("2006-01-02 15:04:05")
	res.Steps = append(res.Steps, "3. База установлена в "+rulePath)
	st.Version = res.Version
	st.InstalledAt = res.InstalledAt
	st.RulePath = rulePath
	st.RulesDir = rulesDir
	st.KerioDir = kerioDir
	st.RuleSHA = res.RuleSHA
	st.RuleSize = res.RuleSize
	st.Counts = counts
	antiSpamAppendHistory(&st, "import", res.Version, "локальный файл "+filepath.Base(srcPath))
	if err := saveAntiSpamStateLocked(certsDir, st); err != nil {
		res.Warnings = append(res.Warnings, "состояние не сохранено: "+err.Error())
	}
	if restart {
		if rerr := PlatformControlKerioService("restart"); rerr != nil {
			res.RestartError = rerr.Error()
			res.Warnings = append(res.Warnings, "KerioMailServer не перезапущен: "+rerr.Error())
		} else {
			res.Restarted = true
			res.Steps = append(res.Steps, "4. Служба Kerio MailServer перезапущена.")
		}
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Автообновление
// ---------------------------------------------------------------------------

type AntiSpamAutoOptions struct {
	Action        string `json:"action"` // enable | disable | run-now
	IntervalHours int    `json:"intervalHours"`
	KerioDir      string `json:"kerioDir"`
	RulesDir      string `json:"rulesDir"`
}

func RunScheduledAntiSpamUpdate(certsDir string, force bool, emit func(level, msg string)) error {
	if emit == nil {
		emit = func(string, string) {}
	}
	st := LoadAntiSpamState(certsDir)
	if !st.AutoUpdate && !force {
		emit("info", "Автообновление антиспам-базы выключено в настройках — выход.")
		return nil
	}
	ctx := AntiSpamInstallOptions{KerioDir: st.KerioDir, RulesDir: st.RulesDir, Restart: true}
	remote, err := fetchAntiSpamManifest()
	if err != nil {
		st.LastError = err.Error()
		st.LastCheckAt = time.Now().Format("2006-01-02 15:04:05")
		_ = SaveAntiSpamState(certsDir, st)
		emit("error", "Антиспам-база: "+err.Error())
		return err
	}
	st.LastCheckAt = time.Now().Format("2006-01-02 15:04:05")
	st.LastRemoteVersion = remote.Manifest.Version
	if st.Version != "" && compareAntiSpamVersions(remote.Manifest.Version, st.Version) <= 0 {
		emit("info", fmt.Sprintf("Антиспам-база актуальна: установлена %s, на GitHub %s.", st.Version, remote.Manifest.Version))
		_ = SaveAntiSpamState(certsDir, st)
		return nil
	}
	emit("info", fmt.Sprintf("Найдено обновление антиспам-базы: %s → %s. Устанавливаю…", st.Version, remote.Manifest.Version))
	res, err := InstallAntiSpamDB(certsDir, ctx)
	if err != nil {
		emit("error", "Антиспам-база не обновлена: "+err.Error())
		return err
	}
	emit("success", fmt.Sprintf("Антиспам-база обновлена до %s (%d правил). Перезапуск Kerio: %v.",
		res.Version, res.TotalRules, res.Restarted))
	return nil
}

// ---------------------------------------------------------------------------
// Проверка письма по локальным спискам (dry-run)
// ---------------------------------------------------------------------------

type AntiSpamMatch struct {
	Group  string  `json:"group"`
	Rule   string  `json:"rule"`
	Value  string  `json:"value"`
	Weight float64 `json:"weight"`
}

type AntiSpamEmailTestResult struct {
	OK         bool            `json:"ok"`
	Score      float64         `json:"score"`
	Verdict    string          `json:"verdict"`
	Level      string          `json:"level"` // clean | likely | spam
	From       string          `json:"from"`
	FromDomain string          `json:"fromDomain"`
	Subject    string          `json:"subject"`
	Matches    []AntiSpamMatch `json:"matches"`
	Notes      []string        `json:"notes"`
	RulesHit   int             `json:"rulesHit"`
}

func readListSet(path string) map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[strings.ToLower(line)] = true
	}
	return out
}

func readListSlice(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.ToLower(line))
	}
	return out
}

var htmlTagRe = regexp.MustCompile(`(?s)<[^>]+>`)
var urlHostRe = regexp.MustCompile(`(?i)https?://([a-z0-9._\-]+)`)

func parseEmailForAntiSpam(raw string) (from, subject, body string, hosts []string, ips []string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		// Мягкий разбор: пользователь мог вставить только фрагмент письма
		for _, line := range strings.Split(raw, "\n") {
			low := strings.ToLower(line)
			switch {
			case strings.HasPrefix(low, "from:"):
				from = strings.TrimSpace(line[5:])
			case strings.HasPrefix(low, "subject:"):
				subject = strings.TrimSpace(line[8:])
			}
		}
		body = raw
	} else {
		from = msg.Header.Get("From")
		subject = msg.Header.Get("Subject")
		bodyBytes, _ := io.ReadAll(io.LimitReader(msg.Body, 2*1024*1024))
		body = string(bodyBytes)
		if strings.Contains(strings.ToLower(msg.Header.Get("Content-Transfer-Encoding")), "quoted-printable") {
			if decoded, derr := io.ReadAll(mimeqp.NewReader(strings.NewReader(body))); derr == nil {
				body = string(decoded)
			}
		}
		for _, h := range msg.Header["Received"] {
			ips = append(ips, extractIPs(h)...)
		}
		if len(ips) == 0 {
			ips = extractIPs(raw)
		}
	}
	dec := new(mimeWordDecoder)
	from = dec.decode(from)
	subject = dec.decode(subject)
	body = htmlTagRe.ReplaceAllString(body, " ")

	plain := strings.ToLower(from + "\n" + subject + "\n" + body)
	for _, m := range urlHostRe.FindAllStringSubmatch(plain, -1) {
		hosts = append(hosts, strings.ToLower(strings.TrimSuffix(m[1], ".")))
	}
	ips = append(ips, extractIPs(body)...)
	return from, subject, body, hosts, uniqueStrings(ips)
}

var ipv4Re = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

func extractIPs(text string) []string {
	var out []string
	for _, m := range ipv4Re.FindAllStringSubmatch(text, -1) {
		if ip := net.ParseIP(m[1]); ip != nil {
			out = append(out, m[1])
		}
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

type mimeWordDecoder struct {
	dec mime.WordDecoder
}

func (m *mimeWordDecoder) decode(s string) string {
	if s == "" {
		return s
	}
	out, err := m.dec.DecodeHeader(s)
	if err != nil {
		return s
	}
	return out
}

func extractEmailAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if addr, err := mail.ParseAddress(raw); err == nil {
		return strings.ToLower(addr.Address)
	}
	if m := regexp.MustCompile(`<([^<>\s]+@[^<>\s]+)>`).FindStringSubmatch(raw); len(m) == 2 {
		return strings.ToLower(m[1])
	}
	if m := regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9._\-]+\.[A-Za-z]{2,}`).FindString(raw); m != "" {
		return strings.ToLower(m)
	}
	return ""
}

func domainOfEmail(addr string) string {
	addr = strings.TrimSpace(strings.ToLower(addr))
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		addr = addr[i+1:]
	}
	addr = strings.Trim(addr, "<> \t\"'")
	return strings.TrimSuffix(addr, ".")
}

func TestEmailAgainstAntiSpamDB(certsDir, rawEmail string) (*AntiSpamEmailTestResult, error) {
	listsDir := antiSpamListsDir(certsDir)
	if !dirExists(listsDir) {
		return nil, fmt.Errorf("локальные списки базы не найдены. Сначала установите базу (кнопка «Установить базу с GitHub»).")
	}
	domains := readListSet(filepath.Join(listsDir, "spam-domains.txt"))
	links := readListSet(filepath.Join(listsDir, "phishing-links.txt"))
	if len(links) == 0 {
		// старая схема базы: ссылки лежали в spam-domains.txt
		links = domains
	}
	emails := readListSet(filepath.Join(listsDir, "spam-emails.txt"))
	allow := readListSet(filepath.Join(listsDir, "allowlist.txt"))
	subjects := readListSlice(filepath.Join(listsDir, "scam-subjects.txt"))
	phrases := readListSlice(filepath.Join(listsDir, "scam-phrases-ru.txt"))
	ipCIDRs := readListSlice(filepath.Join(listsDir, "threat-ips.txt"))

	from, subject, body, hosts, ips := parseEmailForAntiSpam(rawEmail)
	if strings.TrimSpace(from) == "" && strings.TrimSpace(subject) == "" && strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("письмо пустое — вставьте исходник письма (From, Subject, тело)")
	}
	res := &AntiSpamEmailTestResult{OK: true, From: from, Subject: subject}
	res.FromDomain = domainOfEmail(extractEmailAddress(from))

	lowerSubject := strings.ToLower(subject)
	lowerBody := strings.ToLower(body)

	// Белый список
	allowHit := false
	for d := range allow {
		if res.FromDomain == d || strings.HasSuffix(res.FromDomain, "."+d) {
			res.Matches = append(res.Matches, AntiSpamMatch{Group: "Белый список", Rule: "KCM_ALLOW_FROM", Value: d, Weight: -6})
			allowHit = true
			break
		}
	}
	if !allowHit && res.FromDomain != "" {
		for d := range domains {
			if res.FromDomain == d || strings.HasSuffix(res.FromDomain, "."+d) {
				res.Matches = append(res.Matches, AntiSpamMatch{Group: "Домен отправителя", Rule: "KCM_SPAM_FROM_DOMAIN", Value: d, Weight: 3.2})
				break
			}
		}
	}
	if addr := extractEmailAddress(from); addr != "" {
		if emails[addr] {
			res.Matches = append(res.Matches, AntiSpamMatch{Group: "Адрес отправителя", Rule: "KCM_SPAM_FROM_EMAIL", Value: addr, Weight: 4.5})
		}
	}
	subjectHits := 0
	for _, tpl := range subjects {
		if tpl == "" || subjectHits >= 3 {
			continue
		}
		if strings.Contains(lowerSubject, tpl) {
			res.Matches = append(res.Matches, AntiSpamMatch{Group: "Тема письма", Rule: "KCM_SCAM_SUBJECT", Value: tpl, Weight: 1.8})
			subjectHits++
		}
	}
	phraseHits := 0
	for _, ph := range phrases {
		if ph == "" || phraseHits >= 3 {
			continue
		}
		if strings.Contains(lowerBody, ph) {
			res.Matches = append(res.Matches, AntiSpamMatch{Group: "Тело письма", Rule: "KCM_SCAM_PHRASE", Value: ph, Weight: 1.5})
			phraseHits++
		}
	}
	urlHits := 0
	for _, h := range hosts {
		if urlHits >= 2 {
			break
		}
		if links[h] {
			res.Matches = append(res.Matches, AntiSpamMatch{Group: "Ссылка в письме", Rule: "KCM_PHISH_URL", Value: h, Weight: 2.5})
			urlHits++
		}
	}
	ipHits := 0
	for _, rawIP := range ips {
		ip := net.ParseIP(rawIP)
		if ip == nil {
			continue
		}
		for _, cidr := range ipCIDRs {
			mask := cidr
			if !strings.Contains(mask, "/") {
				mask += "/32"
			}
			_, netw, cerr := net.ParseCIDR(mask)
			if cerr == nil && netw.Contains(ip) {
				res.Matches = append(res.Matches, AntiSpamMatch{
					Group: "IP в заголовках Received", Rule: "KCM_SPAM_SRC_IP", Value: rawIP + " ∈ " + mask, Weight: 3.0,
				})
				ipHits++
				break
			}
		}
		if ipHits >= 2 {
			break
		}
	}
	if len(hosts) > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("Найдено ссылок/доменов в письме: %d.", len(hosts)))
	}
	if len(ips) > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("Найдено IP в заголовках: %d.", len(ips)))
	}

	total := 0.0
	for _, m := range res.Matches {
		total += m.Weight
	}
	if total < 0 {
		total = 0
	}
	res.Score = total
	res.RulesHit = len(res.Matches)
	switch {
	case total >= 5:
		res.Level = "spam"
		res.Verdict = fmt.Sprintf("🚫 СПАМ: %.1f очков — Kerio отклонит письмо (порог отказа обычно 5.0).", total)
	case total >= 3:
		res.Level = "likely"
		res.Verdict = fmt.Sprintf("⚠️ ВЕРОЯТНО СПАМ: %.1f очков — письмо будет помечено или попало бы в карантин.", total)
	default:
		res.Level = "clean"
		res.Verdict = fmt.Sprintf("✅ ЧИСТО: %.1f очков — база не считает письмо спамом.", total)
	}
	if allowHit {
		res.Notes = append(res.Notes, "Сработал белый список: −6 очков за доверенного отправителя.")
	}
	res.Notes = append(res.Notes,
		"Расчёт предварительный: Kerio SpamAssassin складывает эти очки с собственными правилами (SPF/DKIM/DNSBL/байесовский фильтр).",
		"Точный итоговый score смотрите в заголовке X-Spam-Score доставленного письма.")
	return res, nil
}

// ---------------------------------------------------------------------------
// Опционально: просмотр DNSBL-списков Kerio через Admin API (только чтение)
// ---------------------------------------------------------------------------

type KerioBlacklistEntry struct {
	ID          int    `json:"id"`
	Enabled     bool   `json:"enabled"`
	DNSSuffix   string `json:"dnsSuffix"`
	Description string `json:"description"`
	Action      string `json:"action"`
}

// KerioListBlacklists читает DNSBL-списки Kerio (Content.getBlackListList).
// Метод только читает настройки — ничего в Kerio не меняет.
func KerioListBlacklists(client *KerioClient) ([]KerioBlacklistEntry, error) {
	raw, err := client.rpc("Content.getBlackListList", nil)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		List []struct {
			ID struct {
				ID int `json:"id"`
			} `json:"id"`
			Enabled     bool   `json:"enabled"`
			DNSSuffix   string `json:"dnsSuffix"`
			Description string `json:"description"`
			Action      any    `json:"action"`
		} `json:"list"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("не удалось разобрать ответ Content.getBlackListList: %w", err)
	}
	out := make([]KerioBlacklistEntry, 0, len(parsed.List))
	for _, item := range parsed.List {
		act := ""
		if m, ok := item.Action.(map[string]any); ok {
			for _, key := range []string{"action", "type", "mode"} {
				if v, ok2 := m[key]; ok2 {
					act = fmt.Sprint(v)
					break
				}
			}
		}
		out = append(out, KerioBlacklistEntry{
			ID:          item.ID.ID,
			Enabled:     item.Enabled,
			DNSSuffix:   item.DNSSuffix,
			Description: item.Description,
			Action:      act,
		})
	}
	return out, nil
}
