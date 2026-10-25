//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
)

var (
	kernel32DLL               = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandle       = kernel32DLL.NewProc("GetModuleHandleW")
	shell32DLL                = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin         = shell32DLL.NewProc("IsUserAnAdmin")
	procShellExecuteW         = shell32DLL.NewProc("ShellExecuteW")
	user32DLL                 = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW           = user32DLL.NewProc("MessageBoxW")
	procLoadImageW            = user32DLL.NewProc("LoadImageW")
	procPostMessageW          = user32DLL.NewProc("PostMessageW")
	procGetSystemMetrics      = user32DLL.NewProc("GetSystemMetrics")
	procSystemParametersInfoW = user32DLL.NewProc("SystemParametersInfoW")

	activeWebViewMu sync.Mutex
	activeWebView   webview2.WebView

	// Кэш сведений о службе и реестре: поиск путей вызывается часто (статус,
	// диагностика, предпросмотр), а каждый вызов — это запуск sc.exe/reg.exe.
	kerioSysCacheMu             sync.Mutex
	kerioSysCacheAt             time.Time
	kerioSysCacheServiceName    string
	kerioSysCacheServiceCmd     string
	kerioSysCacheServiceQueried bool
	kerioSysCacheRegDirs        []string
	kerioSysCacheRegQueried     bool
)

const scheduledTaskName = "KerioLetsEncryptAutoRenew"

func DefaultCertsRoot() string {
	exe, err := os.Executable()
	if err == nil {
		return filepath.Join(filepath.Dir(exe), "certs")
	}
	return "certs"
}

func IsRunningAsAdmin() bool {
	ret, _, _ := procIsUserAnAdmin.Call()
	return ret != 0
}

func RelaunchAsAdmin(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	paramStr := strings.Join(args, " ")
	params, _ := syscall.UTF16PtrFromString(paramStr)
	dir, _ := syscall.UTF16PtrFromString(filepath.Dir(exe))

	ret, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(dir)),
		1, // SW_SHOWNORMAL
	)
	if ret <= 32 {
		return fmt.Errorf("пользователь отменил повышение прав UAC или произошла ошибка запуска (код %d)", ret)
	}
	return nil
}

func ShowWindowsMessageBox(title, message string) {
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(message)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x00000040)
}

func runHiddenCmd(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}

// kerioServiceNames — имена службы Kerio Connect в разных версиях и разрядностях.
var kerioServiceNames = []string{
	"KerioMailServer",
	"KerioConnect",
	"Kerio Connect",
	"KerioConnectService",
}

// PlatformKerioServiceImagePath возвращает имя службы Kerio и её команду
// запуска (BINARY_PATH_NAME). Это самый надёжный источник пути: если Kerio
// поставили в D:\Kerio, в реестре «InstallPath» может не быть, а в команде
// службы путь есть всегда. Строка вида:
//
//	"C:\Program Files\Kerio\MailServer\mailserver.exe" -dir "C:\Program Files\Kerio\MailServer"
func PlatformKerioServiceImagePath() (string, string) {
	kerioSysCacheMu.Lock()
	if time.Since(kerioSysCacheAt) < kerioSysCacheTTL && kerioSysCacheServiceQueried {
		name, cmd := kerioSysCacheServiceName, kerioSysCacheServiceCmd
		kerioSysCacheMu.Unlock()
		return name, cmd
	}
	kerioSysCacheMu.Unlock()

	name, cmd := detectKerioServiceImagePath()

	kerioSysCacheMu.Lock()
	kerioSysCacheServiceName, kerioSysCacheServiceCmd = name, cmd
	kerioSysCacheServiceQueried = true
	kerioSysCacheAt = time.Now()
	kerioSysCacheMu.Unlock()
	return name, cmd
}

// detectKerioServiceImagePath — сам поиск (без кэша).
func detectKerioServiceImagePath() (string, string) {
	for _, name := range kerioServiceNames {
		out, err := runHiddenCmd("sc", "qc", name)
		if err != nil {
			continue
		}
		if cmd := parseScBinaryPath(string(out)); cmd != "" {
			return name, cmd
		}
	}
	// Резерв: значение ImagePath прямо из реестра (если sc недоступен).
	for _, name := range kerioServiceNames {
		out, err := runHiddenCmd("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Services\`+name, "/v", "ImagePath")
		if err != nil {
			continue
		}
		if cmd := parseRegSZ(string(out)); cmd != "" {
			return name, cmd
		}
	}
	// И напоследок — поиск службы по имени среди всех служб системы.
	if out, err := runHiddenCmd("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Services`, "/f", "Kerio", "/k"); err == nil {
		for _, name := range parseKerioServiceNames(string(out)) {
			if scOut, err := runHiddenCmd("sc", "qc", name); err == nil {
				if cmd := parseScBinaryPath(string(scOut)); cmd != "" {
					return name, cmd
				}
			}
		}
	}
	return "", ""
}

// PlatformKerioRegistryDirs — пути, найденные в реестре: значения Kerio
// (InstallPath, Path, InstallDir, Home, Directory) и сведения об удалении
// из «Программы и компоненты» (InstallLocation).
func PlatformKerioRegistryDirs() []string {
	kerioSysCacheMu.Lock()
	if time.Since(kerioSysCacheAt) < kerioSysCacheTTL && kerioSysCacheRegQueried {
		dirs := append([]string(nil), kerioSysCacheRegDirs...)
		kerioSysCacheMu.Unlock()
		return dirs
	}
	kerioSysCacheMu.Unlock()

	dirs := detectKerioRegistryDirs()

	kerioSysCacheMu.Lock()
	kerioSysCacheRegDirs = append([]string(nil), dirs...)
	kerioSysCacheRegQueried = true
	kerioSysCacheAt = time.Now()
	kerioSysCacheMu.Unlock()
	return dirs
}

func detectKerioRegistryDirs() []string {
	var dirs []string
	seen := map[string]bool{}
	add := func(p string) {
		p = normalizeKerioPath(p)
		if p == "" {
			return
		}
		key := strings.ToLower(filepath.ToSlash(p))
		if seen[key] {
			return
		}
		seen[key] = true
		dirs = append(dirs, p)
	}

	keys := []string{
		`HKLM\SOFTWARE\Kerio\MailServer`,
		`HKLM\SOFTWARE\WOW6432Node\Kerio\MailServer`,
		`HKLM\SOFTWARE\Kerio\Connect`,
		`HKLM\SOFTWARE\WOW6432Node\Kerio\Connect`,
		`HKLM\SOFTWARE\Kerio`,
		`HKLM\SOFTWARE\WOW6432Node\Kerio`,
	}
	for _, key := range keys {
		out, err := runHiddenCmd("reg", "query", key, "/s")
		if err != nil {
			continue
		}
		for _, p := range parseKerioPathValues(string(out)) {
			add(p)
		}
	}

	// Записи «Программы и компоненты» — там есть InstallLocation.
	for _, root := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	} {
		out, err := runHiddenCmd("reg", "query", root, "/f", "Kerio", "/k", "/s")
		if err != nil {
			continue
		}
		for _, p := range parseInstallLocationValues(string(out)) {
			add(p)
		}
	}
	return dirs
}

// PlatformKerioSearchRoots — «широкие» каталоги, которые просматриваются,
// если папку установки определить не удалось (portable-сборка, нет службы).
func PlatformKerioSearchRoots() []string {
	var roots []string
	seen := map[string]bool{}
	add := func(p string) {
		p = normalizeKerioPath(p)
		if p == "" {
			return
		}
		key := strings.ToLower(filepath.ToSlash(p))
		if seen[key] {
			return
		}
		seen[key] = true
		roots = append(roots, p)
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"} {
		if base := strings.TrimSpace(os.Getenv(env)); base != "" {
			add(filepath.Join(base, "Kerio"))
		}
	}
	for _, drv := range []string{"C:", "D:", "E:", "F:", "G:"} {
		add(filepath.Join(drv+`\`, "Kerio"))
		add(filepath.Join(drv+`\`, "Program Files", "Kerio"))
		add(filepath.Join(drv+`\`, "Program Files (x86)", "Kerio"))
	}
	return roots
}

func PlatformCandidateKerioDirs() []string {
	var dirs []string
	add := func(p string) { dirs = append(dirs, p) }

	// 1. Точный путь из команды запуска службы (переживает нестандартные диски).
	if _, cmd := PlatformKerioServiceImagePath(); cmd != "" {
		for _, d := range kerioDirsFromServiceCommand(cmd) {
			add(d)
		}
	}

	// 2. Значения реестра Kerio.
	for _, d := range PlatformKerioRegistryDirs() {
		add(d)
	}

	// 3. Переменные окружения Windows (работают и при нестандартном ProgramFiles).
	for _, env := range []string{"ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"} {
		if base := strings.TrimSpace(os.Getenv(env)); base != "" {
			add(filepath.Join(base, "Kerio", "MailServer"))
		}
	}

	// 4. Стандартные пути на всех разумных дисках.
	for _, drv := range []string{"C:", "D:", "E:", "F:", "G:"} {
		add(filepath.Join(drv+`\`, "Program Files", "Kerio", "MailServer"))
		add(filepath.Join(drv+`\`, "Program Files (x86)", "Kerio", "MailServer"))
		add(filepath.Join(drv+`\`, "Kerio", "MailServer"))
		add(filepath.Join(drv+`\`, "MailServer"))
	}
	return dirs
}

// kerioServiceNameCache — имя найденной службы кэшируем, чтобы не гонять
// sc/reg при каждом обновлении карточки.
var (
	kerioServiceNameMu  sync.Mutex
	kerioServiceNameVal string
	kerioServiceNameAt  time.Time
	kerioServiceNameTTL = 60 * time.Second
)

// PlatformKerioServiceName возвращает имя реально установленной службы Kerio.
//
// Раньше start/stop/restart жёстко использовали «KerioMailServer», поэтому на
// серверах, где служба называется иначе (KerioConnect, «Kerio Connect»), любая
// команда падала с «Служба не запущена» / «The service name is invalid».
func PlatformKerioServiceName() string {
	kerioServiceNameMu.Lock()
	if time.Since(kerioServiceNameAt) < kerioServiceNameTTL && kerioServiceNameVal != "" {
		name := kerioServiceNameVal
		kerioServiceNameMu.Unlock()
		return name
	}
	kerioServiceNameMu.Unlock()

	name := detectKerioServiceName()

	kerioServiceNameMu.Lock()
	if name != "" {
		kerioServiceNameVal = name
		kerioServiceNameAt = time.Now()
	}
	kerioServiceNameMu.Unlock()
	return name
}

// ResetKerioServiceNameCache сбрасывает кэш имени службы (после её установки
// или удаления, чтобы карточка Kerio не показывала старое состояние).
func ResetKerioServiceNameCache() {
	kerioServiceNameMu.Lock()
	kerioServiceNameVal = ""
	kerioServiceNameAt = time.Time{}
	kerioServiceNameMu.Unlock()
}

func detectKerioServiceName() string {
	// 1. Служба, у которой в команде запуска есть путь к Kerio.
	if name, cmd := PlatformKerioServiceImagePath(); name != "" && cmd != "" {
		return name
	}
	// 2. Любая из известных служб, которая реально отвечает.
	for _, name := range kerioServiceNames {
		if _, ok := scQueryState(name); ok {
			return name
		}
	}
	// 3. Поиск службы по имени среди всех служб системы.
	if out, err := runHiddenCmd("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Services`, "/f", "Kerio", "/k"); err == nil {
		for _, name := range parseKerioServiceNames(DecodeWindowsConsole(out)) {
			if _, ok := scQueryState(name); ok {
				return name
			}
		}
	}
	return ""
}

// scQueryState запускает `sc query <name>` и возвращает числовой код состояния.
// Используем именно код (1 STOPPED, 4 RUNNING), а не слова: `sc` печатает
// STATE : 4 RUNNING без перевода, но полагаться на локализацию всё равно
// не стоит — цифра одинакова на любой Windows.
func scQueryState(name string) (int, bool) {
	if strings.TrimSpace(name) == "" {
		return 0, false
	}
	out, err := runHiddenCmd("sc", "query", name)
	if err != nil {
		return 0, false
	}
	code, ok := parseScStateCode(DecodeWindowsConsole(out))
	return code, ok
}

// Числовые состояния службы Windows (sc.exe, поле STATE).
const (
	scStateStopped      = 1
	scStateStartPending = 2
	scStateStopPending  = 3
	scStateRunning      = 4
	scStateContinuePend = 5
	scStatePausePending = 6
	scStatePaused       = 7
)

// PlatformKerioServiceStatus — состояние службы Kerio на Windows.
func PlatformKerioServiceStatus() string {
	name := PlatformKerioServiceName()
	if name == "" {
		return "NOT_INSTALLED"
	}
	code, ok := scQueryState(name)
	if !ok {
		return "UNKNOWN"
	}
	switch code {
	case scStateRunning, scStateContinuePend:
		return "RUNNING"
	case scStateStopped, scStateStopPending, scStateStartPending, scStatePaused, scStatePausePending:
		return "STOPPED"
	}
	return "UNKNOWN"
}

// platformAdminHint — подсказка, если Windows отказала в доступе.
func platformAdminHint() string {
	if IsRunningAsAdmin() {
		return "Запустите программу заново: возможно, служба защищена политикой или ещё не завершила предыдущую команду."
	}
	return "Нужны права администратора: закройте программу и запустите её через «Запуск от имени администратора»."
}

// serviceCmdDetail превращает вывод консольной команды в одну читаемую строку.
// Никаких «exit status 2» в интерфейсе: пользователю нужен смысл, а не код.
func serviceCmdDetail(out []byte, err error) string {
	detail := CleanConsoleOutput(out)
	if detail != "" {
		return detail
	}
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "exit status") {
		if code, convErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(msg, "exit status"))); convErr == nil {
			switch code {
			case 2:
				return "Windows не распознала службу (код 2)."
			case 5:
				return "Windows отказала в доступе (код 5)."
			case 1060, 1062:
				return "Служба не установлена (код " + strconv.Itoa(code) + ")."
			default:
				return "команда завершилась с кодом " + strconv.Itoa(code)
			}
		}
	}
	return msg
}

// waitServiceState ждёт нужного состояния службы (Кеrio стартует 10–30 секунд).
func waitServiceState(name string, want int, timeout time.Duration) (int, bool) {
	deadline := time.Now().Add(timeout)
	last := 0
	for {
		if code, ok := scQueryState(name); ok {
			last = code
			if code == want {
				return code, true
			}
		}
		if time.Now().After(deadline) {
			return last, false
		}
		time.Sleep(700 * time.Millisecond)
	}
}

func kerioServiceStart(name string) error {
	if code, ok := scQueryState(name); ok && code == scStateRunning {
		return nil
	}
	out, err := runHiddenCmd("sc", "start", name)
	if code, ok := waitServiceState(name, scStateRunning, 90*time.Second); ok && code == scStateRunning {
		return nil
	}
	detail := serviceCmdDetail(out, err)
	msg := "не удалось запустить службу «" + name + "»"
	if detail != "" {
		msg += ": " + detail
	}
	return fmt.Errorf("%s. %s", msg, platformAdminHint())
}

func kerioServiceStop(name string) error {
	if code, ok := scQueryState(name); ok && code == scStateStopped {
		return nil
	}
	out, err := runHiddenCmd("sc", "stop", name)
	if code, ok := waitServiceState(name, scStateStopped, 60*time.Second); ok && code == scStateStopped {
		return nil
	}
	detail := serviceCmdDetail(out, err)
	msg := "не удалось остановить службу «" + name + "»"
	if detail != "" {
		msg += ": " + detail
	}
	return fmt.Errorf("%s. %s", msg, platformAdminHint())
}

// PlatformControlKerioService — stop/start/restart службы Kerio Connect.
//
// Важно: команда выполняется через `sc`, а готовность определяется по числовому
// состоянию, а не по тексту сообщения. `net stop`/`net start` печатают
// локализованные фразы, поэтому раньше на русской Windows любая попытка
// заканчивалась «exit status 2» с нечитаемым текстом.
func PlatformControlKerioService(action string) error {
	switch action {
	case "start", "stop", "restart":
	default:
		return fmt.Errorf("неизвестное действие службы: %s", action)
	}

	name := PlatformKerioServiceName()
	if name == "" {
		return fmt.Errorf("служба Kerio Connect не найдена на этом компьютере. Проверьте, что Kerio Connect установлен " +
			"(служба обычно называется KerioMailServer или KerioConnect) — или запустите программу на самом сервере Kerio. " +
			"Если Kerio работает на Linux, используйте карточку «Kerio Connect на Linux».")
	}

	if action == "stop" {
		return kerioServiceStop(name)
	}
	if action == "start" {
		return kerioServiceStart(name)
	}
	// restart: если служба не запущена, останавливать нечего — просто стартуем.
	if code, ok := scQueryState(name); !ok || code != scStateRunning {
		return kerioServiceStart(name)
	}
	if err := kerioServiceStop(name); err != nil {
		return err
	}
	return kerioServiceStart(name)
}

func PlatformOpenFolderInExplorer(path string) error {
	target := filepath.Clean(path)
	st, err := os.Stat(target)
	if err == nil && !st.IsDir() {
		cmd := exec.Command("explorer.exe", "/select,", target)
		return cmd.Start()
	}
	cmd := exec.Command("explorer.exe", target)
	return cmd.Start()
}

func PlatformBrowseFolderDialog(prompt string) (string, error) {
	psScript := `Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.FolderBrowserDialog; $f.Description = "` + strings.ReplaceAll(prompt, `"`, "") + `"; $f.ShowNewFolderButton = $true; if ($f.ShowDialog() -eq 'OK') { Write-Output $f.SelectedPath }`
	out, err := runHiddenCmd("powershell.exe", "-NoProfile", "-STA", "-Command", psScript)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func PlatformInstallAutoRenewTask(intervalHours int) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	taskCmd := fmt.Sprintf(`"%s" --renew`, exe)
	args := []string{"/Create", "/F", "/RU", "SYSTEM", "/RL", "HIGHEST", "/TN", scheduledTaskName, "/TR", taskCmd}
	if intervalHours > 0 && intervalHours < 24 {
		args = append(args, "/SC", "HOURLY", "/MO", fmt.Sprintf("%d", intervalHours))
	} else {
		args = append(args, "/SC", "DAILY", "/ST", "03:15")
	}
	out, err := runHiddenCmd("schtasks.exe", args...)
	if err != nil {
		return "", fmt.Errorf("не удалось создать задачу в Планировщике Windows (запустите программу от имени Администратора): %s", strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("Задача автопродления «%s» успешно зарегистрирована в Планировщике заданий Windows!", scheduledTaskName), nil
}

func PlatformRemoveAutoRenewTask() (string, error) {
	out, err := runHiddenCmd("schtasks.exe", "/Delete", "/F", "/TN", scheduledTaskName)
	if err != nil {
		return "", fmt.Errorf("задача не найдена или требуются права Администратора: %s", strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("Задача автопродления «%s» удалена из Планировщика Windows.", scheduledTaskName), nil
}

func PlatformQueryAutoRenewTask() bool {
	_, err := runHiddenCmd("schtasks.exe", "/Query", "/TN", scheduledTaskName)
	return err == nil
}

func PlatformInstallAntiSpamTask(intervalHours int) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	taskCmd := fmt.Sprintf(`"%s" --antispam-update`, exe)
	args := []string{"/Create", "/F", "/RU", "SYSTEM", "/RL", "HIGHEST", "/TN", antiSpamTaskName, "/TR", taskCmd}
	if intervalHours > 0 && intervalHours < 24 {
		args = append(args, "/SC", "HOURLY", "/MO", fmt.Sprintf("%d", intervalHours))
	} else {
		args = append(args, "/SC", "DAILY", "/ST", "04:10")
	}
	out, err := runHiddenCmd("schtasks.exe", args...)
	if err != nil {
		return "", fmt.Errorf("не удалось создать задачу автообновления базы (запустите программу от имени Администратора): %s", strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("Задача автообновления антиспам-базы «%s» зарегистрирована в Планировщике заданий Windows!", antiSpamTaskName), nil
}

func PlatformRemoveAntiSpamTask() (string, error) {
	out, err := runHiddenCmd("schtasks.exe", "/Delete", "/F", "/TN", antiSpamTaskName)
	if err != nil {
		return "", fmt.Errorf("задача автообновления не найдена или требуются права Администратора: %s", strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("Задача автообновления «%s» удалена из Планировщика Windows.", antiSpamTaskName), nil
}

func PlatformQueryAntiSpamTask() bool {
	_, err := runHiddenCmd("schtasks.exe", "/Query", "/TN", antiSpamTaskName)
	return err == nil
}

func PlatformOpenTempFirewallPort(port int) func() {
	ruleName := fmt.Sprintf("KerioCertManager_ACME_TCP_%d", port)
	_, _ = runHiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	_, err := runHiddenCmd(
		"netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=in",
		"action=allow",
		"protocol=TCP",
		fmt.Sprintf("localport=%d", port),
	)
	if err != nil {
		return func() {}
	}
	return func() {
		_, _ = runHiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	}
}

func CloseDesktopWindow() {
	activeWebViewMu.Lock()
	wv := activeWebView
	activeWebViewMu.Unlock()
	if wv != nil {
		wv.Destroy()
	}
}

func PlatformApplyWindowIcon(iconID int) {
	if iconID < 1 || iconID > 4 {
		iconID = 1
	}
	activeWebViewMu.Lock()
	wv := activeWebView
	activeWebViewMu.Unlock()
	if wv == nil {
		return
	}
	hwnd := uintptr(wv.Window())
	if hwnd == 0 {
		return
	}
	hMod, _, _ := procGetModuleHandle.Call(0)
	// IMAGE_ICON = 1, LR_DEFAULTSIZE = 0x0040; WM_SETICON = 0x0080 (ICON_SMALL = 0, ICON_BIG = 1)
	hBig, _, _ := procLoadImageW.Call(hMod, uintptr(iconID), 1, 256, 256, 0)
	hSmall, _, _ := procLoadImageW.Call(hMod, uintptr(iconID), 1, 32, 32, 0)
	if hBig != 0 {
		procPostMessageW.Call(hwnd, 0x0080, 1, hBig)
	}
	if hSmall != 0 {
		procPostMessageW.Call(hwnd, 0x0080, 0, hSmall)
	}
}

// winRect — RECT из Win32 (рабочая область экрана без панели задач).
type winRect struct {
	Left, Top, Right, Bottom int32
}

// desktopWorkArea возвращает ширину и высоту рабочей области экрана в пикселях.
func desktopWorkArea() (int, int) {
	const spiGetWorkArea = 0x0030
	var r winRect
	if ret, _, _ := procSystemParametersInfoW.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&r)), 0); ret != 0 {
		if w, h := int(r.Right-r.Left), int(r.Bottom-r.Top); w > 0 && h > 0 {
			return w, h
		}
	}
	cx, _, _ := procGetSystemMetrics.Call(0) // SM_CXSCREEN
	cy, _, _ := procGetSystemMetrics.Call(1) // SM_CYSCREEN
	return int(cx), int(cy)
}

// adaptiveWindowSize подбирает стартовый размер окна под экран.
// На 1920x1080 остаётся привычные 1380x940, а на ноутбуке 1366x768
// (или в RDP-сессии) окно ужимается, чтобы кнопки и вкладки не уезжали
// за границы экрана. Дальше вёрстка подстраивается через CSS media queries.
func adaptiveWindowSize() (int, int) {
	const (
		preferredW, preferredH = 1380, 940
		margin                 = 48 // место под тень окна и края экрана
		minW, minH             = 640, 520
	)
	w, h := preferredW, preferredH
	if sw, sh := desktopWorkArea(); sw > 0 && sh > 0 {
		if maxW := sw - margin; w > maxW {
			w = maxW
		}
		if maxH := sh - margin; h > maxH {
			h = maxH
		}
	}
	if w < minW {
		w = minW
	}
	if h < minH {
		h = minH
	}
	return w, h
}

// RunDesktopWindow creates a true native Win32 window embedding WebView2 (blocking on main thread until window closes),
// with fallback to explorer.exe browser tab if WebView2 Runtime is missing on old Windows Server 2012/2016.
func RunDesktopWindow(appURL string) (usedNativeWindow bool) {
	runtime.LockOSThread()

	roleSuffix := "user"
	if IsRunningAsAdmin() {
		roleSuffix = "admin"
	}
	dataDir := filepath.Join(os.TempDir(), "KerioCertManagerWV2_"+roleSuffix)
	_ = os.MkdirAll(dataDir, 0700)

	// Prevent Windows 11 / UAC Admin / RDP GPU compositor freezes and bypass corporate proxy for 127.0.0.1
	_ = os.Setenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "--proxy-bypass-list=<-loopback> --disable-gpu")

	initIcon := uint(LoadSavedUISettings(DefaultCertsRoot()).SelectedIconID)
	if initIcon < 1 || initIcon > 4 {
		initIcon = 1
	}

	winW, winH := adaptiveWindowSize()

	wv := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  dataDir,
		WindowOptions: webview2.WindowOptions{
			Title:  "Kerio SSL, Mail Audit, Delist, Sanctions & AntiSpam DB Suite (v" + appVersion + ") — Zakharevich Igor",
			Width:  uint(winW),
			Height: uint(winH),
			IconId: initIcon,
			Center: true,
		},
	})
	if wv != nil {
		activeWebViewMu.Lock()
		activeWebView = wv
		activeWebViewMu.Unlock()
		PlatformApplyWindowIcon(int(initIcon))

		_ = wv.Bind("nativeCloseWindow", func() {
			wv.Destroy()
		})

		wv.Navigate(appURL)
		wv.Run()

		activeWebViewMu.Lock()
		activeWebView = nil
		activeWebViewMu.Unlock()
		return true
	}

	// Fallback if WebView2 Runtime is not installed on an older Windows Server: open normal default browser tab via explorer.exe
	fallback := exec.Command("explorer.exe", appURL)
	fallback.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = fallback.Start()
	return false
}

// startDetached запускает новую копию программы после обновления.
// Процесс не привязан к текущему: родитель сразу завершается.
func startDetached(exe string, args []string) error {
	cmd := exec.Command(exe, args...)
	cmd.Dir = filepath.Dir(exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
