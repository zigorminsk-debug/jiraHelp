//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
)

var (
	shell32DLL        = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin = shell32DLL.NewProc("IsUserAnAdmin")
	procShellExecuteW = shell32DLL.NewProc("ShellExecuteW")
	user32DLL         = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW   = user32DLL.NewProc("MessageBoxW")

	activeWebViewMu sync.Mutex
	activeWebView   webview2.WebView
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

func PlatformCandidateKerioDirs() []string {
	var dirs []string
	// 1. Check Windows Registry (64-bit & WOW6432Node)
	for _, key := range []string{
		`HKLM\SOFTWARE\Kerio\MailServer`,
		`HKLM\SOFTWARE\WOW6432Node\Kerio\MailServer`,
	} {
		out, err := runHiddenCmd("reg", "query", key, "/v", "InstallPath")
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if idx := strings.Index(line, "REG_SZ"); idx >= 0 {
					p := strings.TrimSpace(line[idx+len("REG_SZ"):])
					if p != "" {
						dirs = append(dirs, p)
					}
				}
			}
		}
	}
	// 2. Check common Windows installation drives
	for _, drv := range []string{"C:", "D:", "E:", "F:"} {
		dirs = append(dirs,
			filepath.Join(drv+`\`, "Program Files", "Kerio", "MailServer"),
			filepath.Join(drv+`\`, "Program Files (x86)", "Kerio", "MailServer"),
			filepath.Join(drv+`\`, "Kerio", "MailServer"),
		)
	}
	return dirs
}

func PlatformKerioServiceStatus() string {
	out, err := runHiddenCmd("sc", "query", "KerioMailServer")
	s := string(out)
	if err != nil || strings.Contains(s, "1060") {
		return "NOT_INSTALLED"
	}
	if strings.Contains(s, "RUNNING") {
		return "RUNNING"
	}
	if strings.Contains(s, "STOPPED") {
		return "STOPPED"
	}
	return "UNKNOWN"
}

func PlatformControlKerioService(action string) error {
	switch action {
	case "stop":
		out, err := runHiddenCmd("net", "stop", "KerioMailServer")
		if err != nil && !strings.Contains(string(out), "3521") && !strings.Contains(strings.ToLower(string(out)), "not started") {
			return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	case "start":
		out, err := runHiddenCmd("net", "start", "KerioMailServer")
		if err != nil && !strings.Contains(strings.ToLower(string(out)), "already been started") {
			return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	case "restart":
		_ = PlatformControlKerioService("stop")
		return PlatformControlKerioService("start")
	default:
		return fmt.Errorf("неизвестное действие службы: %s", action)
	}
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

	wv := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  dataDir,
		WindowOptions: webview2.WindowOptions{
			Title:  "Kerio SSL & Mail Server Manager (v2.0)",
			Width:  1300,
			Height: 920,
			IconId: 0,
			Center: true,
		},
	})
	if wv != nil {
		activeWebViewMu.Lock()
		activeWebView = wv
		activeWebViewMu.Unlock()

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
