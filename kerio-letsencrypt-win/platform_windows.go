//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	shell32DLL          = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin   = shell32DLL.NewProc("IsUserAnAdmin")
	procShellExecuteW   = shell32DLL.NewProc("ShellExecuteW")
	user32DLL           = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW     = user32DLL.NewProc("MessageBoxW")
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

// LaunchDesktopGUI opens a frameless native-style Windows app window (Edge App Mode / Chrome App Mode) with automatic fallback to default browser.
func LaunchDesktopGUI(appURL string) {
	appBrowsers := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("LocalAppData"), `Google\Chrome\Application\chrome.exe`),
	}

	for _, bin := range appBrowsers {
		if bin == "" {
			continue
		}
		if st, err := os.Stat(bin); err == nil && !st.IsDir() {
			cmd := exec.Command(
				bin,
				"--app="+appURL,
				"--window-size=1240,880",
				"--proxy-bypass-list=<-loopback>",
				"--disable-features=Translate",
			)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			if err := cmd.Start(); err == nil {
				return
			}
		}
	}

	// Universal Windows fallback (opens default browser even on Server 2012 R2 / 2016 without Chromium)
	fallback := exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", appURL)
	fallback.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = fallback.Start()
}
