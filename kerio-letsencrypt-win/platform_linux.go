//go:build linux

package main

// platform_linux.go — всё, что зависит от Linux.
//
// Зачем отдельный файл: Kerio Connect массово стоит на Linux, и там другие
// пути (/opt/kerio/mailserver), другая служба (systemd/init.d `kerio-connect`)
// и другие задания по расписанию (cron, а не Планировщик Windows). Раньше
// программа на Linux была «демо-режимом»: служба не перезапускалась, задания
// не создавались. Теперь всё работает по-настоящему — это и есть «поддержка
// Kerio на Linux» для случая, когда KerioCertManager запущен на самом сервере
// (режим --server-only) или когда сервер и есть рабочая станция администратора.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// platformLinuxKerioDirs — стандартные каталоги установки Kerio Connect.
var platformLinuxKerioDirs = []string{
	"/opt/kerio/mailserver",
	"/usr/local/kerio/mailserver",
}

// platformLinuxServiceNames — имена службы в разных сборках/дистрибутивах.
var platformLinuxServiceNames = []string{"kerio-connect", "kerio", "keriomailserver"}

func DefaultCertsRoot() string {
	exe, err := os.Executable()
	if err == nil {
		return filepath.Join(filepath.Dir(exe), "certs")
	}
	return "certs"
}

func IsRunningAsAdmin() bool { return os.Geteuid() == 0 }

func RelaunchAsAdmin(_ []string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	return fmt.Errorf("запустите программу через sudo: sudo ./KerioCertManager --server-only")
}

func ShowWindowsMessageBox(_, _ string) {}

// PlatformKerioServiceImagePath — путь к бинарю и имя службы.
func PlatformKerioServiceImagePath() (string, string) {
	for _, dir := range []string{"/opt/kerio/mailserver", "/usr/local/kerio/mailserver"} {
		for _, bin := range []string{"mailserver", "run/mailserver"} {
			p := filepath.Join(dir, bin)
			if fileExists(p) {
				return platformLinuxServiceName(), p
			}
		}
	}
	return "", ""
}

// platformLinuxServiceName — первое известное имя службы, которое реально есть.
func platformLinuxServiceName() string {
	for _, name := range platformLinuxServiceNames {
		if linuxServiceExists(name) {
			return name
		}
	}
	return "kerio-connect"
}

func PlatformKerioRegistryDirs() []string { return nil }

func PlatformKerioSearchRoots() []string {
	return []string{"/opt/kerio", "/usr/local/kerio"}
}

func PlatformCandidateKerioDirs() []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range platformLinuxKerioDirs {
		p := filepath.Clean(d)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// linuxServiceExists — есть ли вообще такая служба в системе.
// Без этой проверки `systemctl is-active` для несуществующего юнита отвечает
// «inactive» (код 3) — ровно как для остановленной службы, и программа
// считала бы «Kerio установлен, но остановлен» там, где Kerio нет вовсе.
func linuxServiceExists(name string) bool {
	if _, err := os.Stat("/etc/init.d/" + name); err == nil {
		return true
	}
	if !isSystemdAvailable() {
		return false
	}
	out, err := exec.Command("systemctl", "list-unit-files", name+".service").CombinedOutput()
	if err != nil && len(out) == 0 {
		return false
	}
	return strings.Contains(string(out), name+".service")
}

// platformLinuxKerioInstalled — установлен ли Kerio Connect вообще
// (по каталогу установки или по службе).
func platformLinuxKerioInstalled() bool {
	for _, dir := range platformLinuxKerioDirs {
		if dirExists(dir) {
			return true
		}
	}
	for _, name := range platformLinuxServiceNames {
		if linuxServiceExists(name) {
			return true
		}
	}
	return false
}

// PlatformKerioServiceStatus — состояние службы Kerio.
func PlatformKerioServiceStatus() string {
	if !platformLinuxKerioInstalled() {
		return "NOT_INSTALLED"
	}
	name := platformLinuxServiceName()
	if isSystemdAvailable() {
		out, err := exec.Command("systemctl", "is-active", name).CombinedOutput()
		s := strings.TrimSpace(string(out))
		switch {
		case err == nil && s == "active":
			return "RUNNING"
		case s == "inactive", s == "failed":
			return "STOPPED"
		case strings.Contains(s, "could not be found"), strings.Contains(s, "not-found"):
			// пробуем init.d
		default:
			if err == nil {
				return "RUNNING"
			}
		}
	}
	if out, err := exec.Command("service", name, "status").CombinedOutput(); err == nil {
		return "RUNNING"
	} else if strings.Contains(strings.ToLower(string(out)), "not running") ||
		strings.Contains(strings.ToLower(string(out)), "stopped") {
		return "STOPPED"
	}
	return "UNKNOWN"
}

// PlatformControlKerioService — start/stop/restart через systemd, с откатом
// на SysV init-скрипт (на старых дистрибутивах и в контейнерах).
func PlatformControlKerioService(action string) error {
	if action != "start" && action != "stop" && action != "restart" {
		return fmt.Errorf("неизвестное действие со службой: %s", action)
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("для управления службой Kerio нужны права root: запустите программу через sudo")
	}
	name := platformLinuxServiceName()

	var lastErr error
	if isSystemdAvailable() {
		if out, err := exec.Command("systemctl", action, name).CombinedOutput(); err == nil {
			return nil
		} else {
			lastErr = fmt.Errorf("systemctl %s %s: %v (%s)", action, name, err, strings.TrimSpace(string(out)))
		}
	}
	// SysV init-скрипт.
	if _, err := os.Stat("/etc/init.d/" + name); err == nil {
		if out, err := exec.Command("/etc/init.d/"+name, action).CombinedOutput(); err == nil {
			return nil
		} else {
			lastErr = fmt.Errorf("/etc/init.d/%s %s: %v (%s)", name, action, err, strings.TrimSpace(string(out)))
		}
	}
	// «service» как последняя попытка.
	if out, err := exec.Command("service", name, action).CombinedOutput(); err == nil {
		return nil
	} else if lastErr == nil {
		lastErr = fmt.Errorf("service %s %s: %v (%s)", name, action, err, strings.TrimSpace(string(out)))
	}
	return lastErr
}

func isSystemdAvailable() bool {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return true
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
}

// PlatformOpenFolderInExplorer — открыть каталог файловым менеджером.
// На сервере без графической оболочки его нет, поэтому ошибка содержит путь,
// который можно просто скопировать в терминал.
func PlatformOpenFolderInExplorer(target string) error {
	clean := strings.TrimSpace(target)
	if clean == "" {
		return fmt.Errorf("пустой путь")
	}
	if _, err := os.Stat(clean); err != nil {
		return fmt.Errorf("каталог недоступен: %w", err)
	}
	for _, opener := range []string{"xdg-open", "gio"} {
		bin, err := exec.LookPath(opener)
		if err != nil {
			continue
		}
		args := []string{clean}
		if opener == "gio" {
			args = []string{"open", clean}
		}
		cmd := exec.Command(bin, args...)
		if err := cmd.Start(); err == nil {
			_ = cmd.Process.Release()
			return nil
		}
	}
	return fmt.Errorf("нет графического файлового менеджера — путь: %s", clean)
}

func PlatformBrowseFolderDialog(_ string) (string, error) { return DefaultCertsRoot(), nil }

// --- Задания по расписанию: cron вместо Планировщика Windows ---

const linuxAutoRenewCron = "/etc/cron.d/kerio-cert-manager-autorenew"
const linuxAntiSpamCron = "/etc/cron.d/kerio-cert-manager-antispam"

// selfExePath — путь к самому файлу программы (для cron-строки).
func selfExePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "/opt/kerio-cert-manager/KerioCertManager"
	}
	return exe
}

func PlatformInstallAutoRenewTask(intervalHours int) (string, error) {
	if intervalHours <= 0 {
		intervalHours = 24
	}
	// Простое расписание: раз в сутки в 03:15 либо каждые N часов.
	line := fmt.Sprintf("15 3 * * * root %s --renew >/dev/null 2>&1", selfExePath())
	if intervalHours != 24 && intervalHours < 24 {
		line = fmt.Sprintf("15 */%d * * * root %s --renew >/dev/null 2>&1", intervalHours, selfExePath())
	}
	content := "# Автопродление сертификатов KerioCertManager (создано программой)\n" +
		"SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" + line + "\n"
	if err := os.WriteFile(linuxAutoRenewCron, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("не удалось записать %s: %w (нужен root)", linuxAutoRenewCron, err)
	}
	return "Задание автопродления создано: " + linuxAutoRenewCron + " (" + line + ")", nil
}

func PlatformRemoveAutoRenewTask() (string, error) {
	if err := os.Remove(linuxAutoRenewCron); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return "Задание автопродления удалено (" + linuxAutoRenewCron + ").", nil
}

func PlatformQueryAutoRenewTask() bool { return fileExists(linuxAutoRenewCron) }

func PlatformInstallAntiSpamTask(intervalHours int) (string, error) {
	if intervalHours <= 0 {
		intervalHours = 12
	}
	line := fmt.Sprintf("10 4 * * * root %s --antispam-update >/dev/null 2>&1", selfExePath())
	if intervalHours != 24 && intervalHours < 24 {
		line = fmt.Sprintf("10 */%d * * * root %s --antispam-update >/dev/null 2>&1", intervalHours, selfExePath())
	}
	content := "# Автообновление антиспам-базы KerioCertManager (создано программой)\n" +
		"SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" + line + "\n"
	if err := os.WriteFile(linuxAntiSpamCron, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("не удалось записать %s: %w (нужен root)", linuxAntiSpamCron, err)
	}
	return "Задание автообновления базы создано: " + linuxAntiSpamCron + " (" + line + ")", nil
}

func PlatformRemoveAntiSpamTask() (string, error) {
	if err := os.Remove(linuxAntiSpamCron); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return "Задание автообновления базы удалено (" + linuxAntiSpamCron + ").", nil
}

func PlatformQueryAntiSpamTask() bool { return fileExists(linuxAntiSpamCron) }

func PlatformOpenTempFirewallPort(_ int) func() { return func() {} }

func CloseDesktopWindow() {}

func PlatformApplyWindowIcon(_ int) {}

func RunDesktopWindow(_ string) bool { return false }

func startDetached(exe string, args []string) error {
	cmd := exec.Command(exe, args...)
	cmd.Dir = filepath.Dir(exe)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
