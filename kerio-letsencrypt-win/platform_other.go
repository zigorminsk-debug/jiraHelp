//go:build !windows && !linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func DefaultCertsRoot() string {
	exe, err := os.Executable()
	if err == nil {
		return filepath.Join(filepath.Dir(exe), "certs")
	}
	return "certs"
}

func IsRunningAsAdmin() bool {
	return os.Geteuid() == 0
}

func RelaunchAsAdmin(_ []string) error {
	return fmt.Errorf("повышение прав через UAC доступно при запуске KerioCertManager.exe в Windows")
}

func ShowWindowsMessageBox(_, _ string) {}

// PlatformKerioServiceImagePath — на Unix-системах аналога «sc qc» нет:
// путь установки берём из стандартных каталогов и переменной окружения.
func PlatformKerioServiceImagePath() (string, string) {
	for _, p := range []string{"/opt/kerio/mailserver/mailserver", "/usr/local/kerio/mailserver/mailserver"} {
		if fileExists(p) {
			return "kerio-connect", p
		}
	}
	return "", ""
}

// PlatformKerioRegistryDirs — реестра нет; используем стандартные пути Linux/macOS.
func PlatformKerioRegistryDirs() []string {
	return nil
}

// PlatformKerioSearchRoots — каталоги, которые просматриваются, если точный
// путь установки неизвестен.
func PlatformKerioSearchRoots() []string {
	// Только каталоги самого Kerio: обход /opt или /usr/local целиком был бы
	// слишком дорогим и всё равно не нашёл бы правил вне установки Kerio.
	return []string{"/opt/kerio", "/usr/local/kerio"}
}

func PlatformCandidateKerioDirs() []string {
	return []string{
		"/opt/kerio/mailserver",
		"/usr/local/kerio/mailserver",
	}
}

func PlatformKerioServiceStatus() string {
	if _, err := os.Stat("/opt/kerio/mailserver"); err == nil {
		return "RUNNING"
	}
	return "DEMO_LINUX_PREVIEW"
}

func PlatformControlKerioService(_ string) error {
	return nil
}

func PlatformOpenFolderInExplorer(path string) error {
	_ = path
	return fmt.Errorf("открытие Проводника Windows работает при запуске KerioCertManager.exe на Windows — в веб-режиме используйте кнопки скачивания файлов ниже")
}

func PlatformBrowseFolderDialog(_ string) (string, error) {
	return DefaultCertsRoot(), nil
}

func PlatformInstallAutoRenewTask(intervalHours int) (string, error) {
	return fmt.Sprintf("На сервере Windows эта кнопка регистрирует системное задание Планировщика (schtasks.exe /TN KerioLetsEncryptAutoRenew, интервал %d ч). В демо-среде Linux используйте скачанный KerioCertManager.exe на Windows.", intervalHours), nil
}

func PlatformRemoveAutoRenewTask() (string, error) {
	return "Задание автопродления отключено.", nil
}

func PlatformQueryAutoRenewTask() bool {
	return false
}

func PlatformOpenTempFirewallPort(_ int) func() {
	return func() {}
}

func PlatformInstallAntiSpamTask(_ int) (string, error) {
	return "", fmt.Errorf("автообновление антиспам-базы через Планировщик доступно только в Windows")
}

func PlatformRemoveAntiSpamTask() (string, error) {
	return "", fmt.Errorf("автообновление антиспам-базы через Планировщик доступно только в Windows")
}

func PlatformQueryAntiSpamTask() bool { return false }

func CloseDesktopWindow() {}

func PlatformApplyWindowIcon(_ int) {}

func RunDesktopWindow(_ string) bool {
	return false
}

// startDetached запускает новую копию программы после обновления
// (на не-Windows системах файл не подменяется автоматически, но функция
// нужна для единообразия).
func startDetached(exe string, args []string) error {
	cmd := exec.Command(exe, args...)
	cmd.Dir = filepath.Dir(exe)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
