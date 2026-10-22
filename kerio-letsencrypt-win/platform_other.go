//go:build !windows

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

func PlatformCandidateKerioDirs() []string {
	return []string{
		"/opt/kerio/mailserver",
		filepath.Join(DefaultCertsRoot(), "_mock_kerio_mailserver"),
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

func LaunchDesktopGUI(_ string) (*exec.Cmd, bool) {
	return nil, false
}
