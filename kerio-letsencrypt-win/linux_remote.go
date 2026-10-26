package main

// linux_remote.go — управление Kerio Connect на Linux по SSH.
//
// Зачем: чаще всего Kerio Connect стоит на Linux, а админ сидит за Windows.
// Программа тогда не может просто «записать файл в папку» — нужен доступ по
// SSH. Здесь реализованы ровно те операции, которые нужны антиспам-базе и
// сертификатам:
//
//	• проверить связь и найти каталог установки Kerio (probe);
//	• загрузить файл (правила .cf, сертификат, ключ) с проверкой SHA-256
//	   уже НА СЕРВЕРЕ (upload + sha256sum);
//	• перезапустить службу kerio-connect (systemctl или /etc/init.d);
//	• отдать готовый shell-скрипт для ручной установки, если SSH недоступен.
//
// Пароль и ключ НИКУДА не сохраняются: они живут в памяти на время операции.
// В настройках хранится только адрес, логин, путь к ключу и отпечаток хоста
// (TOFU: при первом подключении запоминаем, дальше сверяем — это защита от
// подмены сервера).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// LinuxTarget — параметры подключения к Linux-серверу с Kerio Connect.
type LinuxTarget struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	User            string `json:"user"`
	Password        string `json:"password"`
	KeyPath         string `json:"keyPath"`
	KeyPass         string `json:"keyPass"`
	KerioDir        string `json:"kerioDir"`
	Service         string `json:"service"`
	Sudo            bool   `json:"sudo"`
	Restart         bool   `json:"restart"`
	HostFingerprint string `json:"hostFingerprint"`
}

// LinuxProbeResult — что удалось выяснить про сервер (уходит в UI).
type LinuxProbeResult struct {
	OK              bool     `json:"ok"`
	Connected       bool     `json:"connected"`
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	User            string   `json:"user"`
	OS              string   `json:"os"`
	Kernel          string   `json:"kernel"`
	IsRoot          bool     `json:"isRoot"`
	HasSudo         bool     `json:"hasSudo"`
	KerioDir        string   `json:"kerioDir"`
	RulesDir        string   `json:"rulesDir"`
	RulesExists     bool     `json:"rulesExists"`
	SSLcertDir      string   `json:"sslcertDir"`
	ServiceName     string   `json:"serviceName"`
	ServiceActive   string   `json:"serviceActive"`
	ServiceManager  string   `json:"serviceManager"`
	InstalledCF     string   `json:"installedCf"`
	InstalledSize   int64    `json:"installedSize"`
	HostFingerprint string   `json:"hostFingerprint"`
	Steps           []string `json:"steps"`
	Error           string   `json:"error,omitempty"`
}

// LinuxDeployResult — результат загрузки файла/установки.
type LinuxDeployResult struct {
	OK         bool     `json:"ok"`
	RemotePath string   `json:"remotePath"`
	SHA256     string   `json:"sha256"`
	Size       int64    `json:"size"`
	Restarted  bool     `json:"restarted"`
	RestartErr string   `json:"restartErr,omitempty"`
	Steps      []string `json:"steps"`
	Warnings   []string `json:"warnings"`
}

// ---------------------------------------------------------------------------
// Подключение
// ---------------------------------------------------------------------------

// buildSSHClientConfig собирает конфиг подключения. Через замыкание отдаёт
// SHA256-отпечаток ключа хоста (TOFU: показываем в UI, чтобы админ мог
// убедиться, что сервер тот самый).
func buildSSHClientConfig(t LinuxTarget) (*ssh.ClientConfig, *string, error) {
	if strings.TrimSpace(t.Host) == "" {
		return nil, nil, fmt.Errorf("не указан адрес Linux-сервера")
	}
	if strings.TrimSpace(t.User) == "" {
		return nil, nil, fmt.Errorf("не указано имя пользователя SSH")
	}

	var auths []ssh.AuthMethod
	if strings.TrimSpace(t.Password) != "" {
		pwd := t.Password
		auths = append(auths, ssh.Password(pwd))
		auths = append(auths, ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = pwd
			}
			return answers, nil
		}))
	}
	if strings.TrimSpace(t.KeyPath) != "" {
		key, err := os.ReadFile(expandHome(t.KeyPath))
		if err != nil {
			return nil, nil, fmt.Errorf("не удалось прочитать SSH-ключ %s: %w", t.KeyPath, err)
		}
		var signer ssh.Signer
		if strings.TrimSpace(t.KeyPass) != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(t.KeyPass))
		} else {
			signer, err = ssh.ParsePrivateKey(key)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("не удалось разобрать SSH-ключ (нужен OpenSSH или PEM): %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if len(auths) == 0 {
		return nil, nil, fmt.Errorf("укажите пароль SSH или путь к приватному ключу")
	}

	fp := new(string)
	cfg := &ssh.ClientConfig{
		User:    t.User,
		Auth:    auths,
		Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			*fp = hostKeyFingerprint(key)
			return nil
		},
	}
	return cfg, fp, nil
}

// expandHome раскрывает «~» в домашний каталог (в поле «ключ» часто вставляют
// путь вида ~/.ssh/id_ed25519).
func expandHome(p string) string {
	p = strings.TrimSpace(p)
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return home + p[1:]
		}
	}
	return p
}

// sshDial подключается с таймаутом и возвращает клиента и отпечаток ключа хоста.
func sshDial(t LinuxTarget) (*ssh.Client, string, error) {
	cfg, fp, err := buildSSHClientConfig(t)
	if err != nil {
		return nil, "", err
	}
	addr := net.JoinHostPort(strings.TrimSpace(t.Host), strconv.Itoa(portOr22(t.Port)))
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("нет связи с %s: %w (проверьте адрес, порт 22 и firewall)", addr, err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("SSH-аутентификация не удалась: %w (проверьте логин, пароль или ключ, а также разрешён ли вход на сервере)", err)
	}
	return ssh.NewClient(c, chans, reqs), *fp, nil
}

// hostKeyFingerprint возвращает SHA256-отпечаток ключа хоста в формате ssh.
func hostKeyFingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func sshRun(client *ssh.Client, cmd string) (string, int, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", -1, err
	}
	defer session.Close()
	var buf bytes.Buffer
	session.Stdout = &buf
	session.Stderr = &buf
	err = session.Run(cmd)
	code := 0
	if err != nil {
		if ee, ok := err.(*ssh.ExitError); ok {
			code = ee.ExitStatus()
		} else {
			return buf.String(), -1, err
		}
	}
	return buf.String(), code, nil
}

// sshRunWithInput выполняет команду, передавая текст в stdin.
func sshRunWithInput(client *ssh.Client, cmd, input string) (string, int, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", -1, err
	}
	defer session.Close()
	var buf bytes.Buffer
	session.Stdin = strings.NewReader(input)
	session.Stdout = &buf
	session.Stderr = &buf
	err = session.Run(cmd)
	code := 0
	if err != nil {
		if ee, ok := err.(*ssh.ExitError); ok {
			code = ee.ExitStatus()
		} else {
			return buf.String(), -1, err
		}
	}
	return buf.String(), code, nil
}

// ---------------------------------------------------------------------------
// Диагностика сервера
// ---------------------------------------------------------------------------

// linuxProbeScript — одна команда, которая собирает всё нужное про сервер.
// Так быстрее и надёжнее, чем десяток отдельных вызовов SSH.
const linuxProbeScript = `set -u
echo "KCM_OS=$(uname -s 2>/dev/null)"
echo "KCM_KERNEL=$(uname -r 2>/dev/null)"
echo "KCM_USER=$(id -un 2>/dev/null)"
echo "KCM_UID=$(id -u 2>/dev/null)"
if sudo -n true 2>/dev/null; then echo "KCM_SUDO=1"; else echo "KCM_SUDO=0"; fi
for d in /opt/kerio/mailserver /usr/local/kerio/mailserver; do
  if [ -d "$d" ]; then echo "KCM_KERIO=$d"; fi
done
for d in /opt/kerio/mailserver/plugins/spamassassin/rules \
         /opt/kerio/mailserver/plugins/spamserver/spamassassin/rules \
         /usr/local/kerio/mailserver/plugins/spamassassin/rules \
         /usr/local/kerio/mailserver/plugins/spamserver/spamassassin/rules; do
  if [ -d "$d" ]; then echo "KCM_RULES=$d"; fi
done
for d in /opt/kerio/mailserver/sslcert /usr/local/kerio/mailserver/sslcert; do
  if [ -d "$d" ]; then echo "KCM_SSLCERT=$d"; fi
done
if command -v systemctl >/dev/null 2>&1; then echo "KCM_INIT=systemd"; else echo "KCM_INIT=sysv"; fi
for s in kerio-connect kerio keriomailserver; do
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files "$s.service" 2>/dev/null | grep -q "$s.service"; then
    echo "KCM_SERVICE=$s"; break
  fi
  if [ -x "/etc/init.d/$s" ]; then echo "KCM_SERVICE=$s"; break; fi
done
SVC=$(echo "${KCM_SERVICE:-kerio-connect}")
if command -v systemctl >/dev/null 2>&1; then
  echo "KCM_ACTIVE=$(systemctl is-active "$SVC" 2>/dev/null)"
else
  if service "$SVC" status >/dev/null 2>&1; then echo "KCM_ACTIVE=active"; else echo "KCM_ACTIVE=inactive"; fi
fi
for f in /opt/kerio/mailserver/plugins/spamassassin/rules/kerio-antispam.cf \
         /opt/kerio/mailserver/plugins/spamserver/spamassassin/rules/kerio-antispam.cf \
         /usr/local/kerio/mailserver/plugins/spamassassin/rules/kerio-antispam.cf; do
  if [ -f "$f" ]; then echo "KCM_CF=$f"; echo "KCM_CF_SIZE=$(wc -c < "$f" 2>/dev/null)"; break; fi
done
exit 0`

// parseKV разбирает вывод вида KEY=VALUE.
func parseKV(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		idx := strings.Index(line, "=")
		if idx <= 0 || !strings.HasPrefix(line, "KCM_") {
			continue
		}
		m[line[:idx]] = strings.TrimSpace(line[idx+1:])
	}
	return m
}

// ProbeLinuxKerio подключается к серверу и собирает сведения о Kerio.
func ProbeLinuxKerio(ctx context.Context, t LinuxTarget) LinuxProbeResult {
	res := LinuxProbeResult{OK: false, Host: t.Host, Port: t.Port, User: t.User, Steps: []string{}}
	if res.Port == 0 {
		res.Port = 22
	}

	type dialResult struct {
		client *ssh.Client
		fp     string
		err    error
	}
	ch := make(chan dialResult, 1)
	go func() {
		client, fp, err := sshDial(t)
		ch <- dialResult{client: client, fp: fp, err: err}
	}()

	var client *ssh.Client
	select {
	case <-ctx.Done():
		res.Error = "проверка отменена"
		return res
	case d := <-ch:
		if d.err != nil {
			res.Error = d.err.Error()
			return res
		}
		client = d.client
		res.HostFingerprint = d.fp
	}
	defer client.Close()
	res.Connected = true

	out, _, err := sshRun(client, linuxProbeScript)
	if err != nil {
		res.Error = "не удалось выполнить команды на сервере: " + err.Error()
		return res
	}
	kv := parseKV(out)

	res.OS = kv["KCM_OS"]
	res.Kernel = kv["KCM_KERNEL"]
	res.IsRoot = kv["KCM_UID"] == "0"
	res.HasSudo = kv["KCM_SUDO"] == "1"
	res.KerioDir = kv["KCM_KERIO"]
	res.RulesDir = kv["KCM_RULES"]
	res.SSLcertDir = kv["KCM_SSLCERT"]
	res.ServiceName = kv["KCM_SERVICE"]
	res.ServiceManager = kv["KCM_INIT"]
	res.ServiceActive = kv["KCM_ACTIVE"]
	res.InstalledCF = kv["KCM_CF"]
	if v := kv["KCM_CF_SIZE"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			res.InstalledSize = n
		}
	}
	res.RulesExists = res.RulesDir != ""

	res.Steps = append(res.Steps,
		fmt.Sprintf("Подключение по SSH к %s@%s:%d — успешно.", t.User, t.Host, res.Port),
		fmt.Sprintf("Система: %s %s.", res.OS, res.Kernel),
	)
	if res.KerioDir == "" {
		res.Steps = append(res.Steps, "⚠️ Каталог Kerio Connect не найден в /opt/kerio/mailserver или /usr/local/kerio/mailserver.")
	} else {
		res.Steps = append(res.Steps, "Каталог Kerio: "+res.KerioDir)
	}
	if res.RulesDir == "" {
		res.Steps = append(res.Steps, "⚠️ Каталог правил SpamAssassin не найден.")
	} else {
		res.Steps = append(res.Steps, "Каталог правил: "+res.RulesDir)
	}
	if res.InstalledCF != "" {
		res.Steps = append(res.Steps, fmt.Sprintf("База уже установлена: %s (%d байт).", res.InstalledCF, res.InstalledSize))
	} else {
		res.Steps = append(res.Steps, "База KCM на сервере не установлена.")
	}
	res.OK = res.ErrorsEmpty()
	return res
}

// ErrorsEmpty — успешно ли подключение (даже если Kerio не найден).
func (r LinuxProbeResult) ErrorsEmpty() bool { return r.Error == "" && r.Connected }

// ---------------------------------------------------------------------------
// Загрузка файлов и установка
// ---------------------------------------------------------------------------

// uploadFileRemote заливает файл на сервер через base64 в stdin (без SFTP:
// меньше зависимостей и работает даже там, где sftp-server не включён).
// Возвращает отпечаток файла, посчитанный уже на сервере.
func uploadFileRemote(client *ssh.Client, target string, content []byte, sudo bool) (string, error) {
	b64 := base64.StdEncoding.EncodeToString(content)
	dir := path.Dir(target)
	tmp := "/tmp/.kcm-upload-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	prefix := ""
	if sudo {
		prefix = "sudo -n "
	}

	script := fmt.Sprintf(`set -e
umask 022
cat > %s
%smkdir -p %s
%scp -f %s %s
%srm -f %s
%ssha256sum %s | awk '{print $1}'
`, tmp, prefix, shellQuote(dir), prefix, tmp, shellQuote(target), prefix, tmp, prefix, shellQuote(target))

	out, code, err := sshRunWithInput(client, "sh -c "+shellQuote(script), b64)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("команда на сервере завершилась с кодом %d: %s", code, strings.TrimSpace(lastLines(out, 6)))
	}
	sum := strings.TrimSpace(lastLines(out, 1))
	if len(sum) != 64 {
		return "", fmt.Errorf("не удалось получить SHA-256 файла на сервере: %s", strings.TrimSpace(lastLines(out, 5)))
	}
	return sum, nil
}

// shellQuote экранирует строку для передачи в sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// lastLines возвращает последние n непустых строк.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// DeployFileToLinux заливает файл в каталог Kerio и (опционально)
// перезапускает службу. SHA-256 сверяется с посчитанным на сервере.
func DeployFileToLinux(ctx context.Context, t LinuxTarget, remoteDir, fileName string, content []byte, restart bool) LinuxDeployResult {
	res := LinuxDeployResult{Steps: []string{}, Warnings: []string{}}
	if strings.TrimSpace(remoteDir) == "" {
		res.Steps = append(res.Steps, "не указан каталог на сервере")
		return res
	}
	client, _, err := sshDial(t)
	if err != nil {
		res.Steps = append(res.Steps, "ошибка подключения: "+err.Error())
		return res
	}
	defer client.Close()
	return deployToLinuxClient(ctx, client, t, remoteDir, fileName, content, restart)
}

func portOr22(p int) int {
	if p <= 0 {
		return 22
	}
	return p
}

// probeIsRoot — нужен ли sudo (если пользователь не root).
func probeIsRoot(client *ssh.Client) bool {
	out, code, err := sshRun(client, "id -u")
	if err != nil || code != 0 {
		return false
	}
	return strings.TrimSpace(out) == "0"
}

// ---------------------------------------------------------------------------
// Готовый shell-скрипт (когда SSH из программы недоступен)
// ---------------------------------------------------------------------------

// LinuxInstallScript отдаёт самодостаточный скрипт: скачивает свежий .cf с
// GitHub (или берёт локальный файл), кладёт в правильную папку и перезапускает
// Kerio. Нужен в закрытых контурах и когда SSH из программы недоступен.
func LinuxInstallScript(ruleFileURL string) string {
	if ruleFileURL == "" {
		ruleFileURL = "https://github.com/" + updateRepoOwner + "/" + updateRepoName + "/releases/download/antispam-db-latest/" + antiSpamRuleFileName
	}
	return `#!/bin/sh
# ============================================================================
#  KerioCertManager v` + appVersion + ` — установка антиспам-базы KCM в Kerio Connect на Linux
#
#  Что делает:
#    1. ищет каталог установки Kerio Connect;
#    2. скачивает файл правил kerio-antispam.cf (или берёт рядом лежащий);
#    3. кладёт его в plugins/spamassassin/rules с резервной копией прежней версии;
#    4. перезапускает службу kerio-connect.
#
#  Запуск на сервере (от root):
#      sudo sh install-kcm-antispam.sh
#  или с локальным файлом (без интернета):
#      sudo sh install-kcm-antispam.sh ./kerio-antispam.cf
# ============================================================================
set -e

CF_NAME="` + antiSpamRuleFileName + `"
CF_URL="` + ruleFileURL + `"
LOCAL_FILE="${1:-}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say() { printf '  %s\n' "$*"; }
fail() { printf '\n[ОШИБКА] %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || fail "запустите скрипт от root: sudo sh $0"

printf '\n=== 1. Поиск Kerio Connect ===\n'
RULES=""
KERIO=""
for d in /opt/kerio/mailserver /usr/local/kerio/mailserver; do
  [ -d "$d" ] || continue
  KERIO="$d"
  for r in "$d/plugins/spamassassin/rules" "$d/plugins/spamserver/spamassassin/rules"; do
    if [ -d "$r" ]; then RULES="$r"; break; fi
  done
  if [ -z "$RULES" ] && [ -d "$d/plugins" ]; then
    # папки rules ещё нет — создаём в правильном месте
    for sa in "$d/plugins/spamassassin" "$d/plugins/spamserver/spamassassin"; do
      if [ -d "$sa" ]; then RULES="$sa/rules"; mkdir -p "$RULES"; break; fi
    done
  fi
  [ -n "$RULES" ] && break
done
[ -n "$KERIO" ] || fail "Kerio Connect не найден в /opt/kerio/mailserver или /usr/local/kerio/mailserver"
say "Kerio: $KERIO"
[ -n "$RULES" ] || fail "не найден каталог правил SpamAssassin (plugins/spamassassin/rules)"
say "Правила: $RULES"

printf '\n=== 2. Получение файла правил ===\n'
if [ -n "$LOCAL_FILE" ] && [ -f "$LOCAL_FILE" ]; then
  cp "$LOCAL_FILE" "$TMP/$CF_NAME"
  say "использую локальный файл: $LOCAL_FILE"
else
  command -v curl >/dev/null 2>&1 || fail "нужен curl (или укажите локальный файл первым аргументом)"
  curl -fsSL --retry 3 --connect-timeout 15 -o "$TMP/$CF_NAME" "$CF_URL" || fail "не удалось скачать $CF_URL"
  say "файл скачан с GitHub"
fi
SIZE=$(wc -c < "$TMP/$CF_NAME")
[ "$SIZE" -gt 1000 ] || fail "файл подозрительно маленький ($SIZE байт)"
grep -q "KCM_" "$TMP/$CF_NAME" || fail "в файле нет правил KCM — похоже, скачалась страница ошибки"
say "размер: $SIZE байт, содержит правила KCM"

printf '\n=== 3. Установка с резервной копией ===\n'
if [ -f "$RULES/$CF_NAME" ]; then
  BACKUP="$RULES/$CF_NAME.backup-$(date +%Y%m%d-%H%M%S)"
  cp -p "$RULES/$CF_NAME" "$BACKUP"
  say "резервная копия: $BACKUP"
fi
install -m 644 "$TMP/$CF_NAME" "$RULES/$CF_NAME"
SHA_LOCAL=$(sha256sum "$TMP/$CF_NAME" | awk '{print $1}')
SHA_REMOTE=$(sha256sum "$RULES/$CF_NAME" | awk '{print $1}')
[ "$SHA_LOCAL" = "$SHA_REMOTE" ] || fail "SHA-256 не совпал после записи"
say "установлено: $RULES/$CF_NAME"
say "SHA-256: $SHA_REMOTE"

printf '\n=== 4. Перезапуск Kerio ===\n'
SVC="kerio-connect"
for s in kerio-connect kerio keriomailserver; do
  if systemctl list-unit-files "$s.service" 2>/dev/null | grep -q "$s.service"; then SVC="$s"; break; fi
  if [ -x "/etc/init.d/$s" ]; then SVC="$s"; break; fi
done
if systemctl restart "$SVC" 2>/dev/null; then
  say "systemctl restart $SVC — выполнено"
elif [ -x "/etc/init.d/$SVC" ]; then
  "/etc/init.d/$SVC" restart && say "/etc/init.d/$SVC restart — выполнено"
else
  say "не удалось перезапустить службу автоматически"
  say "выполните вручную: sudo systemctl restart kerio-connect"
fi

printf '\n=== Готово ===\n'
say "Проверка: письмо → «Показать исходное сообщение» → строка X-Spam-Status должна содержать KCM_…"
say "Откат: верните файл из резервной копии *.backup-* и перезапустите службу."
printf '\n'
`
}
