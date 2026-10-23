# Kerio SSL & Let's Encrypt Manager (Windows Desktop HTML GUI)

Автономная программа для **Windows / Windows Server (x64)** с современным графическим HTML-интерфейсом для генерации приватных ключей (`.key`) и выпуска бесплатных SSL-сертификатов **Let's Encrypt** (`.crt` Fullchain, `chain.crt`, `.pfx`, `.csr`) на основании введённого **доменного имени** и **IP-адреса** с прямой поддержкой установки в **Kerio Connect (Kerio MailServer)**.

---

## Готовый исполняемый файл для Windows

Готовая скомпилированная программа уже находится прямо в корне репозитория:

- **`KerioCertManager.exe`** (и архив **`KerioCertManager-Windows-x64.zip`** в корне репозитория) — **единый самодостаточный `.exe` файл (~8.7 МБ)** с встроенной иконкой, High-DPI манифестом и HTML GUI.
- **Не требует установки** Python, Certbot, OpenSSL, Node.js или .NET Runtime — просто скопируйте `KerioCertManager.exe` на сервер или ПК с Windows и запустите!

---

## Ключевые возможности

1. **Выпуск сертификатов по введённому Домену и IP-адресу:**
   - Автоматическая предпроверка **DNS A/AAAA ↔ IP**, определение NAT-маршрутизации и доступности портов `80` / `443`.
   - Поддержка кириллических IDN-доменов (`.бел`, `.рф`) с автоматическим Punycode-преобразованием.
   - Быстрое добавление почтовых SAN-поддоменов Kerio в 1 клик: `webmail.<домен>`, `autodiscover.<домен>`, `smtp.<домен>`, `imap.<домен>`, `pop3.<домен>`.
   - Поддержка **обоих профилей Let's Encrypt**:
     - **Classic (90 дней)** — стандартный доменный SSL-сертификат с проверкой привязки к указанному IP;
     - **Short-lived IP + Domain SAN (160 часов, RFC 8738)** — включение и домена, и публичного IP-адреса непосредственно в поле `Subject Alternative Name (SAN)` сертификата Let's Encrypt!
   - Три режима работы: **Let's Encrypt Production**, **Let's Encrypt Staging** (проверка без лимитов), а также **Локальный (Self-Signed для Kerio)** для мгновенной оффлайн-генерации и тестирования.

2. **4 способа прохождения проверки ACME (даже если порт 80 занят Kerio или закрыт):**
   - **HTTP-01 (Встроенный сервер, порт 80)** + опция *автоматической остановки службы `KerioMailServer` на 5–15 секунд проверки с мгновенным обратным запуском*;
   - **TLS-ALPN-01 (Встроенный сервер, порт 443, RFC 8737 `acme-tls/1`)**;
   - **HTTP-01 Webroot** (запись токена в папку запущенного IIS / веб-сервера без остановки порта 80);
   - **Интерактивный DNS-01 (`_acme-challenge` TXT)** — работает даже за закрытым файрволом без открытых портов `80`/`443`!

3. **Полная совместимость с Kerio Connect (Kerio MailServer):**
   - Генерирует незашифрованный приватный ключ **RSA 2048 / 4096 бит в классическом формате OpenSSL PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`)**, который гарантированно принимается всеми версиями Kerio Connect (`8.x`, `9.x`, `10.x`).
   - Формирует правильный файл **`server.crt` (`fullchain`)** = сертификат домена + промежуточная цепочка Let's Encrypt CA (чтобы Outlook, iOS Mail, Android и Thunderbird не выдавали ошибку недоверенной цепочки), а также отдельные `cert-only.crt`, `chain.crt`, PKCS#12 `.pfx`, `.csr`, автоустановщик `install-kerio.bat` и единый `.zip`-архив.
   - **3 способа установки в Kerio Connect:**
     1. Автоматическое копирование в `C:\Program Files\Kerio\MailServer\sslcert\` с авто-бэкапом старых ключей, чтением активного профиля из `mailserver.cfg` (`server` или `cert_1`/`cert_2`) и перезапуском службы `KerioMailServer`;
     2. Бесшовный онлайн-импорт через **Kerio Connect Admin JSON-RPC API (`https://127.0.0.1:4040/admin/api/jsonrpc/`)** (`Session.login` → `Certificates.import` → `Certificates.setActive`) **без остановки почтовых служб**;
     3. Ручной импорт скачанных файлов `server.crt` и `server.key` через веб-консоль Kerio Connect Administration.

4. **Автопродление через Планировщик заданий Windows (`schtasks.exe`):**
   - Регистрация системной задачи `KerioLetsEncryptAutoRenew` (`KerioCertManager.exe --renew`) в 1 клик прямо из интерфейса программы.

---

## Быстрый запуск на Windows Server

1. Скопируйте **`KerioCertManager.exe`** в папку на сервере (например, `C:\KerioCertManager\KerioCertManager.exe`).
2. Нажмите правой кнопкой мыши → **«Запуск от имени администратора»** *(либо нажмите кнопку повышения прав UAC прямо в верхней панели окна программы)*.
3. Введите **Доменное имя** (например, `mail.company.by`) и **IP-адрес** сервера, нажмите **«Сгенерировать ключ и выпустить сертификат»**.
4. Установите сертификат в Kerio Connect кнопкой **«Установить в Kerio Connect»** или импортируйте созданные файлы `server.crt` и `server.key` в разделе **Configuration → SSL Certificates → Import**.

---

## Самостоятельная сборка из исходников (при необходимости)

Проект написан на чистом **Go 1.22+** без единой внешней C/CGO-зависимости:

```bat
cd kerio-letsencrypt-win
build-windows.bat
```

Или кросс-компиляция из Linux / macOS:

```bash
cd kerio-letsencrypt-win
GOOS=windows GOARCH=amd64 go build -ldflags="-H=windowsgui -s -w" -o KerioCertManager.exe .
```
