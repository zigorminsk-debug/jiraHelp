# Kerio SSL & Let's Encrypt Manager (Windows x64 + HTML GUI)

Автономная программа для **Windows / Windows Server (x64)** с графическим HTML-интерфейсом для генерации приватных ключей (`.key`) и выпуска бесплатных SSL-сертификатов **Let's Encrypt** (`.crt` Fullchain, `chain.crt`, `.pfx`, `.csr`) на основании введённого **доменного имени** и **IP-адреса** для почтового сервера **Kerio Connect (Kerio MailServer)**.

---

## ⬇ Скачать готовую программу для Windows

- 💻 **[Скачать `KerioCertManager.exe` (Windows x64, 8.7 МБ)](./KerioCertManager.exe)** — единый готовый к работе `.exe` файл (без установки Python, OpenSSL, Certbot или .NET).
- 📦 **[Скачать `KerioCertManager-Windows-x64.zip` (3.6 МБ)](./KerioCertManager-Windows-x64.zip)** — тот же `KerioCertManager.exe` в ZIP-архиве (если браузер/SmartScreen блокирует прямое скачивание `.exe`).

---

## Быстрый старт на Windows / Windows Server

1. Скачайте **`KerioCertManager.exe`** и поместите его в любую папку на сервере (например, `C:\KerioCertManager\`).
2. Нажмите правой кнопкой мыши по `KerioCertManager.exe` → **«Запуск от имени администратора»** *(либо нажмите кнопку повышения прав UAC прямо в окне программы)*.
3. В открывшемся окне укажите **Доменное имя** (например, `mail.company.by`) и **IP-адрес сервера**, при необходимости добавьте поддомены кнопками `+ webmail`, `+ autodiscover`, `+ smtp`, `+ imap`.
4. Нажмите **«🔐 Сгенерировать ключ и выпустить сертификат»**.
5. Программа сгенерирует совместимую пару файлов для **Kerio Connect**:
   - **`server.key`** — незашифрованный приватный ключ **RSA 2048/4096 бит (`BEGIN RSA PRIVATE KEY`)**;
   - **`server.crt`** — полный сертификат с цепочкой **Let's Encrypt Fullchain** (сертификат сервера + промежуточный CA);
   - а также `chain.crt`, `cert-only.crt`, `.pfx`, `.csr` и скрипт автоустановки `install-kerio.bat`.
6. Установите сертификат в **Kerio Connect** в 1 клик прямо из программы (через папку `sslcert` с авто-бэкапом и учётом `mailserver.cfg` либо онлайн через **Kerio Admin API `:4040`** без остановки почты) или импортируйте `server.crt` + `server.key` вручную в веб-админке **Kerio Connect Administration → Configuration → SSL Certificates → Import**.

---

## Структура ветки

- `KerioCertManager.exe` — готовое 64-битное приложение для Windows с иконкой и HTML GUI
- `KerioCertManager-Windows-x64.zip` — сжатый архив с программой и инструкцией
- `kerio-letsencrypt-win/` — полный исходный код на Go + HTML GUI и скрипт сборки `build-windows.bat`
