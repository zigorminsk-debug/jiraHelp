# CSL HelpDesk / jiraHelp

Android WebView-оболочка и автономный веб-интерфейс управления заявками.
Исходники получены из `origin/main` (`b7f4c61`) 22 октября 2026 года.

**Версия 1.10.4:** добавлены проверка HTTPS-подключения и чтение заявок из
Jira Server/Data Center через REST v2 + Basic Auth. Создание заявок, смена статуса
и комментарии пока локальные. SSO/Bearer PAT и новый Jira Cloud search не реализованы.
Пароль не сохраняется; проверка именно сервера владельца требуется на телефоне.
[Подключение и диагностика](docs/JIRA_CONNECTION.md).

## Проверка и сборка

```sh
node --test tests/*.test.cjs
# JDK 17:
bash scripts/test-java.sh
# JDK 17, Android SDK: platforms;android-33 и build-tools;35.0.0
export ANDROID_SDK_ROOT=/path/to/android-sdk
bash scripts/build-apk.sh
```

Результат: `build/android/CSL-HelpDesk-debug.apk` (тестовая подпись).
GitHub Actions делает те же проверки и сборку на push/PR. Для доверенных веток
`main` и `arena/0b4677fb-jirahelp` подписанный APK публикуется в **Releases** как
prerelease `apk-<run-id>-<attempt>`; ссылка появляется в Summary запуска.
Actions Artifacts не используется из-за исчерпанной квоты аккаунта.

- [Сборка и получение APK](docs/ANDROID_BUILD.md)
- [Аудит, изменения и ограничения](docs/AUDIT.md)
- [Контекст следующему агенту](AGENTS.md)

`helpdesk-apk/` — источник Android APK; `helpdesk-app/` — отдельная старая веб-демо;
`v18_base/` — историческая копия, не используется сборкой. Не редактируйте их как
взаимозаменяемые версии: содержимое различается.

## Проверенная сборка 1.10.4

[Скачать подписанный APK с Jira-подключением](https://github.com/zigorminsk-debug/jiraHelp/releases/download/apk-39754888214-1/CSL-HelpDesk-debug.apk)
· [успешный CI](https://github.com/zigorminsk-debug/jiraHelp/actions/runs/39754888214)
· [SHA-256 и сертификат](https://github.com/zigorminsk-debug/jiraHelp/releases/tag/apk-39754888214-1).

Сборка `356221a`: тесты JS/JVM, компиляция Android, подпись и проверка опубликованного
файла прошли. Подключение к `h.csl.by` требуется проверить с телефона владельца:
см. [инструкцию](docs/JIRA_CONNECTION.md). Для более новых APK смотрите Releases
или ссылку в Summary успешного запуска Actions.
