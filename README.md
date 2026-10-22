# CSL HelpDesk / jiraHelp

Android WebView-оболочка и автономный веб-интерфейс управления заявками.
Исходники получены из `origin/main` (`b7f4c61`) 22 октября 2026 года.

**Важно:** в переданных исходниках отсутствует реализация Jira REST API.
Текущая сборка работает локально; ввод адреса/имени не является проверкой входа
в Jira. Создание заявок, статусы и комментарии локальные. Не вводите рабочие пароли.

## Проверка и сборка

```sh
node --test tests/*.test.cjs
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

## Проверенная сборка

[Скачать подписанный тестовый APK](https://github.com/zigorminsk-debug/jiraHelp/releases/download/apk-39752620540-1/CSL-HelpDesk-debug.apk)
· [успешный CI](https://github.com/zigorminsk-debug/jiraHelp/actions/runs/39752620540)
· [контрольная сумма и сертификат](https://github.com/zigorminsk-debug/jiraHelp/releases/tag/apk-39752620540-1).

Это подтвержденная сборка `73081a6`; для более новых сборок смотрите Releases
или ссылку в Summary соответствующего успешного запуска Actions.
