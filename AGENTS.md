# Передача работы агенту

## Задача
Проверка исходников, исправление ошибок, автоматическая сборка установочного APK
в GitHub Actions и документирование. Общаться с владельцем по-русски.

## Источник и Git
Изначальная база `40a4011` содержала только `.gitattributes`. Пользователь загрузил
исходники в новый независимый root commit `b7f4c61` на main. Fast-forward невозможен
(`unrelated histories`). В текущую рабочую ветку **выборочно** восстановлены
`helpdesk-apk/`, `helpdesk-app/`, `v18_base/` через `git restore --source=origin/main`.
Не переносить 195 MiB SDK/JDK/старых APK и screenshots. Истории не объединялись.
Для будущего PR требуется отдельно решить объединение независимых историй с владельцем;
не делайте force-push в main и не удаляйте пользовательские файлы.

## Активный проект
`helpdesk-apk/` — чистая Java Activity + assets, Gradle отсутствует. Сборка:
`scripts/build-apk.sh` (aapt → javac → d8 → zipalign → apksigner).
Workflow `.github/workflows/android-apk.yml` использует JDK17 / SDK33 / build-tools35.
`node --test tests/*.test.cjs` — локальные регрессионные проверки без npm-зависимостей.
`helpdesk-app/` — отдельная демо, `v18_base/` — неизменяемый исторический снимок,
не источник сборки и не безопасный production-вариант.

## Текущая Jira-интеграция (1.10.4)
Добавлены native `savePrefs`, `testConnection(server,user,password)`, `fetchTickets`,
`clearSession`, pure-Java `JiraClient` (REST v2 Basic HTTPS) и UI callbacks.
Подробности: `docs/JIRA_CONNECTION.md`. Проверка сервера владельца не выполнялась
(домен не разрешен outbound sandbox). Не обещать подтвержденную авторизацию
на `h.csl.by` до теста на телефоне. Полный Jira backend не реализован:
create/status/comments остаются локальными, SSO/Bearer PAT/Cloud search v3 нет.
Не включать cleartext/universal file access/небезопасный TLS для подключения.

## Дальше
1. Проверить фактический результат CI и установить APK на Android 21/33+.
2. Для расширения Jira запросить требования: Server/Data Center/Cloud, версию REST API,
   схему авторизации, проекты, типы задач и transitions. Без этих данных не
   обещать совместимость и не хардкодить Task/HD для реальной записи.
3. Расширять существующий read-only сетевой слой только с регрессиями.
   Добавить Android integration tests для session races и реального TLS/API.
4. Убрать legacy callbacks и демо-данные по согласованию; описания Cloud ADF
   требуют преобразования в текст, сейчас полной поддержки нет.
5. Продолжить тесты реального DOM/WebView, доступности, PWA offline/update,
   сохранения данных при обновлении и release-подписи.
6. Обновлять `docs/AUDIT.md` с командами, результатами и ограничениями.

Не коммитить APK/SDK/JDK/cache/ключи/пароли. Не объявлять тесты на VM полноценным
аудитом безопасности. `safety.js` одинаков в обеих активных версиях (есть тест).

## Актуальная выдача APK
Ранее upload-artifact блокировался квотой аккаунта. Теперь доверенный publish job
публикует подписанный debug APK в GitHub Releases (уникальный prerelease по run ID
и attempt), скачивает файл обратно и проверяет SHA-256/совпадение. Общая сборка —
`.github/actions/build-apk/action.yml`; публикация — `scripts/publish-apk.sh`.
PR и прочие ветки проверяются read-only и ничего не публикуют.
Не возвращать Actions Artifacts до решения квоты. Старые assets/релизы не удалять
без разрешения. Это тестовая сменная подпись, не production signing identity.

Подтверждено: CI run `39752620540` на `73081a6` — **success**; prerelease
`apk-39752620540-1` содержит настоящий APK, SHA256SUMS и signature.txt.
Workflow сам скачал APK после upload и проверил совпадение содержимого.
