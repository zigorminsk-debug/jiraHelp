# Проверка и журнал изменений

## 2026-10-22 — исходное состояние

- База: `40a401162df10cfeebafeffc6c347aac10387b9b` (`Initial commit`).
- `git ls-tree -r HEAD` содержал только `.gitattributes`.
- Исходников, зависимостей, ресурсов, Gradle Wrapper, тестов и workflow не было.
- Поэтому ошибок в коде приложения не обнаружено **не означает**, что приложение
  исправно: код отсутствует, аудит приложения заблокирован.

## Изменения

- `.github/workflows/android-apk.yml`: CI на push/PR/ручной запуск, проверка структуры
  и Wrapper, JDK 17, Android SDK, Gradle с валидацией Wrapper, lint, JVM-тесты,
  debug APK и диагностические артефакты. Read-only права, таймаут 30 минут,
  отмена устаревших запусков и ошибка при отсутствии APK.
- `README.md`: честный статус и навигация.
- `docs/ANDROID_BUILD.md`: контракт проекта, получение APK, ограничения подписи,
  локальные команды и диагностика.
- `AGENTS.md`: контекст и порядок продолжения работы.

## Проверки и ограничения

- Просмотрены все исходные отслеживаемые файлы (только `.gitattributes`).
- YAML workflow успешно разобран PyYAML (BaseLoader); проверены события запуска.
- `bash -n` успешно проверил синтаксис preflight. На временных фикстурах проверены
  пять случаев: пустой репозиторий, проект в корне, проект в `android/`, отсутствие
  Wrapper JAR, два неоднозначных проекта. Все дали ожидаемый код возврата;
  успешные случаи также дали ожидаемый output `directory`.
- `git diff --check` выполнен без ошибок. Новые файлы до добавления в индекс
  этой командой не проверяются; содержимое дополнительно просмотрено при создании.
- Проверочный PyYAML установлен в отдельный venv вне репозитория; системный pip
  отклонил первоначальную установку (externally-managed-environment).
  Эти проверки не заменяют выполнение GitHub Actions.
- В рабочем окружении нет Java/Gradle и Android-проекта; Android lint,
  unit-тесты и сборка не запускались.
- Workflow не отправлялся на GitHub и не выполнялся там в рамках этой работы.
- Поддержка реального проекта, SDK, зависимостей и variants пока не подтверждена.

## Что еще требуется

Получить исходный Android-проект у владельца, выполнить полноценный аудит кода,
добавить тесты найденных дефектов и добиться успешного CI с устанавливаемым APK.
Не создавать выдуманное приложение вместо отсутствующих исходников.

## 2026-10-22 — исходники получены, фактический аудит

Обновление: утверждение выше об отсутствии исходников относится только к первому
этапу. В `origin/main` появился независимый root commit `b7f4c61` с 242 файлами
(~195.6 MiB). Выборочно импортированы исходники/ресурсы Android, веб-демо и
исторический снимок. SDK/JDK/готовые APK/скриншоты не импортированы. Fast-forward
невозможен из-за независимых историй; ветка с исходной базой сохранена.

### Найдено и исправлено

1. **Сборка ресурсов:** отсутствовал `@xml/network_security_config`. Ссылка удалена,
   cleartext HTTP запрещен в application. Отсутствующий `PollJobService` удален
   из manifest вместе с неиспользуемыми permissions фоновых задач/уведомлений.
2. **JS/native контракт:** HTML вызывает отсутствующие savePrefs/fetchTickets/
   testConnection/createTicketOnServer/syncStatus/readFile. Добавлены `hasNative`
   и `callNative`, неизвестные операции показывают явную ошибку вместо TypeError.
   Локальный режим не объявляется подтвержденным входом/онлайн-соединением,
   локальные заявки и смена статуса помечены как несинхронизированные.
3. **XSS:** экранированы темы/исполнители/комментарии/уведомления/имена проектов
   в обоих активных HTML, IDs в inline handlers ограничены безопасным алфавитом,
   CSS tokens и телефон валидируются. Старый `.bak` исключен из assets.
4. **Секреты/изоляция:** пароль больше не записывается в localStorage, старый ключ
   удаляется при загрузке; logout очищает пароль, сервер/имя и кэш заявок/уведомлений.
   При смене аккаунта/сервера кэш очищается. Android backup отключен.
5. **WebView:** запрещены file/content access и universal file access, mixed content;
   удалённая навигация блокируется, bridge удаляется при destroy. Убрано наложение
   интерфейса на системные панели. Внешние intents/clipboard идут на UI thread,
   отсутствие обработчика intent обрабатывается; номер телефона валидируется в Java.
6. **PWA:** относительные start_url/scope и precache работают из подпапки;
   service worker ограничен собственным cache prefix, не удаляет чужие кэши,
   не перехватывает POST/API и получает свежие статические ресурсы network-first.
7. **Локальные ID:** вместо зависимости от длины массива используются LOCAL-ID
   с временем и случайной частью, чтобы не выдавать их за Jira keys.
8. **CI:** вместо непригодной Gradle-заготовки добавлена сборка существующего дерева
   SDK tools с подписью и проверкой APK; статические регрессионные проверки Node.

### Проверки

- `node --test tests/*.test.cjs`: 8/8 успешно (JS syntax, shared helpers, URL/phone,
  XSS card/ID, отсутствие bridge методов, local login, logout/cache, старый пароль,
  manifest). Тесты используют VM и минимальный DOM mock, не браузер/устройство.
- `bash -n scripts/build-apk.sh`: успешно.
- Попытка использовать toolchain из пользовательского main в отдельном cache:
  Java не запускается без `lib/server/libjvm.so`, aapt требует отсутствующую
  `libc++.so`. Не используются для CI. Это не ошибка новой сборочной цепочки.
- API проверки настроек Actions вернул 403 (недостаточно прав integration для
  endpoint settings). Изменять настройки репозитория не предпринималось.

### Оставшиеся риски / не реализовано

- Jira REST backend, аутентификация, pagination, получение проектов, transitions,
  создание задач и фоновые уведомления **отсутствуют в исходниках** и не добавлены
  как фиктивная реализация. Legacy callbacks оставлены для дальнейшей интеграции.
- Старый `v18_base/assets/index.html` просмотрен как исторический вариант; он не
  поставляется в APK, нормализованы только конечные пробелы; он не должен использоваться как production UI.
- Нет интеграционных тестов Android/WebView/реального Jira. Не заявляем полный
  аудит безопасности или работоспособность на всех Android-устройствах.
- Jira Cloud ADF, поврежденный локальный кэш со сложными несовместимыми объектами,
  обработка quota/storage ошибок, доступность и CSP требуют дальнейшей работы.
- target API33 сохранен для совместимости с исходниками; для магазина требуется
  отдельное обновление target и тестирование на актуальном Android.

### Первый запуск GitHub Actions

- Ветка отправлена на origin, commit `bd58713`.
- Run https://github.com/zigorminsk-debug/jiraHelp/actions/runs/39751162504:
  Node checks успешны, сбой на `android-actions/setup-android@v3` до сборки.
  Скачать подробные логи в sandbox не удалось: results-receiver.actions.githubusercontent.com
  недоступен по сетевым ограничениям. Точную причину этого шага не утверждаем.
- Для повторной проверки закреплен runner `ubuntu-24.04`, используется его штатный
  Android SDK и sdkmanager вместо стороннего setup-android. Actions обновлены до
  опубликованных версий и закреплены полными SHA (checkout7.0.1, setup-node7.1.0,
  setup-java6.1.0, upload-artifact7.0.2); устраняется предупреждение Node20.
- Дополнительно WebView блокирует сетевые загрузки (в том числе remote iframes):
  все ресурсы локальные, реализация REST в будущем должна быть нативной.

### Второй запуск и исправление компиляции

- Run https://github.com/zigorminsk-debug/jiraHelp/actions/runs/39751328193:
  SDK установлен успешно, source checks успешны; javac завершился ошибкой
  `cannot find symbol` в месте lambda (`MainActivity.java:58`). При использовании
  Android bootclasspath требуется `core-lambda-stubs.jar` из build-tools;
  добавлен в bootclasspath (стандартный вспомогательный stub для javac/D8).
- Добавлены ещё две регрессии: XSS в detail comments/assignee и очистка кэша при
  смене локального аккаунта. Теперь 10/10 Node checks успешны.
- Cache prefix service worker получил разделитель scope, чтобы кэш родительского
  deployment не совпадал с вложенным scope. Исторический HTML только whitespace-
  нормализован, функционально не изменялся.

### Подтвержденная сборка и внешний блокер артефактов

Run https://github.com/zigorminsk-debug/jiraHelp/actions/runs/39751498573
(commit `bce87d4`): source checks, SDK, **компиляция/сборка/подпись/verify APK успешны**.
Завершающий upload-artifact упал с точной ошибкой:
`Failed to CreateArtifact: Artifact storage quota has been hit. Unable to upload any new artifacts.`
Это квота аккаунта GitHub, не ошибка исходников/сборки. Не скрываем ошибку через
continue-on-error: без скачиваемого APK workflow не должен притворяться успешным.
Нужны действия владельца: освободить Actions storage/увеличить лимит, дождаться
пересчета квоты и повторить запуск. Существующие артефакты не удалялись.

После этого добавлена очистка скрытой detail view, drafts и settings/password при
logout и возврат на dashboard при входе (не показывать данные предыдущей сессии).
Локально 11/11 Node tests успешны, bash syntax, XML и YAML parse успешны.
Установка на Android-устройство не проверялась.

## 2026-10-22 — выдача подписанного APK без квоты Artifacts

По повторному запросу владельца исправлена доставка APK: вместо заблокированного
Actions Artifacts используется GitHub Releases. `scripts/publish-apk.sh` создает
уникальный prerelease `apk-<run-id>-<attempt>`, загружает только APK, контрольную
сумму и вывод проверки сертификата. Повторно скачивает APK и проверяет SHA-256 и
побайтовое совпадение. Успех публикации не маскируется; старые релизы не удаляются.

Workflow разделяет доверенные push/manual (`main`, рабочая ветка) с contents:write
и read-only PR/прочие ветки. Checkout credentials не сохраняются. Общая сборка
вынесена в composite action. Подпись по-прежнему debug, ключ временный; никакой
production-подписи и совместимости с прежним сертификатом не обещается.

Добавлены 3 теста публикации с подменным gh и фиктивным APK: корректная выдача,
поврежденный download, отказ API. Эти тесты не являются реальной публикацией.
Команды локальной проверки: `node --test tests/*.test.cjs` (14 тестов),
`bash -n scripts/build-apk.sh scripts/publish-apk.sh`, `git diff --check`.
Реальный запуск CI проверяется после отправки изменений; результат ниже.

### Подтвержденный результат публикации

- Commit: `73081a684971bbd4028c990fdea5aaae108b22f2`.
- Run: https://github.com/zigorminsk-debug/jiraHelp/actions/runs/39752620540 — **success**.
- Release: https://github.com/zigorminsk-debug/jiraHelp/releases/tag/apk-39752620540-1.
- APK: https://github.com/zigorminsk-debug/jiraHelp/releases/download/apk-39752620540-1/CSL-HelpDesk-debug.apk.
- Через API подтверждены три assets в состоянии uploaded: APK (54 213 байт),
  SHA256SUMS (89 байт), signature.txt (953 байта).
- Все 14 Node checks, Java/resource compile, D8, zipalign, apksigner verify и
  публикация с повторным скачиванием/проверкой содержимого прошли успешно.
- `check` job пропущен **ожидаемо**: доверенный push обслуживает `publish` job,
  который сам запускает те же проверки перед сборкой. Это не пропуск тестирования.
- Повторная сборка создает новый подписанный APK в новом prerelease, предыдущие
  ссылки сохраняются. Физическое устройство не тестировалось; Jira API не добавлялся.

## 2026-10-22 — исправление отсутствующего подключения (1.10.4 / code12)

По скриншоту телефона подтверждено: сообщение про `testConnection` обусловлено
отсутствием реализации в предыдущем APK, а не диагностикой сервера. Добавлены
нативный Jira REST v2 transport (GET myself/search), Basic Auth, HTTPS/TLS default,
запрет redirects, timeouts/response limits/безопасные сообщения ошибок.
Session credentials только в памяти; logout/destroy инвалидирует callbacks старого
аккаунта. Список загружается постранично; частичные результаты при ошибках не
применяются. Данные callback передаются через JSON serialization/parse, не JS code.
Тест кандидатных credentials не меняет активный аккаунт; реальный результат виден
в настройках, надпись «Онлайн» не выставляется по факту ввода данных.

JS: успешный пустой снимок очищает старые server tickets, сохраняет LOCAL drafts;
обновляются descriptions/client/created и поддерживается текстовое представление ADF.
Периодический refresh не выполняется после logout. Создание/status/comments по-прежнему
локальные; release notes/README/AGENTS обновлены, ограничение явно документировано.

Локально: 18 Node tests успешны, `bash -n scripts/*.sh` успешно. JVM transport tests
добавлены в `tests/java/JiraClientTest.java` и CI (`scripts/test-java.sh`): fake HTTP,
URL/context path, auth/header, redirects, HTTP ошибки, HTML вместо JSON, response cap,
disconnect. JDK локально отсутствует — реальная компиляция/выполнение проверяются CI.
Сервер `h.csl.by` не проверялся из sandbox (outbound restrictions); реальные credentials
не запрашивались. Инструкции и следующий device test: `docs/JIRA_CONNECTION.md`.

### Результат CI 1.10.4

Run https://github.com/zigorminsk-debug/jiraHelp/actions/runs/39754888214 — **success**,
commit `356221a8a30d38c7c05a8953328cba6e0815e4e9`. Composite build выполнил Node
regressions и pure-JVM JiraClient tests, компиляцию Android, подпись и verify.
APK опубликован и повторно скачан/проверен через SHA-256 и cmp.
Release: https://github.com/zigorminsk-debug/jiraHelp/releases/tag/apk-39754888214-1.
Через API подтвержден uploaded APK размером 62 405 байт, SHA256SUMS и signature.txt.
Это подтверждает сборку/публикацию, **не подключение к серверу h.csl.by** — нужна
проверка владельцем с телефона по `docs/JIRA_CONNECTION.md`.
