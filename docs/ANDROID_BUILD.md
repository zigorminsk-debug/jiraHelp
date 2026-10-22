# Сборка Android APK

## Фактическая структура

Проект не использует Gradle и сторонние Java-зависимости:

- `helpdesk-apk/AndroidManifest.xml` — applicationId `com.csl.helpdesk`, min API 21,
  target API 33, версия из исходников `1.10.4` / code `12`.
- `helpdesk-apk/src/` — Java Activity, native HTTPS Jira read-only клиент и JS bridge.
- `helpdesk-apk/res/`, `helpdesk-apk/assets/` — Android-ресурсы и локальный HTML/JS.
- `helpdesk-app/` и `v18_base/` не попадают в APK.

## Инструменты и команды

Требуются полноценные JDK 17, Node.js 22 для тестов, Android SDK с пакетами
`platforms;android-33`, `build-tools;35.0.0`. Установка SDK:

```sh
sdkmanager 'platforms;android-33' 'build-tools;35.0.0'
node --test tests/*.test.cjs
export ANDROID_SDK_ROOT=/path/to/android-sdk
bash scripts/build-apk.sh
```

Скрипт `scripts/build-apk.sh` использует `aapt` для ресурсов и генерации R.java,
`javac` (Java 8 bytecode), `d8` для classes.dex, затем `zipalign`, `apksigner`.
Проверяет подпись и выводит метаданные пакета. Результаты в игнорируемом
`build/android/`, который очищается перед каждой сборкой. `ANDROID_PLATFORM` и
`ANDROID_BUILD_TOOLS` позволяют переопределить версии для локальной диагностики.
Не используйте неполные копии SDK/JDK из пользовательского main: локальная проба
показала отсутствие `lib/server/libjvm.so` и зависимость aapt от `libc++.so`.
CI скачивает стандартные пакеты самостоятельно.

## GitHub Actions и получение APK

Workflow `.github/workflows/android-apk.yml` запускается на push, pull request,
workflow_dispatch. Общие шаги сборки вынесены в `.github/actions/build-apk/action.yml`.

- Push/manual в `main` или `arena/0b4677fb-jirahelp`: job `publish` проверяет
  исходники, компилирует/подписывает APK и публикует GitHub **prerelease**
  `apk-<GITHUB_RUN_ID>-<GITHUB_RUN_ATTEMPT>` с APK, `SHA256SUMS`, `signature.txt`.
- PR/прочие ветки: read-only job `check`, проверка и сборка без публикации.
- Checkout не сохраняет credentials. Только доверенный publish job получает
  `contents: write`; токен передается лишь шагу публикации. `pull_request_target`
  не используется. Старые релизы/теги не удаляются и не перезаписываются.
- После upload скрипт скачивает APK обратно, проверяет SHA-256 и точное совпадение
  с собранным файлом. Только затем выводит ссылку в Actions Summary.

Открыть GitHub → Actions → Android APK → успешный запуск → Summary → Download
release; либо репозиторий → Releases → нужный `apk-...` → Assets →
`CSL-HelpDesk-debug.apk`. Не скачивать Source code ZIP вместо APK.
Новый prerelease не объявляется latest production release. Releases не расходуют
квоту Actions Artifacts и не имеют автоматического срока хранения 14 дней.
Владельцу нужно самому управлять сроком хранения; ничего автоматически не удаляем.
При ручном запуске в UI workflow должен находиться в default branch; до слияния
запускается push рабочей ветки. При ошибке прав публикации проверить разрешения
GITHUB_TOKEN/политики Actions: без успешной выдачи файла запуск останется красным.

## Подпись и установка

Это установочный debug APK, не release для магазина. Скрипт каждый раз создает
временный RSA debug-ключ с общеизвестным паролем `android`. Такой пароль допустим
только для этой временной тестовой подписи. Не используйте ее для production.
Из-за смены подписи старое приложение может потребоваться удалить, предварительно
экспортировав локальные данные. На устройстве разрешить установку из выбранного
источника. Совместимость/запуск требуется проверить на реальном устройстве.

Для стабильной подписи согласовать с владельцем отдельный keystore и хранение
в GitHub Secrets, не коммитить ключ в репозиторий. Release-публикация не настроена.
AGP lint/Gradle unit tests не запускаются: в проекте нет Gradle. Есть Node regression
checks, компиляция Java/ресурсов и проверка APK; это не заменяет Android UI-тесты.
Внешние Actions закреплены immutable SHA проверенных release-тегов; при обновлении
проверять исходники и менять SHA осознанно. Runner закреплен `ubuntu-24.04`, SDK manager
берется из предустановленного Android SDK runner. GitHub-hosted runner нужен с доступом к загрузкам Google SDK.

## История квоты Actions

Первые запуски успешно собирали/проверяли APK, но `upload-artifact` возвращал
`Artifact storage quota has been hit`. Существующие артефакты не удалялись.
Текущая схема использует Releases вместо Actions Artifacts: менять квоту для неё
не требуется. Не возвращать upload-artifact без решения вопроса квоты владельцем.
