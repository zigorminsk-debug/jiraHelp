# Сборка Android APK

## Фактическая структура

Проект не использует Gradle и сторонние Java-зависимости:

- `helpdesk-apk/AndroidManifest.xml` — applicationId `com.csl.helpdesk`, min API 21,
  target API 33, версия из исходников `1.10.3` / code `11`.
- `helpdesk-apk/src/` — Java Activity и JS bridge для обмена/телефона/буфера.
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

## GitHub Actions

Workflow `.github/workflows/android-apk.yml` запускается на push, pull request,
workflow_dispatch. Он проверяет JS/регрессии, устанавливает JDK/SDK, собирает,
проверяет и загружает **только конечный APK**, без ключей и промежуточных файлов.

После отправки рабочей ветки: GitHub → Actions → Android APK → успешный запуск →
Artifacts → `CSL-HelpDesk-debug-<run>-<attempt>`. Скачать ZIP, извлечь APK.
Срок хранения — 14 дней. Ручной запуск в UI доступен после появления workflow
в default branch; для ветки до слияния используется push.

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
Внешние Actions закреплены major-тегами, не immutable SHA — остаётся задача усиления
supply-chain защиты. GitHub-hosted runner нужен с доступом к загрузкам Google SDK.
