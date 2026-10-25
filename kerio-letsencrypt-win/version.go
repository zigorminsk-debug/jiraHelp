package main

// appVersion — единственный источник правды для версии программы.
//
// Меняйте версию ТОЛЬКО здесь. Отсюда она автоматически попадает в:
//   - User-Agent при подключении к Kerio Admin API;
//   - JSON-поле "version" при Session.login;
//   - заголовок окна Windows;
//   - проверку TestVersionConsistency (unit-тест сверяет с ней ui/index.html
//     и PE-ресурс rsrc_windows_amd64.syso).
//
// После изменения версии обязательно синхронизируйте:
//   - kerio-letsencrypt-win/ui/index.html (бейдж в шапке и строка в подвале);
//   - kerio-letsencrypt-win/rsrc_windows_amd64.syso (FileVersion/ProductVersion)
//     — иначе `go test ./...` и CI-сборка завершатся ошибкой;
//   - kerio-letsencrypt-win/README.md, FAQ.md и тело PR.
const appVersion = "4.7.1"

// appVersion4 — четырёхкомпонентная версия для полей FileVersion/ProductVersion
// в PE-ресурсе Windows (например, 4.5.2.0). Последний компонент всегда 0.
const appVersion4 = appVersion + ".0"
