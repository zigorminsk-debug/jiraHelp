; ============================================================================
;  KerioCertManager — установщик для Windows (Inno Setup 6)
;
;  Что делает установщик:
;    • ставит программу в C:\Program Files\KerioCertManager (можно изменить);
;    • создаёт ярлыки в меню «Пуск» и (по желанию) на рабочем столе;
;    • копирует рядом инструкцию FAQ.md и README.md;
;    • при удалении снимает задания Планировщика (автопродление и база),
;      НО НЕ УДАЛЯЕТ папку certs с сертификатами и настройками.
;
;  Сборка:  ISCC.exe installer\KerioCertManager-Setup.iss
;  Тихая установка:  KerioCertManager-Setup-4.6.0.exe /S /D=C:\KerioCertManager
; ============================================================================

#define MyAppName "KerioCertManager"
; ВАЖНО: версия должна совпадать с appVersion в kerio-letsencrypt-win/version.go.
; Это проверяет unit-тест TestInstallerVersionMatchesApp (go test ./...).
#define MyAppVersion "4.9.3"
#define MyAppPublisher "Zakharevich Igor"
#define MyAppURL "https://github.com/zigorminsk-debug/jiraHelp"
#define MyAppExeName "KerioCertManager.exe"

; Каталог, откуда берутся файлы: корень репозитория (на уровень выше installer\).
#define RepoRoot ".."

[Setup]
; AppId — «личность» программы. Он НЕ должен меняться между версиями, иначе
; Windows будет считать новую версию другой программой и в «Приложениях»
; появятся две записи.
AppId={{BE09222C-7D93-4DBC-AAC0-FA7C07609B8B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
VersionInfoVersion={#MyAppVersion}.0
VersionInfoProductVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=Установщик KerioCertManager — SSL-сертификаты, антиспам-база и диагностика для Kerio Connect
VersionInfoProductName={#MyAppName}

DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
; Показываем страницу выбора каталога только опытным пользователям.
DisableDirPage=auto
DisableProgramGroupPage=yes
DisableWelcomePage=no
AllowNoIcons=yes

OutputDir={#RepoRoot}\installer\output
OutputBaseFilename=KerioCertManager-Setup-{#MyAppVersion}
SetupIconFile={#RepoRoot}\kerio-letsencrypt-win\ui\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}

; Программа управляет службой Kerio и заданиями Планировщика — без прав
; администратора она бесполезна, поэтому требуем их сразу.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=

Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ShowLanguageDialog=no
SetupLogging=yes
CloseApplications=yes
RestartApplications=no
AllowUNCPath=no
; Минимальная версия Windows: Windows 7 SP1 x64 / Server 2008 R2.
MinVersion=6.1sp1

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительно:"; Flags: unchecked
Name: "quicklaunchicon"; Description: "Создать ярлык в панели быстрого запуска"; GroupDescription: "Дополнительно:"; Flags: unchecked; OnlyBelowVersion: 6.1

[Files]
Source: "{#RepoRoot}\KerioCertManager.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoRoot}\FAQ.md"; DestDir: "{app}"; DestName: "FAQ.md"; Flags: ignoreversion
Source: "{#RepoRoot}\kerio-letsencrypt-win\README.md"; DestDir: "{app}"; DestName: "README.md"; Flags: ignoreversion
Source: "{#RepoRoot}\kerio-letsencrypt-win\ui\icons\*.ico"; DestDir: "{app}\Иконки на выбор"; Flags: ignoreversion

[Dirs]
; Папка сертификатов создаётся заранее и НИКОГДА не удаляется при удалении
; программы (uninsneveruninstall) — иначе можно потерять приватные ключи.
Name: "{app}\certs"; Permissions: users-modify; Flags: uninsneveruninstall

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Comment: "SSL-сертификаты, антиспам-база и диагностика для Kerio Connect"
Name: "{group}\Инструкция (FAQ)"; Filename: "{app}\FAQ.md"
Name: "{group}\Удалить {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: quicklaunchicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Запустить {#MyAppName}"; Flags: nowait postinstall skipifsilent
Filename: "{app}\FAQ.md"; Description: "Открыть инструкцию"; Flags: shellexec nowait postinstall skipifsilent unchecked

[UninstallRun]
; Снимаем задания Планировщика, иначе после удаления программы они будут
; пытаться запустить несуществующий exe (и «молча» падать в журнале).
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN ""KerioLetsEncryptAutoRenew"""; Flags: runhidden; RunOnceId: "DelAutoRenewTask"
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN ""KerioCertManager_AntiSpamDB"""; Flags: runhidden; RunOnceId: "DelAntiSpamTask"

[UninstallDelete]
; Убираем только служебные «хвосты» автообновления. Папка certs сохраняется.
Type: files; Name: "{app}\{#MyAppExeName}.old"
Type: filesandordirs; Name: "{app}\update-tmp"
Type: dirifempty; Name: "{app}"

[Code]
// Перед установкой предупреждаем, если программа сейчас запущена: иначе
// Windows не даст заменить .exe и установка «тихо» не сработает.
function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if Exec(ExpandConstant('{sys}\tasklist.exe'), '/FI "IMAGENAME eq KerioCertManager.exe" /NH',
          '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    // Ничего не делаем: если программа запущена, Inno сам предложит её закрыть
    // (CloseApplications=yes). Здесь только напоминание в лог.
    Log('tasklist выполнен, код ' + IntToStr(ResultCode));
  end;
end;

// После установки показываем, где лежат сертификаты — это первый вопрос
// администратора после «поставил, а где файлы?».
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    Log('Сертификаты и настройки: ' + ExpandConstant('{app}\certs'));
end;
