# KCM AntiSpam DB — автообновляемая антиспам-база для Kerio Connect

Ежедневно собираемая база индикаторов спама, фишинга и мошеннических писем.
Публикуется в GitHub Releases (`antispam-db-latest`) и в ветке `antispam-db`;
программа **KerioCertManager** (вкладка «🛡️ Антиспам-база KCM») устанавливает её
в Kerio Connect и обновляет по расписанию.

## Что генерируется (`dist/`)

| Файл | Назначение |
|---|---|
| `kerio-antispam.cf` | готовые правила SpamAssassin для Kerio Connect (основной артефакт) |
| `spam-domains.txt` | домены **отправителей** (правила `From =~ /@домен/`) |
| `phishing-links.txt` | домены **ссылок/лендингов** (правила `uri`) |
| `spam-emails.txt` | конкретные адреса отправителей |
| `scam-subjects.txt` | подстроки тем мошеннических писем |
| `scam-phrases-ru.txt` | фразы в теле письма (RU/EN) |
| `threat-ips.txt` | IPv4-сети источников спама |
| `allowlist.txt` | белый список (защита от ложных срабатываний) |
| `manifest.json` | версия, дата, количества, размеры, **SHA-256** каждого файла и **состояние источников** |
| `stats.json`, `RELEASE_NOTES.md` | статистика сборки и текст релиза |

## Источники

| Источник | Тип | Статус | Лицензия |
|---|---|---|---|
| Phishing.Database — `phishing-domains-ACTIVE.txt` | ссылки | ✅ работает | MIT |
| OpenPhish public feed | ссылки | ✅ работает | публичный фид |
| ShadowWhisperer BlockLists — `Scam` | отправители | ✅ работает | Unlicense |
| ShadowWhisperer BlockLists — `Malware` | ссылки | ✅ работает | Unlicense |
| HaGeZi TIF (mini) | ссылки | ✅ работает | см. репозиторий |
| Dogino Discord-Phishing (domains + scam URLs) | ссылки | ✅ работает | MIT |
| Spamhaus DROP | IP/CIDR | ✅ работает | условия Spamhaus |
| FireHOL level1 (DSHIELD/FEODO/DROP/bogons) | IP/CIDR | ✅ работает | см. репозиторий |
| abuse.ch URLhaus | ссылки | 🔑 нужен `ABUSECH_AUTH_KEY` | abuse.ch (non-commercial) |
| phishing.army | — | ⏸ заменён на Phishing.Database | CC BY-NC 4.0 |
| StevenBlack/hosts | — | ⏸ отключён (реклама/трекеры) | MIT |

### Почему URLhaus отключён по умолчанию

21 октября 2026 abuse.ch **закрыл анонимные выгрузки**: `urlhaus.abuse.ch/downloads/*`
(включая `text_recent`, `csv_online`, `urlhaus.ndb`) отвечают `410 Gone`, а API без ключа — `401`.
Остался официальный путь через личный **Auth-Key** (бесплатный, только для некоммерческого
использования): `GET https://urlhaus-api.abuse.ch/v1/urls/recent/...` с заголовком `Auth-Key`.

Сборщик поддерживает это «из коробки»: достаточно добавить секрет `ABUSECH_AUTH_KEY`
(Settings → Secrets and variables → Actions → New repository secret), и фид включится сам —
без правок кода. Пока ключа нет, источник честно помечается в `manifest.json` как
`skipped` с причиной, а база собирается из остальных источников.

### Почему phishing.army заменён

`https://phishing.army/download/phishing_army_blocklist_extended.txt` отдаёт не список,
а Cloudflare-заглушку «One moment, please…» (анти-бот проверка для дата-центров),
поэтому парсер получал 0 доменов. Сборщик теперь **распознаёт HTML/анти-бот страницы**
и сообщает об этом в `sources[].error`, а не молча пишет «0 записей».
Замена — **Phishing.Database** (`phishing-domains-ACTIVE.txt`, 11 МБ, MIT), который
содержит те же активные фишинговые домены и стабильно доступен через GitHub.

## Как работает сборка

`tools/build_db.py`:

1. читает курируемые списки из `sources/*.txt` (`scam-domains.txt`, `phishing-links.txt`, …);
2. скачивает публичные фиды из `feeds.json` и раскладывает их по ролям **senders / links / ips**;
3. нормализует домены/URL/IP: понимает plain-домены, `hosts`, adblock (`||domain^`), URL-ленты
   и выгрузки вида `0.0.0.0domain.tld`; отбрасывает приватные и слишком широкие сети;
4. применяет белый список: доверенные зоны (`bank.by`, `google.com`, …) не блокируются никогда,
   а публичные CDN/хостинги (`000webhostapp.com`, `pages.dev`, …) — только точно, без поддоменов
   (то есть `evil.000webhostapp.com` в базе остаётся);
5. обрезает списки по лимитам **с учётом приоритета источника** (сначала курируемые списки и
   Phishing.Database, потом остальные), а не по алфавиту;
6. генерирует `kerio-antispam.cf`, считает SHA-256 и пишет `manifest.json` + `RELEASE_NOTES.md`.

```bash
python3 antispam-db/tools/build_db.py               # полная сборка (нужен интернет)
python3 antispam-db/tools/build_db.py --offline     # только курируемые списки
python3 antispam-db/tools/build_db.py --out /tmp/db # в другую папку
```

Workflow `.github/workflows/antispam-db.yml` запускается по расписанию (ежедневно 03:17 UTC),
по изменению `antispam-db/**` и вручную. Он собирает базу, проверяет SHA-256, синтаксис
регулярных выражений и санитарные условия (белый список не попал в чёрный), публикует релиз
`antispam-db-latest` и force-push в ветку `antispam-db`.

## Правила и очки

| Группа | Правило | Очки |
|---|---|---:|
| Домены отправителей | `KCM_SPAM_FROM_DOMAIN_*` (`From =~ /@домен/`) | +3.2 |
| Адреса отправителей | `KCM_SPAM_FROM_EMAIL_*` | +4.5 |
| Мотивы в теме | `KCM_SCAM_SUBJECT_*` | +1.8 |
| Фразы в теле | `KCM_SCAM_PHRASE_*` | +1.5 |
| Фишинговые ссылки | `KCM_PHISH_URL_*` (`uri`) | +2.5 |
| IP/CIDR источников | `KCM_SPAM_SRC_IP_*` (`Received`) | +3.0 |
| Белый список | `KCM_ALLOW_FROM_*` | −6.0 |

Очки складываются с собственными правилами Kerio (SPF/DKIM/DMARC, DNSBL, байесовский фильтр).
Порог отказа Kerio по умолчанию — около 5.0.

**IP-правила:** SpamAssassin ищет IP простым текстом, поэтому правила строятся только для
сетей `/16`, `/24` и `/32` — так исключены ложные срабатывания. Более узкие/широкие сети
(`/20`, `/22`, …) остаются в `threat-ips.txt` для предварительной проверки писем в программе,
но в `.cf` не попадают (счётчик — `stats.json → ipsWithoutRegexRule`).

## Установка в Kerio Connect

**Из программы:** вкладка «🛡️ Антиспам-база KCM (GitHub)» → «Проверить обновления» →
«Предпросмотр» → «Установить / Обновить базу в Kerio».

**Вручную:**

1. Скачайте `kerio-antispam.cf` со страницы релиза `antispam-db-latest`.
2. Скопируйте в `<Kerio>\plugins\spamassassin\rules\` (Windows: `C:\Program Files\Kerio\MailServer\plugins\spamassassin\rules`).
3. Перезапустите службу `KerioMailServer` (или включите/выключите SURBL в Контент-фильтре и нажмите «Применить»).
4. В письмах появится заголовок `X-Spam-Score` с учётом правил `KCM_*`.

**Удаление:** удалите `kerio-antispam.cf` из папки правил и перезапустите службу.

## Как добавить свои индикаторы

- домены отправителей — `sources/scam-domains.txt`;
- домены ссылок — `sources/phishing-links.txt`;
- адреса — `sources/scam-emails.txt`;
- темы — `sources/scam-subjects.txt` (подстрока, регистр не важен);
- фразы — `sources/scam-phrases-ru.txt`;
- IP/CIDR — `sources/threat-ips.txt`;
- исключения — `sources/allowlist.txt`.

После изменения запустите сборку локально или дождитесь workflow.

## Лицензии

- Phishing.Database — MIT;
- ShadowWhisperer BlockLists — Unlicense;
- Dogino Discord-Phishing-URLs — MIT;
- HaGeZi DNS blocklists — по лицензии проекта;
- OpenPhish public feed — публичный фид;
- Spamhaus DROP — по условиям Spamhaus;
- FireHOL blocklist-ipsets — по лицензии репозитория;
- abuse.ch URLhaus — non-commercial, требуется личный Auth-Key;
- курируемые списки и код сборщика — MIT.

База предоставляется «как есть» и не заменяет антивирус. Она не фильтрует легитимные
рассылки по политическим или коммерческим признакам — только технические индикаторы
спама, фишинга и вредоносных ссылок.
