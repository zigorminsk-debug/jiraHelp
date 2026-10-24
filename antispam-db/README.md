# KCM AntiSpam DB — автообновляемая антиспам-база для Kerio Connect

Ежедневно собираемая база индикаторов спама, фишинга и мошеннических писем.
Публикуется в GitHub Releases (`antispam-db-latest`) и в ветке `antispam-db`;
программа **KerioCertManager** (вкладка «🛡️ Антиспам-база KCM») устанавливает её
в Kerio Connect и обновляет по расписанию.

## Что генерируется (`dist/`)

| Файл | Назначение |
|---|---|
| `kerio-antispam.cf` | готовые правила SpamAssassin для Kerio Connect (основной артефакт) |
| `spam-domains.txt` | домены отправителей и фишинговых ссылок |
| `spam-emails.txt` | конкретные адреса отправителей |
| `scam-subjects.txt` | подстроки тем мошеннических писем |
| `scam-phrases-ru.txt` | фразы в теле письма (RU/EN) |
| `threat-ips.txt` | IPv4 CIDR источников спама |
| `allowlist.txt` | белый список (защита от ложных срабатываний) |
| `manifest.json` | версия, дата, количества, размеры и **SHA-256** каждого файла |
| `stats.json`, `RELEASE_NOTES.md` | статистика сборки и текст релиза |

## Как работает сборка

`tools/build_db.py`:

1. читает курируемые списки из `sources/*.txt`;
2. скачивает публичные фиды из `feeds.json` (URLhaus, OpenPhish, Phishing Army, HaGeZi, Spamhaus DROP);
3. нормализует домены/URL/IP, выбрасывает приватные и слишком широкие подсети;
4. применяет белый список (включая поддомены) и жёсткие лимиты по количеству записей;
5. генерирует `kerio-antispam.cf` с группами правил и счётом очков;
6. считает SHA-256 и пишет `manifest.json` + `RELEASE_NOTES.md`.

```bash
python3 antispam-db/tools/build_db.py               # полная сборка (нужен интернет)
python3 antispam-db/tools/build_db.py --offline     # только курируемые списки
python3 antispam-db/tools/build_db.py --out /tmp/db # в другую папку
```

Workflow `.github/workflows/antispam-db.yml` запускается по расписанию (ежедневно 03:17 UTC),
по изменению `antispam-db/**` и вручную. Он собирает базу, проверяет SHA-256 и синтаксис
регулярных выражений, публикует релиз `antispam-db-latest` и force-push в ветку `antispam-db`.

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

- домены/URL — `sources/scam-domains.txt`;
- адреса — `sources/scam-emails.txt`;
- темы — `sources/scam-subjects.txt` (подстрока, регистр не важен);
- фразы — `sources/scam-phrases-ru.txt`;
- IP/CIDR — `sources/threat-ips.txt`;
- исключения — `sources/allowlist.txt`.

После изменения запустите сборку локально или дождитесь workflow.

## Лицензии и источники

- URLhaus (abuse.ch) — CC0;
- OpenPhish public feed — публичный фид;
- Phishing Army — CC BY-NC 4.0;
- HaGeZi DNS blocklists — по лицензии проекта;
- Spamhaus DROP — по условиям Spamhaus;
- курируемые списки и код сборщика — MIT.

База предоставляется «как есть» и не заменяет антивирус. Она не фильтрует легитимные
рассылки по политическим или коммерческим признакам — только технические индикаторы
спама, фишинга и вредоносных ссылок.
