# Антиспам-база KCM 2026.10.24-0851

Сгенерирована: 2026-10-24T08:51:43+00:00

| Группа правил | Записей | Очки SpamAssassin |
|---|---:|---|
| Домены отправителей | 7446 | +3.2 |
| Адреса отправителей | 0 | +4.5 |
| Мотивы в теме письма | 39 | +1.8 |
| Фразы мошеннических писем | 23 | +1.5 |
| Домены фишинговых ссылок | 30000 | +2.5 |
| IP/CIDR источников | 4766 | +3.0 |
| Белый список | 58 | −6.0 |

## Источники

- ✅ phishing-database-domains: 11930 записей (Phishing.Database (MIT))
- ✅ openphish: 258 записей (OpenPhish public feed)
- ✅ shadowwhisperer-scam: 7446 записей (ShadowWhisperer BlockLists — Scam (Unlicense))
- ✅ hagezi-tif: 7698 записей (HaGeZi Threat Intelligence Feed (mini))
- ✅ dogino-phishing-domains: 5998 записей (Dogino/Discord-Phishing-URLs)
- ✅ shadowwhisperer-malware: 6000 записей (ShadowWhisperer BlockLists — Malware (Unlicense))
- ✅ dogino-scam-urls: 2998 записей (Dogino/Discord-Phishing-URLs — scam URLs)
- ✅ spamhaus-drop: 1687 записей (Spamhaus DROP List)
- ✅ firehol-level1: 4626 записей (FireHOL level1 (агрегат DSHIELD/FEODO/DROP/bogons))
- ⚠️ urlhaus: нужен ключ ABUSECH_AUTH_KEY (бесплатный, некоммерческое использование)
- ⏸ phishing-army: отключён (отключён: Cloudflare отдаёт заглушку «One moment, please...» вместо списка (0 записей). Замена — Phishing.Database ACTIVE.)
- ⏸ stevenblack-unified: отключён (отключён: преимущественно реклама/трекеры, не спам-письма)

## Файлы

- `kerio-antispam.cf` — готовые правила SpamAssassin для Kerio Connect
- `spam-domains.txt`, `phishing-links.txt`, `spam-emails.txt`, `scam-subjects.txt`, `scam-phrases-ru.txt`, `threat-ips.txt`, `allowlist.txt` — исходные списки
- `manifest.json` — версия, размеры и SHA-256 каждого файла

## Установка

1. В KerioCertManager откройте вкладку «🛡️ Антиспам-база KCM (GitHub)» и нажмите «Установить / Обновить базу в Kerio».
2. Либо вручную: скопируйте `kerio-antispam.cf` в `<Kerio>\plugins\spamassassin\rules\` и перезапустите службу KerioMailServer.

_Данные предоставляются «как есть». База не заменяет антивирус и не фильтрует легитимные рассылки по политическим/коммерческим признакам._