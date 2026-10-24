#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KCM AntiSpam DB builder.

Собирает антиспам-базу из:
  1) курируемых источников  ./sources/*.txt
  2) публичных фидов        ./feeds.json  (URLhaus, OpenPhish, Phishing Army, HaGeZi, Spamhaus DROP)

Результат (./dist):
  manifest.json          — версия, дата, количество записей, SHA-256 файлов
  spam-domains.txt       — домены отправителей/ссылок
  spam-emails.txt        — конкретные адреса
  scam-subjects.txt      — шаблоны тем писем
  scam-phrases-ru.txt    — фразы мошеннических писем (RU/EN)
  threat-ips.txt         — IP/CIDR источников спама
  allowlist.txt          — белый список (защита от ложных срабатываний)
  kerio-antispam.cf      — готовые правила SpamAssassin для Kerio Connect
  stats.json             — статистика по источникам

Запуск:
  python3 tools/build_db.py                 # полная сборка (нужен интернет)
  python3 tools/build_db.py --offline       # только курируемые списки
  python3 tools/build_db.py --out dist
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
URL_RE = re.compile(r"^(?:https?|ftp)://([^/:?#]+)", re.I)
HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-z0-9._-]+)$", re.I)
ADBLOCK_RE = re.compile(r"^\|\|([a-z0-9._-]+)\^?$", re.I)

# Жёсткие лимиты, чтобы .cf оставался быстрым для SpamAssassin
MAX_DOMAINS = 26000
MAX_EMAILS = 4000
MAX_URLS = 14000
MAX_IPS = 6000
MAX_SUBJECTS = 400
MAX_PHRASES = 400

# Никогда не блокируем эти домены (крупные легитимные отправители и сервисы)
SAFETY_ALLOW = """
google.com googleapis.com gstatic.com youtube.com gmail.com
microsoft.com microsoftonline.com office.com office365.com outlook.com live.com windows.com windowsupdate.com azure.com
apple.com icloud.com mozilla.org
yandex.ru yandex.by yandex.net ya.ru mail.ru inbox.ru list.ru bk.ru
beltelecom.by tut.by onliner.by
github.com gitlab.com cloudflare.com amazon.com amazonaws.com paypal.com
facebook.com instagram.com whatsapp.com telegram.org t.me vk.com ok.ru
sendgrid.net mailchimp.com mandrillapp.com mailgun.org amazonses.com
dropbox.com zoom.us slack.com atlassian.net jetbrains.com
1c.ru bitrix24.ru kaspersky.com drweb.com
""".split()

CHUNK_DOMAINS = 50
CHUNK_EMAILS = 40
CHUNK_URLS = 40
CHUNK_IPS = 60
CHUNK_SUBJECTS = 25
CHUNK_PHRASES = 25
CHUNK_ALLOW = 60


def log(msg):
    print(msg, flush=True)


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            yield line


def normalize_domain(raw):
    d = raw.strip().lower().strip(".")
    d = d.replace("*.", "").replace("||", "").replace("^", "")
    if d.startswith("www."):
        pass  # оставляем как есть, www. всё равно попадёт через базовый домен ниже
    if not DOMAIN_RE.match(d):
        return ""
    return d


def extract_host(line):
    line = line.strip()
    if not line or line.startswith("#") or line.startswith(";") or line.startswith("!"):
        return ""
    m = URL_RE.match(line)
    if m:
        host = m.group(1).lower().strip(".")
    else:
        m = HOSTS_RE.match(line)
        if m:
            host = m.group(1).lower().strip(".")
        else:
            m = ADBLOCK_RE.match(line)
            host = m.group(1).lower().strip(".") if m else line.split()[0].lower().strip(".")
    return normalize_domain(host)


def fetch(url, timeout=45, limit=16 * 1024 * 1024):
    req = urllib.request.Request(url, headers={
        "User-Agent": "KCM-AntiSpam-DB/1.0 (+https://github.com/zigorminsk-debug/jiraHelp)",
        "Accept": "text/plain,*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(limit)
    return data.decode("utf-8", errors="replace")


def load_feeds():
    path = os.path.join(ROOT, "feeds.json")
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh).get("feeds", [])


def parse_ip_lines(text):
    out = set()
    for line in text.splitlines():
        line = line.split(";")[0].split("#")[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.is_private or net.is_loopback or net.is_multicast:
            continue
        if net.prefixlen < 12:  # слишком широкие диапазоны пропускаем
            continue
        out.add(str(net))
    return out


def cidr_to_regex(cidr):
    """Превращает IPv4 CIDR в префиксный regex для заголовка Received.

    Поддерживаются только октетно-выровненные маски (/16, /24, /32): для них
    регулярное выражение остаётся точным и не даёт ложных срабатываний.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4 or net.prefixlen < 16 or net.prefixlen % 8 != 0:
        return ""
    octets = str(net.network_address).split(".")[: net.prefixlen // 8]
    if not octets:
        return ""
    return r"\.".join(octets) + ("" if net.prefixlen == 32 else r"\.")


def build(offline=False, out_dir=None):
    started = time.time()
    out_dir = out_dir or os.path.join(ROOT, "dist")
    os.makedirs(out_dir, exist_ok=True)

    domains, emails, subjects, phrases, urls, ips, allow = set(), set(), set(), set(), set(), set(), set()
    stats = {"sources": [], "startedAt": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    # --- белый список ---
    for base in SAFETY_ALLOW:
        allow.add(base)
    for line in read_lines(os.path.join(ROOT, "sources", "allowlist.txt")):
        d = normalize_domain(line)
        if d:
            allow.add(d)
    allow -= {""}

    # --- курируемые списки ---
    for line in read_lines(os.path.join(ROOT, "sources", "scam-domains.txt")):
        d = extract_host(line)
        if d:
            domains.add(d)
    for line in read_lines(os.path.join(ROOT, "sources", "scam-emails.txt")):
        e = line.strip().lower()
        if "@" in e and DOMAIN_RE.match(e.split("@", 1)[1]):
            emails.add(e)
    for line in read_lines(os.path.join(ROOT, "sources", "scam-subjects.txt")):
        subjects.add(line.strip())
    for line in read_lines(os.path.join(ROOT, "sources", "scam-phrases-ru.txt")):
        phrases.add(line.strip())
    for line in read_lines(os.path.join(ROOT, "sources", "threat-ips.txt")):
        ips |= parse_ip_lines(line)

    # --- публичные фиды ---
    feed_domains, feed_urls = [], []
    if not offline:
        for feed in load_feeds():
            name = feed.get("name", "feed")
            if not feed.get("enabled", True):
                stats["sources"].append({"name": name, "enabled": False, "ok": False, "count": 0})
                continue
            url = feed.get("url", "")
            ftype = feed.get("type", "plain-domains")
            limit = int(feed.get("limit", 12000))
            try:
                log(f"  · загрузка {name}: {url}")
                text = fetch(url)
            except Exception as exc:  # noqa: BLE001 - фид может быть недоступен
                log(f"    ! {name}: {exc}")
                stats["sources"].append({"name": name, "enabled": True, "ok": False,
                                         "count": 0, "error": str(exc)[:200], "url": url,
                                         "credit": feed.get("credit", "")})
                continue

            got_d, got_u, got_i = set(), set(), set()
            try:
                if ftype == "ips":
                    got_i = parse_ip_lines(text)
                elif ftype == "urls":
                    for line in text.splitlines():
                        host = extract_host(line)
                        if host:
                            got_u.add(host)
                        if len(got_u) >= limit:
                            break
                else:  # plain-domains | hosts | adblock
                    for line in text.splitlines():
                        host = extract_host(line)
                        if host:
                            got_d.add(host)
                        if len(got_d) >= limit:
                            break
            except Exception as exc:  # noqa: BLE001 - битый фид не должен ломать всю сборку
                log(f"    ! {name}: ошибка разбора: {exc}")
                stats["sources"].append({"name": name, "enabled": True, "ok": False,
                                         "count": 0, "error": "parse: " + str(exc)[:200], "url": url,
                                         "credit": feed.get("credit", "")})
                continue
            got_d = set(list(got_d)[:limit])
            got_u = set(list(got_u)[:limit])
            got_i = set(list(got_i)[:limit])
            feed_domains.extend(sorted(got_d))
            feed_urls.extend(sorted(got_u))
            ips |= got_i
            cnt = len(got_d) + len(got_u) + len(got_i)
            log(f"    + {name}: {cnt} записей")
            stats["sources"].append({"name": name, "enabled": True, "ok": True, "count": cnt,
                                     "url": url, "credit": feed.get("credit", ""),
                                     "domains": len(got_d), "urls": len(got_u), "ips": len(got_i)})

    # --- нормализация и защита от ложных срабатываний ---
    domains |= set(feed_domains)
    urls |= set(feed_urls)

    def allowed(d):
        if d in allow:
            return True
        parts = d.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in allow:
                return True
        return False

    domains = sorted(d for d in domains if d and not allowed(d))
    urls = sorted(u for u in urls if u and not allowed(u) and u not in set(domains))
    emails = sorted(e for e in emails if e and not allowed(e.split("@", 1)[1]))
    subjects = sorted({s for s in subjects if s and len(s) <= 160})
    phrases = sorted({p for p in phrases if p and len(p) <= 120})
    ips = sorted(ips)

    domains = domains[:MAX_DOMAINS]
    urls = urls[:MAX_URLS]
    emails = emails[:MAX_EMAILS]
    ips = ips[:MAX_IPS]
    subjects = subjects[:MAX_SUBJECTS]
    phrases = phrases[:MAX_PHRASES]

    # --- запись списков ---
    def write_list(name, items):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(f"# KCM AntiSpam DB — {name}\n")
            fh.write(f"# generated: {stats['startedAt']}\n")
            fh.write(f"# entries: {len(items)}\n")
            for item in items:
                fh.write(item + "\n")
        return path

    written = {}
    for name, items in (
        ("spam-domains.txt", domains),
        ("spam-emails.txt", emails),
        ("scam-subjects.txt", subjects),
        ("scam-phrases-ru.txt", phrases),
        ("threat-ips.txt", ips),
        ("allowlist.txt", sorted(allow)),
    ):
        written[name] = write_list(name, items)

    # --- генерация SpamAssassin-правил для Kerio ---
    version = datetime.now(timezone.utc).strftime("%Y.%m.%d-%H%M")
    cf = render_cf(version, domains, emails, urls, ips, subjects, phrases, sorted(allow))
    cf_path = os.path.join(out_dir, "kerio-antispam.cf")
    with open(cf_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(cf)
    written["kerio-antispam.cf"] = cf_path

    # --- manifest ---
    sha = {}
    sizes = {}
    for name, path in written.items():
        with open(path, "rb") as fh:
            data = fh.read()
        sha[name] = hashlib.sha256(data).hexdigest()
        sizes[name] = len(data)

    manifest = {
        "schema": 1,
        "version": version,
        "generatedAt": stats["startedAt"],
        "minClientVersion": "4.4",
        "counts": {
            "domains": len(domains),
            "emails": len(emails),
            "urls": len(urls),
            "ips": len(ips),
            "subjects": len(subjects),
            "phrases": len(phrases),
            "allowlist": len(allow),
        },
        "files": sorted(written.keys()),
        "sha256": sha,
        "sizes": sizes,
        "ruleFile": "kerio-antispam.cf",
        "sources": stats["sources"],
        "credits": sorted({s.get("credit", "") for s in stats["sources"] if s.get("credit")}),
        "license": "Данные: см. credits. Код сборщика: MIT.",
    }
    # --- release notes (используются GitHub Release) ---
    notes = []
    notes.append(f"# Антиспам-база KCM {version}")
    notes.append("")
    notes.append(f"Сгенерирована: {stats['startedAt']}")
    notes.append("")
    notes.append("| Группа правил | Записей | Очки SpamAssassin |")
    notes.append("|---|---:|---|")
    notes.append(f"| Домены отправителей | {len(domains):,} | +3.2 |".replace(",", " "))
    notes.append(f"| Адреса отправителей | {len(emails):,} | +4.5 |".replace(",", " "))
    notes.append(f"| Мотивы в теме письма | {len(subjects):,} | +1.8 |".replace(",", " "))
    notes.append(f"| Фразы мошеннических писем | {len(phrases):,} | +1.5 |".replace(",", " "))
    notes.append(f"| Домены фишинговых ссылок | {len(urls):,} | +2.5 |".replace(",", " "))
    notes.append(f"| IP/CIDR источников | {len(ips):,} | +3.0 |".replace(",", " "))
    notes.append(f"| Белый список | {len(allow):,} | −6.0 |".replace(",", " "))
    notes.append("")
    notes.append("## Файлы")
    notes.append("")
    notes.append("- `kerio-antispam.cf` — готовые правила SpamAssassin для Kerio Connect")
    notes.append("- `spam-domains.txt`, `spam-emails.txt`, `scam-subjects.txt`, `scam-phrases-ru.txt`, `threat-ips.txt`, `allowlist.txt` — исходные списки")
    notes.append("- `manifest.json` — версия, размеры и SHA-256 каждого файла")
    notes.append("")
    notes.append("## Установка")
    notes.append("")
    notes.append("1. В KerioCertManager откройте вкладку «🛡️ Антиспам-база KCM (GitHub)» и нажмите «Установить / Обновить базу в Kerio».")
    notes.append("2. Либо вручную: скопируйте `kerio-antispam.cf` в `<Kerio>\\plugins\\spamassassin\\rules\\` и перезапустите службу KerioMailServer.")
    notes.append("")
    notes.append("## Источники")
    notes.append("")
    for src in stats["sources"]:
        if src.get("ok"):
            notes.append(f"- {src['name']}: {src['count']} записей ({src.get('credit', '')})")
        elif src.get("enabled"):
            notes.append(f"- {src['name']}: недоступен ({src.get('error', '')[:120]})")
    notes.append("")
    notes.append("_Данные предоставляются «как есть». База не заменяет антивирус и не фильтрует легитимные рассылки по политическим/коммерческим признакам._")
    with open(os.path.join(out_dir, "RELEASE_NOTES.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(notes))

    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
    stats["durationMs"] = int((time.time() - started) * 1000)
    stats["counts"] = manifest["counts"]
    with open(os.path.join(out_dir, "stats.json"), "w", encoding="utf-8") as fh:
        json.dump(stats, fh, ensure_ascii=False, indent=2)

    log("")
    log(f"✅ Готово за {stats['durationMs']} мс → {out_dir}")
    log(f"   домены: {len(domains)}, URL-домены: {len(urls)}, письма: {len(emails)}, "
        f"IP/CIDR: {len(ips)}, темы: {len(subjects)}, фразы: {len(phrases)}")
    log(f"   правила: {sizes['kerio-antispam.cf']} байт, версия {version}")
    return 0


def esc(text):
    """Экранирование для регулярных выражений SpamAssassin."""
    out = []
    for ch in text:
        if ch in r"\.^$|?*+()[]{}":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def render_cf(version, domains, emails, urls, ips, subjects, phrases, allow):
    lines = [
        "# ============================================================================",
        "# KCM AntiSpam DB for Kerio Connect",
        f"# Версия базы: {version}",
        f"# Сгенерировано: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "# Установлено программой KerioCertManager (Zakharevich Igor, ziv@csl.by)",
        "# Удалить базу: удалите этот файл из MailServer/plugins/spamassassin/rules/",
        "# ============================================================================",
        "",
        "# --- Домены отправителей из базы спама/фишинга (score 3.2) ---",
    ]
    idx = 0
    for part in chunks(domains, CHUNK_DOMAINS):
        idx += 1
        alt = "|".join(esc(d) for d in part)
        name = f"KCM_SPAM_FROM_DOMAIN_{idx:03d}"
        lines.append(f"header   {name}   From =~ /@(?:{alt})(?:[>\\s,]|$)/i")
        lines.append(f"describe {name}   Отправитель из антиспам-базы KCM (домен {part[0]}…{part[-1]})")
        lines.append(f"score    {name}   3.2")
    lines.append("")

    if emails:
        lines.append("# --- Конкретные адреса отправителей (score 4.5) ---")
        idx = 0
        for part in chunks(emails, CHUNK_EMAILS):
            idx += 1
            alt = "|".join(esc(e) for e in part)
            name = f"KCM_SPAM_FROM_EMAIL_{idx:03d}"
            lines.append(f"header   {name}   From =~ /(?:{alt})/i")
            lines.append(f"describe {name}   Адрес отправителя из антиспам-базы KCM")
            lines.append(f"score    {name}   4.5")
        lines.append("")

    if subjects:
        lines.append("# --- Шаблоны мошеннических тем писем (score 1.8) ---")
        idx = 0
        for part in chunks(subjects, CHUNK_SUBJECTS):
            idx += 1
            alt = "|".join(esc(s) for s in part)
            name = f"KCM_SCAM_SUBJECT_{idx:03d}"
            lines.append(f"header   {name}   Subject =~ /({alt})/i")
            lines.append(f"describe {name}   Типовая тема спам/фишинг-письма (KCM)")
            lines.append(f"score    {name}   1.8")
        lines.append("")

    if phrases:
        lines.append("# --- Фразы в теле письма (score 1.5) ---")
        idx = 0
        for part in chunks(phrases, CHUNK_PHRASES):
            idx += 1
            alt = "|".join(esc(p) for p in part)
            name = f"KCM_SCAM_PHRASE_{idx:03d}"
            lines.append(f"body     {name}   /({alt})/i")
            lines.append(f"describe {name}   Фраза мошеннического письма (KCM)")
            lines.append(f"score    {name}   1.5")
        lines.append("")

    if urls:
        lines.append("# --- Домены вредоносных/фишинговых ссылок в письме (score 2.5) ---")
        idx = 0
        for part in chunks(urls, CHUNK_URLS):
            idx += 1
            alt = "|".join(esc(u) for u in part)
            name = f"KCM_PHISH_URL_{idx:03d}"
            lines.append(f"uri      {name}   /(?i)(?:{alt})/")
            lines.append(f"describe {name}   Ссылка на домен из фишинг-базы KCM")
            lines.append(f"score    {name}   2.5")
            lines.append(f"tflags   {name}   net")
        lines.append("")

    ip_rules = []
    for cidr in ips:
        rx = cidr_to_regex(cidr)
        if rx:
            ip_rules.append(rx)
    if ip_rules:
        lines.append("# --- IP-адреса источников спама в заголовках Received (score 3.0) ---")
        idx = 0
        for part in chunks(ip_rules, CHUNK_IPS):
            idx += 1
            alt = "|".join(part)
            name = f"KCM_SPAM_SRC_IP_{idx:03d}"
            lines.append(f"header   {name}   Received =~ /\\[(?:{alt})/")
            lines.append(f"describe {name}   IP отправителя из антиспам-базы KCM")
            lines.append(f"score    {name}   3.0")
        lines.append("")

    if allow:
        lines.append("# --- Белый список: снижаем ложные срабатывания (score -6.0) ---")
        idx = 0
        for part in chunks(allow, CHUNK_ALLOW):
            idx += 1
            alt = "|".join(esc(d) for d in part)
            name = f"KCM_ALLOW_FROM_{idx:03d}"
            lines.append(f"header   {name}   From =~ /@(?:{alt})(?:[>\\s,]|$)/i")
            lines.append(f"describe {name}   Доверенный отправитель (белый список KCM)")
            lines.append(f"score    {name}   -6.0")
        lines.append("")

    lines.append("# Статистика базы:")
    lines.append(f"#   домены={len(domains)} emails={len(emails)} urls={len(urls)} "
                 f"ips={len(ips)} subjects={len(subjects)} phrases={len(phrases)} allow={len(allow)}")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="не загружать внешние фиды")
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    args = ap.parse_args()
    sys.exit(build(offline=args.offline, out_dir=args.out))
