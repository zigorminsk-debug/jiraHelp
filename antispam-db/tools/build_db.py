#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KCM AntiSpam DB builder.

Собирает антиспам-базу из:
  1) курируемых источников  ./sources/*.txt
  2) публичных фидов        ./feeds.json

Результат (./dist):
  manifest.json          — версия, дата, количество записей, SHA-256 файлов
  spam-domains.txt       — домены отправителей (правила From:)
  phishing-links.txt     — домены ссылок/лендингов (правила uri:)
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
import gzip
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
URL_RE = re.compile(r"^(?:https?|ftp)://([^/:?#\s]+)", re.I)
HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-z0-9._-]+)$", re.I)
ADBLOCK_RE = re.compile(r"^\|\|([a-z0-9._-]+)\^?$", re.I)
BARE_IPV4_PREFIX_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)(?=[a-z0-9])", re.I)
HTML_MARKERS = (
    "<!doctype html",
    "<html",
    "just a moment",
    "one moment, please",
    "checking your browser",
    "cf-chl",
    "enable javascript and cookies",
    "attention required! | cloudflare",
    "<title>access denied",
    "<title>403 forbidden",
)

# Жёсткие лимиты, чтобы .cf оставался быстрым для SpamAssassin
MAX_DOMAINS = 12000   # домены отправителей (правило From:)
MAX_LINKS = 30000     # домены ссылок (правило uri:)
MAX_EMAILS = 4000
MAX_IPS = 12000
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

# Публичные CDN/хостинги: сам домен блокировать нельзя (сломаем половину интернета),
# но конкретные поддомены (evil.000webhostapp.com) — можно и нужно.
INFRA_DENY_EXACT = """
000webhostapp.com weebly.com weeblysite.com godaddysites.com webflow.io
pages.dev workers.dev vercel.app netlify.app github.io repl.co
appspot.com azurewebsites.net cloudfunctions.net web.core.windows.net
myportfolio.com webnode.com wixsite.com myshopify.com duckdns.org hopto.org
blogspot.com wordpress.com bluehost.me mybluehost.me 125mb.com atwebpages.com
wcomhost.com byethost7.com webcindario.com 16mb.com
amazonaws.com cloudfront.net firebaseapp.com
""".split()

CHUNK_SENDERS = 50
CHUNK_LINKS = 40
CHUNK_EMAILS = 40
CHUNK_IPS = 60
CHUNK_SUBJECTS = 25
CHUNK_PHRASES = 25
CHUNK_ALLOW = 60

DEFAULT_PRIORITY = 100
TYPE_PRIORITY = {"urls": 30, "plain-domains": 30, "hosts": 30, "adblock": 30, "ips": 20}


class FeedError(Exception):
    """Ошибка загрузки/разбора одного фида (не должна ломать всю сборку)."""


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
    if not DOMAIN_RE.match(d):
        return ""
    return d


def extract_host(line):
    """Достаёт домен из строки любого поддерживаемого формата."""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith(";") or line.startswith("!"):
        return ""
    # Некоторые фиды клеят hosts-префикс прямо к домену: 0.0.0.0evil.com
    line = BARE_IPV4_PREFIX_RE.sub("", line)
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


def parse_ip_lines(text):
    """Парсит IP/CIDR, отбрасывая приватные, служебные и слишком широкие сети.

    В список попадают все корректные IPv4-сети (>= /12); правила SpamAssassin
    строятся только для октетных масок /16, /24, /32 — см. cidr_to_regex().
    """
    out, skipped = set(), 0
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
        if net.prefixlen < 12:
            skipped += 1
            continue
        out.add(str(net))
    return out, skipped


def looks_like_challenge(text):
    head = text[:4096].lower()
    if not head.strip():
        return "пустой ответ"
    for marker in HTML_MARKERS:
        if marker in head:
            return "HTML/анти-бот страница (Cloudflare или WAF)"
    return ""


def fetch(url, timeout=60, limit=64 * 1024 * 1024, headers=None):
    req = urllib.request.Request(url, headers={
        "User-Agent": "KCM-AntiSpam-DB/1.1 (+https://github.com/zigorminsk-debug/jiraHelp)",
        "Accept": "text/plain,text/csv,application/json,*/*;q=0.8",
        "Accept-Encoding": "gzip",
        "Cache-Control": "no-cache",
        **(headers or {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(limit)
            encoding = (resp.headers.get("Content-Encoding") or "").lower()
    except urllib.error.HTTPError as exc:
        hint = ""
        if exc.code in (401, 403):
            hint = " (нужен Auth-Key/онлайн-регистрация)"
        elif exc.code == 410:
            hint = " (публичная выгрузка закрыта владельцем фида)"
        raise FeedError(f"HTTP {exc.code}{hint}") from exc
    except Exception as exc:  # noqa: BLE001 - сетевые ошибки не должны ломать сборку
        raise FeedError(str(exc)[:200]) from exc

    if encoding == "gzip" or raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except Exception as exc:  # noqa: BLE001
            raise FeedError(f"не удалось распаковать gzip: {exc}") from exc

    text = raw.decode("utf-8", errors="replace")
    problem = looks_like_challenge(text)
    if problem:
        raise FeedError(problem)
    return text


def load_feeds():
    path = os.path.join(ROOT, "feeds.json")
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh).get("feeds", [])


def parse_feed_text(text, ftype, limit):
    """Возвращает (домены, ip, сколько сетей отброшено как слишком широкие)."""
    domains, ips = set(), set()
    if ftype == "ips":
        ips, skipped = parse_ip_lines(text)
        return set(), ips, skipped
    if ftype == "csv-urls":
        for line in text.splitlines():
            for cell in line.split(","):
                host = extract_host(cell.strip().strip('"'))
                if host:
                    domains.add(host)
                if len(domains) >= limit:
                    return domains, set(), 0
        return domains, set(), 0
    if ftype == "json-urls":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FeedError(f"некорректный JSON: {exc}") from exc
        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            items = payload.get("urls") or payload.get("data") or []
        else:
            items = []
        for item in items:
            if isinstance(item, dict):
                item = item.get("url") or item.get("domain") or item.get("host") or ""
            host = extract_host(str(item))
            if host:
                domains.add(host)
            if len(domains) >= limit:
                break
        return domains, set(), 0
    # plain-domains | hosts | adblock | urls
    for line in text.splitlines():
        host = extract_host(line)
        if host:
            domains.add(host)
        if len(domains) >= limit:
            break
    return domains, set(), 0


def is_subdomain_of(host, parents):
    host = host.lower()
    if host in parents:
        return True
    parts = host.split(".")
    for i in range(1, len(parts) - 1):
        if ".".join(parts[i:]) in parents:
            return True
    return False


def allowed(host, allow):
    """Полный запрет: сам домен или любой его поддомен (для отправителей и доверенных зон)."""
    return is_subdomain_of(host, allow)


def allowed_link(host, trusted, infra):
    """Для ссылок: доверенные зоны режем целиком, а инфраструктурные — только точно."""
    return is_subdomain_of(host, trusted) or host.lower() in infra


def pick_by_priority(prio_map, limit):
    """Обрезает список по лимиту, сохраняя самые приоритетные источники."""
    ordered = sorted(prio_map.items(), key=lambda kv: (kv[1], kv[0]))
    if len(ordered) > limit:
        ordered = ordered[:limit]
    return sorted(name for name, _ in ordered)


def build(offline=False, out_dir=None):
    started = time.time()
    out_dir = out_dir or os.path.join(ROOT, "dist")
    os.makedirs(out_dir, exist_ok=True)

    senders, links = {}, {}
    emails, subjects, phrases, ips, allow = set(), set(), set(), set(), set()
    stats = {"sources": [], "startedAt": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    ip_skipped = 0

    # --- белый список ---
    for base in SAFETY_ALLOW:
        allow.add(base)
    for line in read_lines(os.path.join(ROOT, "sources", "allowlist.txt")):
        d = normalize_domain(line)
        if d:
            allow.add(d)
    allow.discard("")

    # --- курируемые списки ---
    for line in read_lines(os.path.join(ROOT, "sources", "scam-domains.txt")):
        d = extract_host(line)
        if d:
            senders.setdefault(d, 0)
    for line in read_lines(os.path.join(ROOT, "sources", "phishing-links.txt")):
        d = extract_host(line)
        if d:
            links.setdefault(d, 0)
    for line in read_lines(os.path.join(ROOT, "sources", "scam-emails.txt")):
        e = line.strip().lower()
        if "@" in e and DOMAIN_RE.match(e.split("@", 1)[1]):
            emails.add(e)
    for line in read_lines(os.path.join(ROOT, "sources", "scam-subjects.txt")):
        subjects.add(line.strip())
    for line in read_lines(os.path.join(ROOT, "sources", "scam-phrases-ru.txt")):
        phrases.add(line.strip())
    curated_ips, skipped = parse_ip_lines("\n".join(read_lines(os.path.join(ROOT, "sources", "threat-ips.txt"))))
    ips |= curated_ips
    ip_skipped += skipped

    # --- публичные фиды ---
    feeds = [] if offline else load_feeds()
    for feed in feeds:
        name = feed.get("name", "feed")
        url = feed.get("url", "")
        ftype = feed.get("type", "plain-domains")
        limit = int(feed.get("limit", 12000))
        role = feed.get("role") or ("ips" if ftype == "ips" else "links")
        priority = int(feed.get("priority", TYPE_PRIORITY.get(ftype, DEFAULT_PRIORITY)))
        credit = feed.get("credit", "")
        meta = {"name": name, "url": url, "credit": credit, "role": role,
                "priority": priority, "license": feed.get("license", "")}

        if not feed.get("enabled", True):
            meta.update({"enabled": False, "ok": False, "count": 0,
                         "error": feed.get("note", "отключён в feeds.json")})
            stats["sources"].append(meta)
            log(f"  – {name}: отключён ({meta['error']})")
            continue

        auth_env = feed.get("auth_env", "")
        headers = {}
        if auth_env:
            key = os.environ.get(auth_env, "").strip()
            if not key:
                meta.update({"enabled": True, "ok": False, "skipped": True, "count": 0,
                             "error": f"нужен ключ {auth_env} (бесплатный, некоммерческое использование)"})
                stats["sources"].append(meta)
                log(f"  – {name}: пропущен, не задан {auth_env}")
                continue
            for hname, hvalue in (feed.get("headers") or {}).items():
                headers[hname] = str(hvalue).replace("{key}", key)
            url = url.replace("{key}", key)

        try:
            log(f"  · загрузка {name}: {feed.get('url')}")
            text = fetch(url, headers=headers)
            got, got_ips, got_skipped = parse_feed_text(text, ftype, limit)
            got = {d for d in got if not allowed_link(d, allow, INFRA_DENY_EXACT)}
            got = set(list(got)[:limit])
            ip_skipped += got_skipped
        except FeedError as exc:
            meta.update({"enabled": True, "ok": False, "count": 0, "error": str(exc)[:220]})
            stats["sources"].append(meta)
            log(f"    ! {name}: {exc}")
            continue

        if not got and not got_ips:
            meta.update({"enabled": True, "ok": False, "count": 0,
                         "error": "0 записей после разбора — формат не распознан"})
            stats["sources"].append(meta)
            log(f"    ! {name}: 0 записей (формат не распознан)")
            continue

        if role == "senders":
            for d in got:
                senders.setdefault(d, priority)
        elif role == "ips":
            ips |= got_ips
        else:
            for d in got:
                links.setdefault(d, priority)
        meta.update({"enabled": True, "ok": True,
                     "count": len(got) + len(got_ips),
                     "domains": len(got) if role != "ips" else 0,
                     "ips": len(got_ips)})
        stats["sources"].append(meta)
        log(f"    + {name}: {meta['count']} записей ({role})")

    # --- нормализация и защита от ложных срабатываний ---
    senders = {d: p for d, p in senders.items() if d and not allowed(d, allow)}
    links = {d: p for d, p in links.items()
             if d and not allowed_link(d, allow, INFRA_DENY_EXACT) and d not in senders}

    sender_list = pick_by_priority(senders, MAX_DOMAINS)
    link_list = pick_by_priority(links, MAX_LINKS)
    email_list = sorted(e for e in emails if e and not allowed(e.split("@", 1)[1], allow))[:MAX_EMAILS]
    subject_list = sorted({s for s in subjects if s and len(s) <= 160})[:MAX_SUBJECTS]
    phrase_list = sorted({p for p in phrases if p and len(p) <= 120})[:MAX_PHRASES]
    ip_list = sorted(ips)[:MAX_IPS]

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
        ("spam-domains.txt", sender_list),
        ("phishing-links.txt", link_list),
        ("spam-emails.txt", email_list),
        ("scam-subjects.txt", subject_list),
        ("scam-phrases-ru.txt", phrase_list),
        ("threat-ips.txt", ip_list),
        ("allowlist.txt", sorted(allow)),
    ):
        written[name] = write_list(name, items)

    # --- генерация SpamAssassin-правил для Kerio ---
    version = datetime.now(timezone.utc).strftime("%Y.%m.%d-%H%M")
    cf = render_cf(version, sender_list, link_list, email_list, ip_list,
                   subject_list, phrase_list, sorted(allow))
    cf_path = os.path.join(out_dir, "kerio-antispam.cf")
    with open(cf_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(cf)
    written["kerio-antispam.cf"] = cf_path

    sha, sizes = {}, {}
    for name, path in written.items():
        with open(path, "rb") as fh:
            data = fh.read()
        sha[name] = hashlib.sha256(data).hexdigest()
        sizes[name] = len(data)

    ok_sources = [s for s in stats["sources"] if s.get("ok")]
    failed_sources = [s for s in stats["sources"] if s.get("enabled") and not s.get("ok")]
    manifest = {
        "schema": 2,
        "version": version,
        "generatedAt": stats["startedAt"],
        "minClientVersion": "4.4",
        "counts": {
            "domains": len(sender_list),
            "urls": len(link_list),
            "emails": len(email_list),
            "ips": len(ip_list),
            "subjects": len(subject_list),
            "phrases": len(phrase_list),
            "allowlist": len(allow),
        },
        "files": sorted(written.keys()),
        "sha256": sha,
        "sizes": sizes,
        "ruleFile": "kerio-antispam.cf",
        "sources": stats["sources"],
        "sourcesOk": len(ok_sources),
        "sourcesFailed": len(failed_sources),
        "credits": sorted({s.get("credit", "") for s in stats["sources"] if s.get("credit")}),
        "license": "Данные: см. credits. Код сборщика: MIT.",
    }

    notes = []
    notes.append(f"# Антиспам-база KCM {version}")
    notes.append("")
    notes.append(f"Сгенерирована: {stats['startedAt']}")
    notes.append("")
    notes.append("| Группа правил | Записей | Очки SpamAssassin |")
    notes.append("|---|---:|---|")
    notes.append(f"| Домены отправителей | {len(sender_list)} | +3.2 |")
    notes.append(f"| Адреса отправителей | {len(email_list)} | +4.5 |")
    notes.append(f"| Мотивы в теме письма | {len(subject_list)} | +1.8 |")
    notes.append(f"| Фразы мошеннических писем | {len(phrase_list)} | +1.5 |")
    notes.append(f"| Домены фишинговых ссылок | {len(link_list)} | +2.5 |")
    notes.append(f"| IP/CIDR источников | {len(ip_list)} | +3.0 |")
    notes.append(f"| Белый список | {len(allow)} | −6.0 |")
    notes.append("")
    notes.append("## Источники")
    notes.append("")
    for src in stats["sources"]:
        if src.get("ok"):
            notes.append(f"- ✅ {src['name']}: {src['count']} записей ({src.get('credit', '')})")
        elif src.get("enabled"):
            notes.append(f"- ⚠️ {src['name']}: {src.get('error', 'недоступен')}")
        else:
            notes.append(f"- ⏸ {src['name']}: отключён ({src.get('error', '')})")
    notes.append("")
    notes.append("## Файлы")
    notes.append("")
    notes.append("- `kerio-antispam.cf` — готовые правила SpamAssassin для Kerio Connect")
    notes.append("- `spam-domains.txt`, `phishing-links.txt`, `spam-emails.txt`, `scam-subjects.txt`, `scam-phrases-ru.txt`, `threat-ips.txt`, `allowlist.txt` — исходные списки")
    notes.append("- `manifest.json` — версия, размеры и SHA-256 каждого файла")
    notes.append("")
    notes.append("## Установка")
    notes.append("")
    notes.append("1. В KerioCertManager откройте вкладку «🛡️ Антиспам-база KCM (GitHub)» и нажмите «Установить / Обновить базу в Kerio».")
    notes.append("2. Либо вручную: скопируйте `kerio-antispam.cf` в `<Kerio>\\plugins\\spamassassin\\rules\\` и перезапустите службу KerioMailServer.")
    notes.append("")
    notes.append("_Данные предоставляются «как есть». База не заменяет антивирус и не фильтрует легитимные рассылки по политическим/коммерческим признакам._")
    with open(os.path.join(out_dir, "RELEASE_NOTES.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(notes))

    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)

    stats["durationMs"] = int((time.time() - started) * 1000)
    stats["counts"] = manifest["counts"]
    stats["sourcesOk"] = len(ok_sources)
    stats["sourcesFailed"] = len(failed_sources)
    stats["ipsSkippedTooWide"] = ip_skipped
    stats["ipsWithoutRegexRule"] = sum(1 for c in ip_list if not cidr_to_regex(c))
    with open(os.path.join(out_dir, "stats.json"), "w", encoding="utf-8") as fh:
        json.dump(stats, fh, ensure_ascii=False, indent=2)

    log("")
    log(f"✅ Готово за {stats['durationMs']} мс → {out_dir}")
    log(f"   отправители: {len(sender_list)}, ссылки: {len(link_list)}, письма: {len(email_list)}, "
        f"IP/CIDR: {len(ip_list)}, темы: {len(subject_list)}, фразы: {len(phrase_list)}")
    log(f"   источников: {len(ok_sources)} ок, {len(failed_sources)} недоступно; "
        f"правила: {sizes['kerio-antispam.cf']} байт, версия {version}")
    if failed_sources:
        for src in failed_sources:
            log(f"     ! {src['name']}: {src.get('error', '')}")
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


def cidr_to_regex(cidr):
    """Превращает IPv4 CIDR в префиксный regex для заголовка Received.

    Поддерживаются только октетно-выровненные маски (/16, /24, /32): для них
    регулярное выражение остаётся точным и не даёт ложных срабатываний.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4 or net.prefixlen not in (16, 24, 32):
        return ""
    octets = str(net.network_address).split(".")[: net.prefixlen // 8]
    if not octets:
        return ""
    return r"\.".join(octets) + ("" if net.prefixlen == 32 else r"\.")


def render_cf(version, senders, links, emails, ips, subjects, phrases, allow):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# ============================================================================",
        "# KCM AntiSpam DB for Kerio Connect",
        f"# Версия базы: {version}",
        f"# Сгенерировано: {stamp}",
        "# Установлено программой KerioCertManager (Zakharevich Igor, ziv@csl.by)",
        "# Удалить базу: удалите этот файл из MailServer/plugins/spamassassin/rules/",
        "# ============================================================================",
        "",
    ]

    if senders:
        lines.append("# --- Домены отправителей из базы спама/фишинга (score 3.2) ---")
        index = 0
        for part in chunks(senders, CHUNK_SENDERS):
            index += 1
            alt = "|".join(esc(d) for d in part)
            name = f"KCM_SPAM_FROM_DOMAIN_{index:03d}"
            lines.append(f"header   {name}   From =~ /@(?:{alt})(?:[>\\s,]|$)/i")
            lines.append(f"describe {name}   Отправитель из антиспам-базы KCM (домен {part[0]}…{part[-1]})")
            lines.append(f"score    {name}   3.2")
        lines.append("")

    if emails:
        lines.append("# --- Конкретные адреса отправителей (score 4.5) ---")
        index = 0
        for part in chunks(emails, CHUNK_EMAILS):
            index += 1
            alt = "|".join(esc(e) for e in part)
            name = f"KCM_SPAM_FROM_EMAIL_{index:03d}"
            lines.append(f"header   {name}   From =~ /(?:{alt})/i")
            lines.append(f"describe {name}   Адрес отправителя из антиспам-базы KCM")
            lines.append(f"score    {name}   4.5")
        lines.append("")

    if subjects:
        lines.append("# --- Шаблоны мошеннических тем писем (score 1.8) ---")
        index = 0
        for part in chunks(subjects, CHUNK_SUBJECTS):
            index += 1
            alt = "|".join(esc(s) for s in part)
            name = f"KCM_SCAM_SUBJECT_{index:03d}"
            lines.append(f"header   {name}   Subject =~ /({alt})/i")
            lines.append(f"describe {name}   Типовая тема спам/фишинг-письма (KCM)")
            lines.append(f"score    {name}   1.8")
        lines.append("")

    if phrases:
        lines.append("# --- Фразы в теле письма (score 1.5) ---")
        index = 0
        for part in chunks(phrases, CHUNK_PHRASES):
            index += 1
            alt = "|".join(esc(p) for p in part)
            name = f"KCM_SCAM_PHRASE_{index:03d}"
            lines.append(f"body     {name}   /({alt})/i")
            lines.append(f"describe {name}   Фраза мошеннического письма (KCM)")
            lines.append(f"score    {name}   1.5")
        lines.append("")

    if links:
        lines.append("# --- Домены вредоносных/фишинговых ссылок в письме (score 2.5) ---")
        index = 0
        for part in chunks(links, CHUNK_LINKS):
            index += 1
            alt = "|".join(esc(u) for u in part)
            name = f"KCM_PHISH_URL_{index:03d}"
            lines.append(f"uri      {name}   /(?i)(?:{alt})/")
            lines.append(f"describe {name}   Ссылка на домен из фишинг-базы KCM")
            lines.append(f"score    {name}   2.5")
            lines.append(f"tflags   {name}   net")
        lines.append("")

    ip_rules = [rx for rx in (cidr_to_regex(cidr) for cidr in ips) if rx]
    if ip_rules:
        lines.append("# --- IP-адреса источников спама в заголовках Received (score 3.0) ---")
        index = 0
        for part in chunks(ip_rules, CHUNK_IPS):
            index += 1
            alt = "|".join(part)
            name = f"KCM_SPAM_SRC_IP_{index:03d}"
            lines.append(f"header   {name}   Received =~ /\\[(?:{alt})/")
            lines.append(f"describe {name}   IP отправителя из антиспам-базы KCM")
            lines.append(f"score    {name}   3.0")
        lines.append("")

    if allow:
        lines.append("# --- Белый список: снижаем ложные срабатывания (score -6.0) ---")
        index = 0
        for part in chunks(allow, CHUNK_ALLOW):
            index += 1
            alt = "|".join(esc(d) for d in part)
            name = f"KCM_ALLOW_FROM_{index:03d}"
            lines.append(f"header   {name}   From =~ /@(?:{alt})(?:[>\\s,]|$)/i")
            lines.append(f"describe {name}   Доверенный отправитель (белый список KCM)")
            lines.append(f"score    {name}   -6.0")
        lines.append("")

    lines.append("# Статистика базы:")
    lines.append(f"#   отправители={len(senders)} ссылки={len(links)} emails={len(emails)} "
                 f"ips={len(ips)} subjects={len(subjects)} phrases={len(phrases)} allow={len(allow)}")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="не загружать внешние фиды")
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    args = ap.parse_args()
    sys.exit(build(offline=args.offline, out_dir=args.out))
