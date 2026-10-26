package by.csl.kcm;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Автономные проверки с телефона — без компьютера и без программы на ПК.
 *
 * Проверяется то, что чаще всего ломает почту и сайт:
 *   • SSL-сертификат домена (срок, издатель, имена в SAN);
 *   • DNS: A/AAAA, MX, SPF и DMARC;
 *   • доступность почтовых портов и админки Kerio;
 *   • попадание IP и домена в спам-базы (RBL/DBL).
 *
 * DNS-записи MX/TXT читаются через DNS-over-HTTPS (Cloudflare). Это обычный
 * HTTPS-запрос, он проходит там, где прямой UDP-DNS к 53 порту заблокирован
 * мобильным оператором. Если интернет недоступен — проверка честно об этом
 * скажет, а не покажет «записи не найдены».
 */
final class Checks {

    /** Одна строка отчёта. */
    static final class Line {
        final String status; // ok | warn | fail | info
        final String title;
        final String detail;

        Line(String status, String title, String detail) {
            this.status = status;
            this.title = title;
            this.detail = detail == null ? "" : detail;
        }
    }

    /** Группа строк: «SSL», «DNS», «Порты», «Спам-базы». */
    static final class Section {
        final String title;
        final List<Line> lines = new ArrayList<Line>();

        Section(String title) {
            this.title = title;
        }

        void add(String status, String title, String detail) {
            lines.add(new Line(status, title, detail));
        }
    }

    /**
     * Контекст приложения — нужен только системному резолверу Android
     * (DnsSystem). Ставится один раз из MainActivity, дальше проверки
     * работают в фоновых потоках без Activity.
     */
    private static volatile Context appContext;

    private Checks() {
    }

    static void init(Context context) {
        if (context == null) {
            return;
        }
        Context app = context.getApplicationContext();
        appContext = app != null ? app : context;
    }

    private static final int CONNECT_TIMEOUT_MS = 5000;

    // ------------------------------------------------------------------
    // Общий прогон
    // ------------------------------------------------------------------

    static List<Section> runAll(String rawDomain) {
        String domain = normalizeDomain(rawDomain);
        List<Section> out = new ArrayList<Section>();
        if (domain.isEmpty()) {
            Section s = new Section("Ошибка");
            s.add("fail", "Не указан домен", "Введите домен, например mail.example.com");
            out.add(s);
            return out;
        }

        out.add(checkTls(domain));
        out.add(checkDns(domain));

        String ip = null;
        try {
            ip = InetAddress.getByName(domain).getHostAddress();
        } catch (Exception ignored) {
            // уже попадёт в отчёт DNS-секции
        }
        if (ip != null) {
            out.add(checkPorts(ip, domain));
            out.add(checkRbl(domain, ip));
        } else {
            Section s = new Section("Порты и спам-базы");
            s.add("warn", "Проверка пропущена", "IP-адрес домена не определён — порты и RBL проверить нельзя.");
            out.add(s);
        }
        return out;
    }

    static String normalizeDomain(String raw) {
        String d = raw == null ? "" : raw.trim();
        d = d.replace("https://", "").replace("http://", "");
        int slash = d.indexOf('/');
        if (slash >= 0) {
            d = d.substring(0, slash);
        }
        int at = d.indexOf('@');
        if (at >= 0) {
            d = d.substring(at + 1);
        }
        int colon = d.indexOf(':');
        if (colon > 0) {
            d = d.substring(0, colon);
        }
        return d.trim().toLowerCase(Locale.ROOT);
    }

    // ------------------------------------------------------------------
    // SSL
    // ------------------------------------------------------------------

    static Section checkTls(String domain) {
        Section s = new Section("SSL-сертификат");
        SSLSocket socket = null;
        try {
            SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
            socket = (SSLSocket) f.createSocket();
            socket.connect(new InetSocketAddress(domain, 443), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(CONNECT_TIMEOUT_MS);
            socket.startHandshake();

            Certificate[] chain = socket.getSession().getPeerCertificates();
            if (chain == null || chain.length == 0) {
                s.add("fail", "Сервер не отдал сертификат", "TLS-соединение установлено, но цепочка пуста.");
                return s;
            }
            X509Certificate leaf = (X509Certificate) chain[0];
            Date notAfter = leaf.getNotAfter();
            long daysLeft = (notAfter.getTime() - System.currentTimeMillis()) / (24L * 3600L * 1000L);
            SimpleDateFormat fmt = new SimpleDateFormat("dd.MM.yyyy", Locale.ROOT);

            String status = daysLeft < 0 ? "fail" : (daysLeft <= 14 ? "warn" : "ok");
            String note = daysLeft < 0
                    ? "СЕРТИФИКАТ ИСТЁК — сайт и почта будут выдавать ошибку"
                    : (daysLeft <= 14 ? "истекает скоро, обновите его" : "действует");
            s.add(status, "Срок действия",
                    "до " + fmt.format(notAfter) + " (осталось " + daysLeft + " дн.) — " + note);

            s.add("info", "Издатель", leaf.getIssuerDN() == null ? "—" : leaf.getIssuerDN().getName());
            s.add("info", "Кому выдан", leaf.getSubjectDN() == null ? "—" : leaf.getSubjectDN().getName());

            String names = sanNames(leaf);
            s.add(names.contains(domain) ? "ok" : "warn", "Имена в сертификате",
                    names.isEmpty() ? "SAN не указан" : names);

            s.add(chain.length > 1 ? "ok" : "warn", "Цепочка",
                    "сертификатов в цепочке: " + chain.length
                            + (chain.length > 1 ? " (промежуточный выдан сервером — хорошо)"
                            : " — почтовые клиенты могут не принять"));

            if (daysLeft >= 0 && daysLeft <= 14) {
                s.add("info", "Что делать", "Выпустите новый сертификат в программе на компьютере "
                        + "или продлите его у удостоверяющего центра.");
            }
            return s;
        } catch (Exception e) {
            s.add("fail", "Не удалось подключиться по TLS",
                    e.getClass().getSimpleName() + ": " + e.getMessage()
                            + "\nПроверьте, что домен указывает на этот сервер и порт 443 открыт.");
            return s;
        } finally {
            closeQuietly(socket);
        }
    }

    private static String sanNames(X509Certificate cert) {
        StringBuilder sb = new StringBuilder();
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> item : sans) {
                    if (item == null || item.size() < 2) {
                        continue;
                    }
                    Object type = item.get(0);
                    Object value = item.get(1);
                    if (type instanceof Integer && ((Integer) type).intValue() == 2 && value != null) {
                        if (sb.length() > 0) {
                            sb.append(", ");
                        }
                        sb.append(value.toString());
                    }
                }
            }
        } catch (Exception ignored) {
            // некоторые сертификаты не отдают SAN — не критично
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // DNS
    // ------------------------------------------------------------------

    static Section checkDns(String domain) {
        Section s = new Section("DNS и почтовые записи");

        String ip = "";
        try {
            InetAddress[] all = InetAddress.getAllByName(domain);
            StringBuilder sb = new StringBuilder();
            for (InetAddress a : all) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(a.getHostAddress());
            }
            ip = sb.toString();
            s.add("ok", "A/AAAA-запись", ip);
        } catch (Exception e) {
            s.add("fail", "Домен не разрешается в IP",
                    "DNS не знает такого имени. Проверьте A-запись у регистратора.");
        }

        JSONArray mx = doh(domain, "MX");
        if (mx == null) {
            s.add("warn", "MX-записи", "не удалось получить (нет интернета или DNS-over-HTTPS заблокирован)");
        } else if (mx.length() == 0) {
            s.add("fail", "MX-записи", "не найдены — почта на этот домен приходить не будет");
        } else {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < mx.length(); i++) {
                JSONObject rec = mx.optJSONObject(i);
                if (rec == null) {
                    continue;
                }
                if (sb.length() > 0) {
                    sb.append("; ");
                }
                sb.append(rec.optString("data", "")).append(" (приоритет ")
                        .append(rec.optInt("priority", 0)).append(")");
            }
            s.add("ok", "MX-записи", sb.toString());
        }

        String spf = firstTxtStartingWith(domain, "v=spf1");
        if (spf == null) {
            s.add("fail", "SPF", "запись v=spf1 не найдена — письма чаще попадают в спам");
        } else {
            boolean hard = spf.contains("-all");
            s.add(hard ? "ok" : "warn", "SPF", spf
                    + (hard ? "" : "\nВ конце записи лучше указать -all (жёсткий запрет подделки)."));
        }

        String dmarc = firstTxtStartingWith("_dmarc." + domain, "v=DMARC1");
        if (dmarc == null) {
            s.add("warn", "DMARC", "записи нет — крупные почтовые сервисы снижают доверие к домену");
        } else {
            s.add("ok", "DMARC", dmarc);
        }

        String dkim = findDkim(domain);
        if (dkim != null) {
            s.add("ok", "DKIM", dkim);
        } else {
            s.add("info", "DKIM", "селектор не угадать без настройки Kerio: посмотрите его в Kerio "
                    + "Configuration → Domains → ваш домен → DKIM.");
        }
        return s;
    }

    private static String findDkim(String domain) {
        String[] selectors = {"default", "mail", "kerio", "dkim", "s1", "selector1", "google"};
        for (String sel : selectors) {
            JSONArray arr = doh(sel + "._domainkey." + domain, "TXT");
            if (arr == null) {
                return null;
            }
            for (int i = 0; i < arr.length(); i++) {
                JSONObject rec = arr.optJSONObject(i);
                String data = rec == null ? "" : rec.optString("data", "");
                if (data.contains("v=DKIM1") || data.contains("p=")) {
                    return "селектор «" + sel + "» найден и опубликован";
                }
            }
        }
        return null;
    }

    private static String firstTxtStartingWith(String name, String prefix) {
        JSONArray arr = doh(name, "TXT");
        if (arr == null) {
            return null;
        }
        for (int i = 0; i < arr.length(); i++) {
            JSONObject rec = arr.optJSONObject(i);
            String data = rec == null ? "" : rec.optString("data", "");
            if (data.startsWith(prefix)) {
                return data;
            }
        }
        return null;
    }

    /**
     * DNS-запрос MX/TXT через DNS-over-HTTPS.
     *
     * Провайдеров два: Cloudflare и Google. У операторов бывает, что один из
     * них недоступен, и тогда весь блок DNS показывал «нет данных» —
     * хотя сеть работает.
     */
    private static JSONArray doh(String name, String type) {
        for (String base : DOH_BASES) {
            HttpURLConnection conn = null;
            try {
                String url = base + "?name=" + URLEncoder.encode(name, "UTF-8") + "&type=" + type;
                conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
                conn.setReadTimeout(CONNECT_TIMEOUT_MS);
                conn.setRequestProperty("Accept", "application/dns-json");
                if (conn.getResponseCode() != 200) {
                    continue;
                }
                JSONObject json = new JSONObject(readAll(conn.getInputStream()));
                JSONArray answers = json.optJSONArray("Answer");
                if (answers != null) {
                    return answers;
                }
                // NOERROR без ответа — это «записи нет», второй провайдер
                // то же самое и скажет.
                if (json.optInt("Status", -1) == 3 || json.optInt("Status", -1) == 0) {
                    return null;
                }
            } catch (Exception ignored) {
                // пробуем следующего провайдера
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }
        return null;
    }

    private static String readAll(InputStream in) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(in, "UTF-8"));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = r.readLine()) != null) {
            sb.append(line);
        }
        r.close();
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Порты
    // ------------------------------------------------------------------

    private static final int[][] PORTS = {
            {443, 1},   // HTTPS
            {25, 1},    // SMTP
            {587, 1},   // SMTP submission
            {465, 1},   // SMTPS
            {993, 1},   // IMAPS
            {995, 1},   // POP3S
            {4040, 1},  // Kerio WebAdmin
    };

    private static final String[] PORT_NAMES = {
            "HTTPS (сайт и веб-почта)", "SMTP (приём почты)", "SMTP 587 (отправка)",
            "SMTPS 465", "IMAPS 993", "POP3S 995", "Kerio WebAdmin 4040",
    };

    static Section checkPorts(String ip, String domain) {
        Section s = new Section("Открытые порты");
        for (int i = 0; i < PORTS.length; i++) {
            int port = PORTS[i][0];
            String name = PORT_NAMES[i];
            boolean open = portOpen(ip, port);
            if (open) {
                s.add("ok", port + " — " + name, "порт отвечает");
            } else {
                // 4040 часто закрыт снаружи намеренно — это не ошибка.
                String status = (port == 4040) ? "info" : "warn";
                String hint = (port == 4040)
                        ? "админка Kerio обычно не публикуется в интернет — это правильная настройка"
                        : "порт не отвечает: служба остановлена, закрыт файрвол или провайдер блокирует";
                s.add(status, port + " — " + name, hint);
            }
        }
        if (!portOpen(ip, 25)) {
            s.add("info", "Почему 25 может быть закрыт",
                    "Многие хостеры и провайдеры блокируют 25 порт. Если почта не ходит — "
                            + "проверьте это в Kerio: Logs → SMTP.");
        }
        return s;
    }

    private static boolean portOpen(String host, int port) {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host, port), 3000);
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            closeQuietly(socket);
        }
    }

    // ------------------------------------------------------------------
    // Спам-базы (RBL/DBL)
    // ------------------------------------------------------------------

    /**
     * Одна спам-база.
     *
     * site — куда отправить человека, если база не отвечает: у крупных зон
     * есть веб-проверка, и это честнее, чем показывать «нет ответа».
     */
    private static final class Zone {
        final String host;
        final String site;
        final boolean domain;

        Zone(String host, String site, boolean domain) {
            this.host = host;
            this.site = site;
            this.domain = domain;
        }
    }

    // Список сверен с реальными ответами: SORBS и CBL закрылись (2024),
    // поэтому их здесь нет. Суффикс «.ns» у UCEPROTECT2 не нужен — берём level 1.
    private static final Zone[] IP_ZONES = {
            new Zone("zen.spamhaus.org", "https://check.spamhaus.org", false),
            new Zone("bl.spamcop.net", "https://www.spamcop.net/w3m?action=checkblock&ip=", false),
            new Zone("b.barracudacentral.org", "https://www.barracudacentral.org/rbl/removal-request", false),
            new Zone("dnsbl-1.uceprotect.net", "https://www.uceprotect.net/en/rblcheck.php?ipr=", false),
            new Zone("psbl.surriel.com", "https://psbl.org/listing?ip=", false),
            new Zone("bl.mailspike.net", "https://mailspike.org/iplookup.html", false),
            new Zone("bl.blocklist.de", "https://www.blocklist.de/en/search.html?ip=", false),
            new Zone("dnsbl.dronebl.org", "https://dronebl.org/lookup?ip=", false),
    };

    private static final Zone[] DOMAIN_ZONES = {
            new Zone("dbl.spamhaus.org", "https://check.spamhaus.org", true),
    };

    /**
     * Контрольная точка RBL: адрес 127.0.0.2 должен числиться в любой живой
     * базе. Спрашиваем её первым делом — так отличается «IP чистый»
     * (база ответила, записи нет) от «база не отвечает» и от блокировки
     * публичных резолверов.
     */
    private static final String CONTROL_IP = "2.0.0.127";

    // DNS-over-HTTPS: работает через обычный HTTPS, поэтому проходит там, где
    // мобильный оператор не пускает UDP на 53-й порт.
    private static final String[] DOH_BASES = {
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve",
    };

    private static final String[] UDP_RESOLVERS = {"1.1.1.1", "8.8.8.8"};

    private static final int DOH_CONNECT_TIMEOUT_MS = 4000;
    private static final int DOH_READ_TIMEOUT_MS = 5000;

    private static final int ST_LISTED = 1;
    private static final int ST_CLEAN = 0;
    private static final int ST_NOT_CHECKED = 2;
    private static final int ST_NO_NETWORK = 3;

    /** Результат запроса к одной зоне. */
    private static final class RblAnswer {
        final int state;
        final String address;
        final String channel;

        RblAnswer(int state, String address, String channel) {
            this.state = state;
            this.address = address;
            this.channel = channel;
        }
    }

    static Section checkRbl(String domain, String ip) {
        resetDohBreaker();
        Section s = new Section("Спам-базы (RBL)");

        String reversed = reverseIp(ip);
        if (reversed == null) {
            s.add("warn", "IP-адрес", "не удалось получить публичный IPv4 для проверки");
        } else {
            // Базы опрашиваются параллельно: последовательно это 8 баз × 2
            // запроса, и на медленной сети проверка занимала бы полминуты.
            java.util.concurrent.ExecutorService pool =
                    java.util.concurrent.Executors.newFixedThreadPool(Math.min(4, IP_ZONES.length));
            java.util.List<java.util.concurrent.Future<RblAnswer>> futures =
                    new ArrayList<java.util.concurrent.Future<RblAnswer>>();
            try {
                for (Zone zone : IP_ZONES) {
                    final String q = reversed + "." + zone.host;
                    final String zoneHost = zone.host;
                    futures.add(pool.submit(new java.util.concurrent.Callable<RblAnswer>() {
                        @Override
                        public RblAnswer call() {
                            return probeZone(q, zoneHost);
                        }
                    }));
                }
                int listedCount = 0;
                int noNetwork = 0;
                int notChecked = 0;
                for (int i = 0; i < IP_ZONES.length; i++) {
                    Zone zone = IP_ZONES[i];
                    RblAnswer a = await(futures.get(i));
                    if (a.state == ST_LISTED) {
                        listedCount++;
                        s.add("fail", "IP в базе " + zone.host, "адрес " + ip + " там числится ("
                                + a.address + ") — подайте заявку на удаление: " + zone.site);
                    } else if (a.state == ST_NO_NETWORK) {
                        noNetwork++;
                        s.add("warn", zone.host, "проверить не удалось: база не ответила ни по одному каналу");
                    } else if (a.state == ST_NOT_CHECKED) {
                        notChecked++;
                        s.add("info", zone.host, blockedHint(zone));
                    } else {
                        s.add("ok", zone.host, "IP чистый" + channelSuffix(a.channel));
                    }
                }

                if (listedCount > 0) {
                    s.add("fail", "Итог по IP", ip + " найден в " + listedCount + " из "
                            + IP_ZONES.length + " баз");
                } else if (noNetwork == IP_ZONES.length) {
                    s.add("warn", "Итог по IP", "ни одна база не ответила — похоже, сеть блокирует "
                            + "DNS-запросы. Попробуйте через Wi-Fi или другую сеть");
                } else if (notChecked > 0) {
                    s.add("warn", "Итог по IP", "в " + notChecked + " базах проверить не удалось, "
                            + "в остальных " + ip + " не найден");
                } else {
                    s.add("ok", "Итог по IP", ip + " не найден в опрошенных спам-базах");
                }
            } finally {
                pool.shutdownNow();
            }
        }

        for (Zone zone : DOMAIN_ZONES) {
            RblAnswer a = probeZone(domain + "." + zone.host, zone.host);
            if (a.state == ST_LISTED) {
                s.add("fail", "Домен в базе " + zone.host,
                        domain + " числится в списке доменов-спамеров: " + zone.site);
            } else if (a.state == ST_NO_NETWORK) {
                s.add("warn", zone.host, "проверить не удалось: база не ответила ни по одному каналу");
            } else if (a.state == ST_NOT_CHECKED) {
                s.add("info", zone.host, blockedHint(zone));
            } else {
                s.add("ok", zone.host, "домен чистый" + channelSuffix(a.channel));
            }
        }

        s.add("info", "Что делать при попадании",
                "В программе на компьютере откройте вкладку «Выход из блэклистов» — там готовые "
                        + "письма-заявки на 8 баз.");
        return s;
    }

    private static String blockedHint(Zone zone) {
        if (zone.host.endsWith("spamhaus.org")) {
            return "Spamhaus не отвечает публичным DNS-серверам (это его правило, а не сбой). "
                    + "Проверьте адрес на " + zone.site;
        }
        return "база не ответила на контрольный запрос — посмотрите вручную: " + zone.site;
    }

    private static String channelSuffix(String channel) {
        return channel == null || channel.isEmpty() ? "" : " · " + channel;
    }

    private static RblAnswer await(java.util.concurrent.Future<RblAnswer> f) {
        try {
            return f.get(40, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception e) {
            return new RblAnswer(ST_NO_NETWORK, null, "");
        }
    }

    /**
     * Опрашивает одну зону: сначала контрольную точку 127.0.0.2, потом сам адрес.
     *
     * Без контрольного запроса нельзя отличить «записи нет» от «база молчит»:
     * и то, и другое выглядит как отсутствие ответа.
     */
    private static RblAnswer probeZone(String question, String zone) {
        Boolean alive = zoneAlive(zone);

        Probe value = resolve(question);
        if (value.listed) {
            if (value.policyBlock) {
                // 127.255.255.x — не «числится в базе», а отказ в обслуживании
                // публичного резолвера. Показывать это как спам нельзя.
                return new RblAnswer(ST_NOT_CHECKED, null, value.channel);
            }
            return new RblAnswer(ST_LISTED, value.address, value.channel);
        }
        if (alive == null) {
            return new RblAnswer(ST_NO_NETWORK, null, value.channel);
        }
        if (alive) {
            // Зона отвечает, контрольная точка в ней числится, а наш адрес —
            // нет. Значит адреса в базе нет.
            return new RblAnswer(ST_CLEAN, null, value.channel);
        }
        return new RblAnswer(ST_NOT_CHECKED, null, value.channel);
    }

    /**
     * Жива ли база: null — проверить не удалось, true/false — что ответила
     * контрольная точка.
     *
     * Важно: NXDOMAIN на контрольную точку означает, что зона не отвечает нам
     * вообще (так ведёт себя Spamhaus с публичными резолверами). Это не «спам»
     * и не «чисто» — это «проверьте на сайте».
     */
    private static Boolean zoneAlive(String zone) {
        Probe control = resolve(CONTROL_IP + "." + zone);
        if (!control.answered) {
            return null;
        }
        return Boolean.valueOf(control.listed);
    }

    // ------------------------------------------------------------------
    // Каналы разрешения имён
    // ------------------------------------------------------------------

    /** Ответ одного DNS-запроса. */
    private static final class Probe {
        final boolean answered;
        final boolean listed;
        final boolean policyBlock;
        final String address;
        final String channel;

        Probe(boolean answered, boolean listed, boolean policyBlock, String address, String channel) {
            this.answered = answered;
            this.listed = listed;
            this.policyBlock = policyBlock;
            this.address = address;
            this.channel = channel;
        }
    }

    private static Probe probeListed(String ip, String channel) {
        boolean policy = ip.startsWith("127.255.255.");
        return new Probe(true, true, policy, ip, channel);
    }

    private static Probe probeClean(String channel) {
        return new Probe(true, false, false, null, channel);
    }

    private static Probe probeUnknown(String channel) {
        return new Probe(false, false, false, null, channel);
    }

    /**
     * Предохранитель для DNS-over-HTTPS.
     *
     * Если он не работает (оператор режет или сервис ограничил частоту),
     * не нужно повторять попытку для каждой из восьми баз: это десятки
     * лишних запросов и секунды ожидания. После двух подряд отказов
     * канал отключается до конца проверки.
     */
    private static final java.util.concurrent.atomic.AtomicInteger dohFailures =
            new java.util.concurrent.atomic.AtomicInteger();

    private static void resetDohBreaker() {
        dohFailures.set(0);
    }

    private static boolean dohUsable() {
        return dohFailures.get() < 2;
    }

    /**
     * Разрешает имя всеми доступными способами по очереди.
     *
     * Сначала — системный резолвер Android (API 29+): он единственный отдаёт
     * точный код ответа и при этом ходит через DNS оператора, то есть работает
     * в мобильной сети. DNS-over-HTTPS и UDP остаются запасными каналами:
     * на телефоне они часто закрыты, а раньше именно они были единственными,
     * из-за чего все базы показывали «нет ответа».
     */
    static Probe resolve(String name) {
        if (DnsSystem.supported()) {
            DnsSystem.Reply r = DnsSystem.query(appContext, name);
            if (r.answered) {
                if (r.nxdomain) {
                    return probeClean("DNS телефона");
                }
                DnsReply parsed = parseAnswer(r.raw);
                if (parsed != null && parsed.address != null) {
                    return probeListed(parsed.address, "DNS телефона");
                }
                // Ответ без A-записи — имени сопоставлен только другой тип.
                return probeClean("DNS телефона");
            }
        }
        if (dohUsable()) {
            for (String base : DOH_BASES) {
                Probe p = probeDoh(name, base);
                if (p.answered) {
                    dohFailures.set(0);
                    return p;
                }
            }
            dohFailures.incrementAndGet();
        }
        for (String server : UDP_RESOLVERS) {
            Probe p = probeUdp(name, server);
            if (p.answered) {
                return p;
            }
        }
        if (!DnsSystem.supported()) {
            // Android 5–9: лучшего источника нет, но NXDOMAIN он не различает.
            Probe sys = probeSystem(name);
            if (sys.answered) {
                return sys;
            }
        }
        return probeUnknown("нет ответа");
    }

    /** Системный резолвер Android: быстрый, но NXDOMAIN и сбой неразличимы. */
    private static Probe probeSystem(String name) {
        try {
            InetAddress[] all = InetAddress.getAllByName(name);
            if (all != null) {
                for (InetAddress a : all) {
                    String ip = a.getHostAddress();
                    if (ip != null && ip.startsWith("127.")) {
                        return probeListed(ip, "системный DNS");
                    }
                }
            }
            return probeClean("системный DNS");
        } catch (Exception e) {
            return probeUnknown("системный DNS");
        }
    }

    /** DNS-over-HTTPS: единственный канал, который отдаёт точный код ответа. */
    private static Probe probeDoh(String name, String base) {
        String channel = base.contains("google") ? "Google DoH" : "Cloudflare DoH";
        JSONObject json = dohJson(base, name);
        if (json == null) {
            return probeUnknown(channel);
        }
        int status = json.optInt("Status", -1);
        if (status == 3) {
            return probeClean(channel);           // NXDOMAIN — записи нет
        }
        if (status != 0) {
            return probeUnknown(channel);         // SERVFAIL / REFUSED
        }
        JSONArray answers = json.optJSONArray("Answer");
        if (answers != null) {
            for (int i = 0; i < answers.length(); i++) {
                JSONObject rec = answers.optJSONObject(i);
                String data = rec == null ? "" : rec.optString("data", "");
                if (data.startsWith("127.")) {
                    return probeListed(data, channel);
                }
            }
        }
        return probeClean(channel);               // NOERROR без A-записи
    }

    /** Обычный DNS по UDP — последний вариант, когда HTTPS недоступен. */
    private static Probe probeUdp(String name, String server) {
        try {
            DnsReply r = dnsQuery(name, server, 4000);
            if (r == null) {
                return probeUnknown("UDP " + server);
            }
            if (r.rcode == 3) {
                return probeClean("UDP " + server);
            }
            if (r.rcode != 0) {
                return probeUnknown("UDP " + server);
            }
            if (r.address == null) {
                return probeClean("UDP " + server);
            }
            return probeListed(r.address, "UDP " + server);
        } catch (Exception e) {
            return probeUnknown("UDP " + server);
        }
    }

    /** JSON-ответ DoH или null. */
    private static JSONObject dohJson(String base, String name) {
        HttpURLConnection conn = null;
        try {
            String url = base + "?name=" + URLEncoder.encode(name, "UTF-8") + "&type=A";
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(DOH_CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(DOH_READ_TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/dns-json");
            if (conn.getResponseCode() != 200) {
                return null;
            }
            return new JSONObject(readAll(conn.getInputStream()));
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /** Минимальный ответ DNS: код и первый A-адрес. */
    static final class DnsReply {
        int rcode;
        String address;
    }

    private static DnsReply dnsQuery(String name, String server, int timeoutMs) throws Exception {
        int id = (int) (Math.random() * 65535) & 0xFFFF;
        byte[] query = buildQuery(name, id);
        java.net.DatagramSocket socket = new java.net.DatagramSocket();
        try {
            socket.setSoTimeout(timeoutMs);
            InetAddress target = InetAddress.getByName(server);
            socket.send(new java.net.DatagramPacket(query, query.length, target, 53));
            byte[] buf = new byte[1500];
            java.net.DatagramPacket packet = new java.net.DatagramPacket(buf, buf.length);
            socket.receive(packet);
            return parseReply(buf, packet.getLength(), id);
        } finally {
            closeQuietly(socket);
        }
    }

    private static byte[] buildQuery(String name, int id) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write((id >> 8) & 0xFF);
        out.write(id & 0xFF);
        out.write(0x01);            // RD — просим рекурсию
        out.write(0x00);
        out.write(0x00);            // QDCOUNT = 1
        out.write(0x01);
        out.write(0x00);
        out.write(0x00);            // ANCOUNT
        out.write(0x00);
        out.write(0x00);            // NSCOUNT
        out.write(0x00);
        out.write(0x00);            // ARCOUNT
        for (String label : name.split("\\.")) {
            byte[] bytes = label.getBytes("US-ASCII");
            if (bytes.length == 0 || bytes.length > 63) {
                continue;
            }
            out.write(bytes.length);
            out.write(bytes, 0, bytes.length);
        }
        out.write(0x00);            // конец имени
        out.write(0x00);            // QTYPE = A
        out.write(0x01);
        out.write(0x00);            // QCLASS = IN
        out.write(0x01);
        return out.toByteArray();
    }

    private static int skipName(byte[] b, int off) {
        while (off < b.length) {
            int len = b[off] & 0xFF;
            if (len == 0) {
                return off + 1;
            }
            if ((len & 0xC0) == 0xC0) {
                return off + 2;     // указатель на сжатое имя
            }
            off += 1 + len;
        }
        return off;
    }

    /** Разбор DNS-ответа, пришедшего от системного резолвера (ID не сверяем). */
    static DnsReply parseAnswer(byte[] b) {
        if (b == null || b.length < 12) {
            return null;
        }
        return parseReply(b, b.length, -1);
    }

    private static DnsReply parseReply(byte[] b, int len, int id) {
        if (len < 12) {
            return null;
        }
        if (id >= 0) {
            int rid = ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
            if (rid != id) {
                return null;
            }
        }
        DnsReply reply = new DnsReply();
        reply.rcode = b[3] & 0x0F;
        int questions = ((b[4] & 0xFF) << 8) | (b[5] & 0xFF);
        int answers = ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);

        int off = 12;
        for (int i = 0; i < questions && off < len; i++) {
            off = skipName(b, off) + 4;
        }
        for (int i = 0; i < answers && off + 10 <= len; i++) {
            off = skipName(b, off);
            if (off + 10 > len) {
                break;
            }
            int type = ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
            int rdlen = ((b[off + 8] & 0xFF) << 8) | (b[off + 9] & 0xFF);
            off += 10;
            if (type == 1 && rdlen == 4 && off + 4 <= len) {
                reply.address = (b[off] & 0xFF) + "." + (b[off + 1] & 0xFF) + "."
                        + (b[off + 2] & 0xFF) + "." + (b[off + 3] & 0xFF);
                break;
            }
            off += rdlen;
        }
        return reply;
    }

    private static String reverseIp(String ip) {
        if (ip == null) {
            return null;
        }
        String clean = ip.trim();
        if (clean.contains(":")) {
            return null; // IPv6-обратные зоны у RBL почти не поддерживаются
        }
        String[] parts = clean.split("\\.");
        if (parts.length != 4) {
            return null;
        }
        return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0];
    }

    // ------------------------------------------------------------------
    // Отчёт
    // ------------------------------------------------------------------

    static void closeQuietly(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
                // ничего не делаем
            }
        }
    }

    static void closeQuietly(Socket s) {
        if (s != null) {
            try {
                s.close();
            } catch (Exception ignored) {
                // ничего не делаем
            }
        }
    }
}
