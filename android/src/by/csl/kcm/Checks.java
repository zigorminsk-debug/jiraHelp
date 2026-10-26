package by.csl.kcm;

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

    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final String DOH = "https://cloudflare-dns.com/dns-query";

    private Checks() {
    }

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

    /** Запрос к DNS-over-HTTPS (Cloudflare). Возвращает массив answer или null. */
    private static JSONArray doh(String name, String type) {
        HttpURLConnection conn = null;
        try {
            String url = DOH + "?name=" + URLEncoder.encode(name, "UTF-8") + "&type=" + type;
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(CONNECT_TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/dns-json");
            int code = conn.getResponseCode();
            if (code != 200) {
                return null;
            }
            String body = readAll(conn.getInputStream());
            JSONObject json = new JSONObject(body);
            return json.optJSONArray("Answer");
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
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

    private static final String[] IP_ZONES = {
            "zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org",
            "dnsbl.sorbs.net", "spam.dnsbl.sorbs.net", "cbl.abuseat.org",
    };

    private static final String[] DOMAIN_ZONES = {"dbl.spamhaus.org"};

    static Section checkRbl(String domain, String ip) {
        Section s = new Section("Спам-базы (RBL)");

        String reversed = reverseIp(ip);
        if (reversed == null) {
            s.add("warn", "IP-адрес", "не удалось получить публичный IPv4 для проверки");
        } else {
            boolean listed = false;
            for (String zone : IP_ZONES) {
                String answer = resolveA(reversed + "." + zone);
                if (answer != null && answer.startsWith("127.0.0.")) {
                    listed = true;
                    s.add("fail", "IP в базе " + zone, "адрес " + ip + " там числится — подайте заявку на удаление");
                } else if (answer == null) {
                    s.add("info", zone, "нет ответа (база недоступна или запрос заблокирован)");
                } else {
                    s.add("ok", zone, "IP чистый");
                }
            }
            if (!listed) {
                s.add("ok", "Итог по IP", ip + " не найден в опрошенных спам-базах");
            }
        }

        for (String zone : DOMAIN_ZONES) {
            String answer = resolveA(domain + "." + zone);
            if (answer != null && answer.startsWith("127.0.0.")) {
                s.add("fail", "Домен в базе " + zone, domain + " числится в списке доменов-спамеров");
            } else if (answer == null) {
                s.add("info", zone, "нет ответа (база недоступна)");
            } else {
                s.add("ok", zone, "домен чистый");
            }
        }

        s.add("info", "Что делать при попадании",
                "В программе на компьютере откройте вкладку «Выход из блэклистов» — там готовые "
                        + "письма-заявки на 8 баз.");
        return s;
    }

    /** DNS-запрос A-записи (RBL отвечают адресом 127.0.0.x, если запись есть). */
    private static String resolveA(String name) {
        try {
            return InetAddress.getByName(name).getHostAddress();
        } catch (Exception e) {
            return null;
        }
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
