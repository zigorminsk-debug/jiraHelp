package com.csl.helpdesk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/** Read-only Jira REST v2 transport. Default platform TLS checks are never bypassed. */
public final class JiraClient {
    public interface Connections { HttpURLConnection open(URL url) throws IOException; }
    public static final class Failure extends IOException {
        public Failure(String message) { super(message); }
    }
    private final Connections connections;
    public JiraClient() { this(url -> (HttpURLConnection) url.openConnection()); }
    public JiraClient(Connections connections) { this.connections = connections; }

    public static String serverUrl(String value) {
        try {
            URI uri = new URI(value.trim());
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                    || uri.getRawFragment() != null) throw new IllegalArgumentException();
            String result = uri.toASCIIString();
            while (result.endsWith("/")) result = result.substring(0, result.length() - 1);
            return result;
        } catch (Exception e) {
            throw new IllegalArgumentException("Укажите HTTPS URL Jira без логина, query и fragment");
        }
    }

    public String get(String server, String authorization, String resource) throws IOException {
        // Only fixed API resources are exposed. Never send credentials to caller-controlled URLs.
        if (!resource.matches("myself|search\\?startAt=[0-9]+&maxResults=100&fields=summary,description,status,priority,assignee,reporter,created")) {
            throw new IllegalArgumentException("Unsupported API resource");
        }
        if (authorization == null || !authorization.startsWith("Basic ")
                || authorization.contains("\r") || authorization.contains("\n")) {
            throw new IllegalArgumentException("Invalid authorization");
        }
        HttpURLConnection connection = connections.open(new URL(serverUrl(server) + "/rest/api/2/" + resource));
        try {
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(20000);
            // Jira -> SSO/another host redirect must not carry Authorization.
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Authorization", authorization);
            int status = connection.getResponseCode();
            if (status == 401) throw new Failure("HTTP 401: неверный логин/пароль или токен; возможна CAPTCHA Jira");
            if (status == 403) throw new Failure("HTTP 403: доступ запрещён; проверьте права, CAPTCHA и политику авторизации");
            if (status >= 300 && status < 400) throw new Failure("HTTP " + status + ": сервер перенаправляет на вход/SSO. Нужна авторизация REST API, не веб-сессия");
            if (status == 404) throw new Failure("HTTP 404: Jira REST v2 не найден. Проверьте URL и context path (например /jira)");
            if (status == 429) throw new Failure("HTTP 429: слишком много запросов. Повторите позже");
            if (status != 200) throw new Failure("Jira вернула HTTP " + status);
            String contentType = connection.getContentType();
            if (contentType == null || !contentType.toLowerCase(java.util.Locale.ROOT).contains("application/json")) {
                throw new Failure("Сервер вернул не JSON. Возможна HTML-страница входа/прокси вместо Jira API");
            }
            try (InputStream stream = connection.getInputStream(); ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = stream.read(buffer)) != -1) {
                    if (bytes.size() + count > 4 * 1024 * 1024) throw new Failure("Ответ Jira превышает 4 MiB; сузьте выборку");
                    bytes.write(buffer, 0, count);
                }
                return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
            }
        } finally {
            connection.disconnect();
        }
    }
}
