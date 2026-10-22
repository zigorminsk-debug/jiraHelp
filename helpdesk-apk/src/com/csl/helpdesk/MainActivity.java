package com.csl.helpdesk;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;
import android.util.Base64;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/** Bundled WebView UI with a native HTTPS, read-only Jira REST v2 client. */
public class MainActivity extends Activity {
    private static final String HOME = "file:///android_asset/index.html";
    private WebView webView;
    private final ExecutorService network = Executors.newSingleThreadExecutor();
    private final JiraClient jira = new JiraClient();
    private volatile Session session;
    private volatile boolean destroyed;
    private final AtomicReference<Session> fetching = new AtomicReference<>();

    private static final class Session {
        final String server;
        final String authorization;
        Session(String server, String username, String password) {
            this.server = JiraClient.serverUrl(server);
            this.authorization = "Basic " + Base64.encodeToString(
                (username + ":" + password).getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
        }
    }

    private void callback(Session expected, String function, Object... values) {
        JSONArray args = new JSONArray();
        for (Object value : values) args.put(value);
        // Encode the entire argument array as a JSON string, never concatenate server data as code.
        final String payload = JSONObject.quote(args.toString()).replace("\u2028", "\\u2028").replace("\u2029", "\\u2029");
        runOnUiThread(() -> {
            if (destroyed || session != expected || webView == null) return;
            webView.evaluateJavascript("window['" + function + "'].apply(null,JSON.parse(" + payload + "));", null);
        });
    }

    private String errorMessage(Exception e) {
        if (e instanceof JiraClient.Failure) return e.getMessage();
        if (e instanceof javax.net.ssl.SSLException) return "Ошибка TLS/сертификата. Проверьте сертификат сервера и дату телефона; проверка TLS не отключается";
        if (e instanceof java.net.UnknownHostException) return "Не найден сервер: проверьте адрес, DNS и VPN";
        if (e instanceof java.net.SocketTimeoutException) return "Таймаут подключения к Jira. Проверьте сеть/VPN и доступность сервера";
        if (e instanceof org.json.JSONException) return "Некорректный JSON ответ Jira API";
        return "Не удалось подключиться к Jira. Проверьте сеть, URL и доступность REST API";
    }

    private JSONObject authenticate(Session current) throws Exception {
        JSONObject user = new JSONObject(jira.get(current.server, current.authorization, "myself"));
        if (user.optString("name").isEmpty() && user.optString("accountId").isEmpty()
                && user.optString("key").isEmpty()) throw new JiraClient.Failure("Ответ /myself не содержит пользователя Jira");
        return user;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(Color.parseColor("#0d0d1a"));
        getWindow().setNavigationBarColor(Color.parseColor("#1a1a2e"));
        // Keep system insets: edge-to-edge previously hid controls under status/navigation bars.
        webView = new WebView(this);
        setContentView(webView);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true); // Bundled UI requires JS; remote navigation is blocked.
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false); // android_asset remains accessible.
        settings.setAllowContentAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setBlockNetworkLoads(true); // REST runs natively, never inside remote WebView frames.
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setSupportZoom(false);
        settings.setMediaPlaybackRequiresUserGesture(true);
        webView.setBackgroundColor(Color.parseColor("#0d0d1a"));
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                // Never expose AndroidBridge to a navigated remote/untrusted document.
                return !HOME.equals(url);
            }
        });
        webView.setWebChromeClient(new WebChromeClient());
        webView.addJavascriptInterface(new AndroidBridge(), "AndroidBridge");
        webView.loadUrl(HOME);
    }

    private void launch(final Intent intent) {
        // JavascriptInterface callbacks execute on a WebView background thread.
        runOnUiThread(() -> {
            try {
                startActivity(intent);
            } catch (ActivityNotFoundException | SecurityException e) {
                Toast.makeText(this, "Приложение недоступно", Toast.LENGTH_SHORT).show();
            }
        });
    }

    public class AndroidBridge {
        @JavascriptInterface
        public synchronized void savePrefs(String server, String username, String password) {
            session = null; // Invalidates queued callbacks from old account, even if validation fails.
            if (server == null || username == null || password == null || username.trim().isEmpty()
                    || username.contains(":") || password.isEmpty()) return;
            try { session = new Session(server, username.trim(), password); }
            catch (IllegalArgumentException ignored) { /* UI validates and reports invalid URL. */ }
        }

        @JavascriptInterface
        public void clearSession() { session = null; }

        @JavascriptInterface
        public void testConnection(String server, String username, String password) {
            final Session expected = session;
            final Session candidate;
            try {
                if (username == null || username.trim().isEmpty() || username.contains(":")
                        || password == null || password.isEmpty()) throw new IllegalArgumentException();
                candidate = new Session(server, username.trim(), password);
            } catch (IllegalArgumentException e) {
                callback(expected, "onConnectionTestResult", false, "Укажите HTTPS URL, логин и пароль/API токен");
                return;
            }
            if (destroyed) return;
            network.execute(() -> {
                if (session != expected || destroyed) return;
                try {
                    authenticate(candidate);
                    callback(expected, "onConnectionTestResult", true, "Подключение к Jira подтверждено");
                } catch (Exception e) {
                    callback(expected, "onConnectionTestResult", false, errorMessage(e));
                }
            });
        }

        @JavascriptInterface
        public void fetchTickets() {
            final Session current = session;
            if (current == null) {
                callback(null, "onConnectionResult", false, "Заполните логин и пароль/API токен");
                return;
            }
            if (destroyed || fetching.getAndSet(current) == current) return;
            network.execute(() -> {
                try {
                    if (session != current || destroyed) return;
                    authenticate(current);
                    JSONArray issues = new JSONArray();
                    int start = 0;
                    while (true) {
                        if (session != current || destroyed) return;
                        JSONObject page = new JSONObject(jira.get(current.server, current.authorization,
                            "search?startAt=" + start + "&maxResults=100&fields=summary,description,status,priority,assignee,reporter,created"));
                        JSONArray batch = page.getJSONArray("issues");
                        if (batch.length() == 0) break;
                        for (int i = 0; i < batch.length(); i++) issues.put(batch.getJSONObject(i));
                        start += batch.length();
                        if (start >= page.getInt("total")) break;
                        if (start >= 5000) throw new JiraClient.Failure("Более 5000 заявок: требуется фильтр выборки. Неполный результат не применён");
                    }
                    JSONObject response = new JSONObject();
                    response.put("issues", issues);
                    callback(current, "onConnectionResult", true, "Подключение к Jira подтверждено");
                    callback(current, "onTicketsFetched", response);
                } catch (Exception e) {
                    callback(current, "onConnectionResult", false, errorMessage(e));
                } finally { fetching.compareAndSet(current, null); }
            });
        }

        private void share(String text, String title, String packageName) {
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_SUBJECT, title);
            intent.putExtra(Intent.EXTRA_TEXT, text);
            if (packageName != null) {
                intent.setPackage(packageName);
                launch(intent); // A chooser can hide a missing target application.
            } else {
                launch(Intent.createChooser(intent, "Поделиться через..."));
            }
        }

        @JavascriptInterface
        public void shareTicket(String title, String text) { share(text, title, null); }
        @JavascriptInterface
        public void shareToTelegram(String text) { share(text, "Заявка", "org.telegram.messenger"); }
        @JavascriptInterface
        public void shareToViber(String text) { share(text, "Заявка", "com.viber.voip"); }
        @JavascriptInterface
        public void shareToWhatsApp(String text) { share(text, "Заявка", "com.whatsapp"); }

        @JavascriptInterface
        public void callPhone(String number) {
            if (number != null && number.matches("\\+?[0-9]{7,15}")) {
                launch(new Intent(Intent.ACTION_DIAL, Uri.fromParts("tel", number, null)));
            }
        }

        @JavascriptInterface
        public void copyToClipboard(String text) {
            runOnUiThread(() -> {
                ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (clipboard != null) {
                    clipboard.setPrimaryClip(ClipData.newPlainText("ticket", text));
                    Toast.makeText(MainActivity.this, "Скопировано в буфер обмена", Toast.LENGTH_SHORT).show();
                }
            });
        }
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }

    @Override
    protected void onDestroy() {
        destroyed = true;
        session = null;
        network.shutdownNow();
        if (webView != null) {
            webView.removeJavascriptInterface("AndroidBridge");
            webView.stopLoading();
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }
}
