package by.csl.kcm;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Обновление приложения прямо с GitHub Releases.
 *
 * Логика простая и не требует сервера: GitHub отдаёт последний релиз
 * репозитория, мы сравниваем версию со своей, при наличии новой — скачиваем
 * APK и передаём его системному установщику.
 *
 * Обновление «поверх» установится только если APK подписан тем же ключом,
 * что и установленная копия. Поэтому релизные сборки подписываются
 * постоянным ключом из android/keystore (см. build-apk.sh).
 */
final class Updates {

    // Именно список, а не /releases/latest: в репозитории есть служебные
    // релизы kerio-latest и antispam-db-latest, и «последним» GitHub может
    // назвать любой из них. Нам нужен только тег вида vX.Y.Z.
    private static final String API = "https://api.github.com/repos/" + Versions.REPO + "/releases?per_page=30";
    private static final String PAGE = "https://github.com/" + Versions.REPO + "/releases/latest";

    private static final String PREFS = "kcm_updates";
    private static final String KEY_LAST_CHECK = "last_check_ms";
    private static final long DAY_MS = 24L * 60 * 60 * 1000;
    private static final int CONNECT_TIMEOUT_MS = 12000;
    private static final int READ_TIMEOUT_MS = 30000;

    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private Updates() {
    }

    /** Описание доступного релиза. */
    static final class Release {
        final String version;
        final String apkUrl;
        final long sizeBytes;
        final String pageUrl;

        Release(String version, String apkUrl, long sizeBytes, String pageUrl) {
            this.version = version;
            this.apkUrl = apkUrl;
            this.sizeBytes = sizeBytes;
            this.pageUrl = pageUrl;
        }

        String humanSize() {
            if (sizeBytes <= 0) {
                return "";
            }
            double mb = sizeBytes / (1024.0 * 1024.0);
            if (mb < 1) {
                return Math.round(sizeBytes / 1024.0) + " КБ";
            }
            return String.format(java.util.Locale.US, "%.1f МБ", mb);
        }
    }

    interface Callback {
        /** release == null, если обновления нет; error != null при сбое. */
        void onResult(Release release, String error);
    }

    interface Progress {
        void onProgress(int percent);

        /** file == null, если скачать не удалось; error — причина. */
        void onDone(File file, String error);
    }

    // ------------------------------------------------------------------
    // Проверка
    // ------------------------------------------------------------------

    /** Проверяет последний релиз в фоне и отвечает в потоке интерфейса. */
    static void check(final Context ctx, final Callback cb) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                Release release = null;
                String error = null;
                try {
                    release = fetchLatest();
                } catch (Exception e) {
                    error = describe(e);
                }
                final Release r = release;
                final String err = error;
                MAIN.post(new Runnable() {
                    @Override
                    public void run() {
                        cb.onResult(r, err);
                    }
                });
            }
        }, "kcm-update-check").start();
    }

    /**
     * Тихая проверка при запуске: не чаще одного раза в сутки.
     * Если найдено обновление — вызывается onFound, иначе ничего не происходит.
     */
    static void maybeAutoCheck(final Activity a, final Callback onFound) {
        SharedPreferences p = a.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        long last = p.getLong(KEY_LAST_CHECK, 0L);
        if (System.currentTimeMillis() - last < DAY_MS) {
            return;
        }
        check(a, new Callback() {
            @Override
            public void onResult(Release release, String error) {
                // Время сохраняем и при ошибке: иначе без интернета приложение
                // будет долбить GitHub при каждом открытии.
                a.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                        .edit().putLong(KEY_LAST_CHECK, System.currentTimeMillis()).apply();
                if (release != null) {
                    onFound.onResult(release, null);
                }
            }
        });
    }

    private static Release fetchLatest() throws Exception {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(API).openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/vnd.github+json");
            conn.setRequestProperty("User-Agent", "KerioCertManager-Mobile/" + Versions.APP_VERSION);
            int code = conn.getResponseCode();
            if (code == 404) {
                throw new IllegalStateException("В репозитории пока нет ни одного релиза");
            }
            if (code == 403) {
                throw new IllegalStateException("GitHub ограничил частоту запросов — попробуйте через час");
            }
            if (code != 200) {
                throw new IllegalStateException("GitHub ответил кодом " + code);
            }
            String body = readAll(conn.getInputStream());
            JSONArray releases = new JSONArray(body);
            for (int i = 0; i < releases.length(); i++) {
                JSONObject rel = releases.optJSONObject(i);
                if (rel == null || rel.optBoolean("draft", false) || rel.optBoolean("prerelease", false)) {
                    continue;
                }
                String version = normalize(rel.optString("tag_name", ""));
                if (!isVersionTag(version)) {
                    continue;                       // «kerio-latest», «antispam-db-latest»
                }
                if (!isNewer(version, Versions.APP_VERSION)) {
                    continue;                       // уже установлено или старее
                }
                JSONArray assets = rel.optJSONArray("assets");
                if (assets == null) {
                    continue;
                }
                for (int j = 0; j < assets.length(); j++) {
                    JSONObject asset = assets.optJSONObject(j);
                    if (asset == null) {
                        continue;
                    }
                    String name = asset.optString("name", "");
                    String url = asset.optString("browser_download_url", "");
                    if (name.endsWith(".apk") && !url.isEmpty()) {
                        return new Release(version, url, asset.optLong("size", 0L),
                                rel.optString("html_url", PAGE));
                    }
                }
            }
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /** «v4.9.4» → «4.9.4». */
    private static String normalize(String tag) {
        String v = tag == null ? "" : tag.trim();
        if (v.startsWith("v") || v.startsWith("V")) {
            v = v.substring(1);
        }
        return v;
    }

    /** Тег должен быть именно версией: 4.9.4, а не kerio-latest. */
    static boolean isVersionTag(String version) {
        if (version == null || version.isEmpty()) {
            return false;
        }
        String[] parts = version.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 4) {
                return false;
            }
            for (int i = 0; i < part.length(); i++) {
                if (!Character.isDigit(part.charAt(i))) {
                    return false;
                }
            }
        }
        return true;
    }

    /** true, если версия remote новее локальной. */
    static boolean isNewer(String remote, String local) {
        int[] a = Versions.parse(remote);
        int[] b = Versions.parse(local);
        for (int i = 0; i < 3; i++) {
            if (a[i] != b[i]) {
                return a[i] > b[i];
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Скачивание и установка
    // ------------------------------------------------------------------

    /** Скачивает APK и запускает системный установщик. Всё в фоне. */
    static void downloadAndInstall(final Activity activity, final Release release,
                                   final Progress cb) {
        if (!canInstall(activity)) {
            requestInstallPermission(activity);
            return;
        }
        new Thread(new Runnable() {
            @Override
            public void run() {
                File result = null;
                String error = null;
                try {
                    result = download(activity, release, cb);
                } catch (Exception e) {
                    error = describe(e);
                }
                final File f = result;
                final String err = error;
                MAIN.post(new Runnable() {
                    @Override
                    public void run() {
                        cb.onDone(f, err);
                        if (f != null && activity.isFinishing() == false) {
                            install(activity, f);
                        }
                    }
                });
            }
        }, "kcm-update-download").start();
    }

    private static File download(Activity a, Release release, Progress cb) throws Exception {
        File dir = UpdateProvider.dir(a);
        cleanup(dir, release.version);
        File out = new File(dir, "KerioCertManager-Mobile-" + release.version + ".apk");

        HttpURLConnection conn = null;
        InputStream in = null;
        OutputStream os = null;
        try {
            conn = (HttpURLConnection) new URL(release.apkUrl).openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestProperty("User-Agent", "KerioCertManager-Mobile/" + Versions.APP_VERSION);
            conn.setInstanceFollowRedirects(true);
            int code = conn.getResponseCode();
            if (code != 200) {
                throw new IllegalStateException("не удалось скачать APK (код " + code + ")");
            }
            long total = conn.getContentLength();
            in = conn.getInputStream();
            os = new FileOutputStream(out);
            byte[] buf = new byte[16384];
            long done = 0;
            int lastPercent = -1;
            int n;
            while ((n = in.read(buf)) > 0) {
                os.write(buf, 0, n);
                done += n;
                if (total > 0) {
                    final int percent = (int) (done * 100 / total);
                    if (percent != lastPercent && percent % 5 == 0) {
                        lastPercent = percent;
                        report(cb, percent);
                    }
                }
            }
            os.flush();
        } finally {
            closeQuietly(in);
            closeQuietly(os);
            if (conn != null) {
                conn.disconnect();
            }
        }

        if (out.length() < 1024) {
            //noinspection ResultOfMethodCallIgnored
            out.delete();
            throw new IllegalStateException("скачался пустой файл");
        }
        // APK — это zip, он всегда начинается с «PK».
        InputStream check = null;
        try {
            check = new java.io.FileInputStream(out);
            int b1 = check.read();
            int b2 = check.read();
            if (b1 != 'P' || b2 != 'K') {
                //noinspection ResultOfMethodCallIgnored
                out.delete();
                throw new IllegalStateException("скачанный файл не похож на APK");
            }
        } finally {
            closeQuietly(check);
        }
        report(cb, 100);
        return out;
    }

    private static void report(final Progress cb, final int percent) {
        MAIN.post(new Runnable() {
            @Override
            public void run() {
                cb.onProgress(percent);
            }
        });
    }

    private static void cleanup(File dir, String keepVersion) {
        File[] files = dir.listFiles();
        if (files == null) {
            return;
        }
        for (File f : files) {
            if (f.isFile() && f.getName().endsWith(".apk")
                    && !f.getName().contains(keepVersion)) {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
            }
        }
    }

    static boolean canInstall(Activity a) {
        if (Build.VERSION.SDK_INT < 26) {
            return true;
        }
        return a.getPackageManager().canRequestPackageInstalls();
    }

    private static void requestInstallPermission(final Activity a) {
        new AlertDialog.Builder(a)
                .setTitle("Разрешите установку")
                .setMessage("Чтобы поставить обновление, Android должен разрешить этому приложению "
                        + "устанавливать APK. Откроется экран настроек — включите переключатель "
                        + "«Разрешить установку из этого источника» и вернитесь назад.")
                .setPositiveButton("Открыть настройки", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        try {
                            Intent i = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                    Uri.parse("package:" + a.getPackageName()));
                            a.startActivity(i);
                        } catch (Exception e) {
                            Toast.makeText(a, "Не удалось открыть настройки: " + e.getMessage(),
                                    Toast.LENGTH_LONG).show();
                        }
                    }
                })
                .setNegativeButton("Отмена", null)
                .show();
    }

    /** Ставит уже скачанный файл (например, если пользователь нажал «Позже»). */
    static void installFile(Activity a, File apk) {
        if (apk == null || !apk.isFile()) {
            Toast.makeText(a, "Файл обновления не найден — скачайте заново",
                    Toast.LENGTH_LONG).show();
            return;
        }
        if (!canInstall(a)) {
            requestInstallPermission(a);
            return;
        }
        install(a, apk);
    }

    private static void install(Activity a, File apk) {
        try {
            Uri uri = UpdateProvider.uriFor(apk.getName());
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setDataAndType(uri, "application/vnd.android.package-archive");
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            a.startActivity(i);
        } catch (Exception e) {
            Toast.makeText(a, "Не удалось открыть установщик: " + e.getMessage(),
                    Toast.LENGTH_LONG).show();
        }
    }

    /** Ссылка на страницу релизов — на случай ручной установки. */
    static void openReleasesPage(Context c) {
        try {
            Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(PAGE));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            c.startActivity(i);
        } catch (Exception e) {
            Toast.makeText(c, "Не удалось открыть браузер", Toast.LENGTH_SHORT).show();
        }
    }

    // ------------------------------------------------------------------
    // Мелочи
    // ------------------------------------------------------------------

    private static String describe(Exception e) {
        String msg = e.getMessage();
        if (msg == null || msg.trim().isEmpty()) {
            msg = e.getClass().getSimpleName();
        }
        if (e instanceof java.net.UnknownHostException) {
            return "Нет связи с GitHub — проверьте интернет";
        }
        if (e instanceof java.net.SocketTimeoutException) {
            return "GitHub не ответил вовремя — попробуйте ещё раз";
        }
        return msg;
    }

    private static String readAll(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        return out.toString("UTF-8");
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
                // ничего
            }
        }
    }
}
