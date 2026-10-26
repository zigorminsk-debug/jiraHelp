package by.csl.kcm;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

/**
 * Главный экран приложения KerioCertManager Mobile.
 *
 * Две вкладки:
 *   📱 «Пульт»    — подключение к программе на компьютере по Wi-Fi;
 *   🔎 «Проверка» — автономная диагностика домена без компьютера.
 *
 * В шапке — кнопка проверки обновлений с GitHub. Раз в сутки приложение
 * проверяет релизы само и просто подсвечивает кнопку, если вышла новая
 * версия: без навязчивых окон.
 *
 * Никаких библиотек кроме платформы: APK собирается без Gradle и без
 * интернета, поэтому обновлять зависимости не придётся никогда.
 */
public class MainActivity extends Activity {

    private RemotePane remotePane;
    private CheckPane checkPane;
    private Button remoteTab;
    private Button checkTab;
    private Button updateButton;
    private TextView updateStatus;

    /** Найденный, но ещё не установленный релиз. */
    private Updates.Release foundRelease;
    /** Уже скачанный APK: повторно качать не нужно. */
    private File downloadedFile;
    private boolean checking;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Ui.BG);
        root.setFitsSystemWindows(true);

        root.addView(buildHeader(), new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        root.addView(buildTabs(), new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        FrameLayout content = new FrameLayout(this);
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        root.addView(content, cp);

        remotePane = new RemotePane(this);
        checkPane = new CheckPane(this);
        content.addView(remotePane, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        content.addView(checkPane, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        setContentView(root);
        selectTab(true);
        autoCheckUpdates();
    }

    private View buildHeader() {
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.VERTICAL);
        header.setPadding(Ui.dp(this, 16), Ui.dp(this, 14), Ui.dp(this, 16), Ui.dp(this, 6));

        TextView title = Ui.title(this, "KerioCertManager", 19f);
        header.addView(title);

        TextView sub = Ui.text(this, "Mobile " + Versions.APP_VERSION
                + " · пульт к программе на ПК и проверка домена", Ui.MUTED, 12.5f);
        sub.setPadding(0, Ui.dp(this, 2), 0, 0);
        header.addView(sub);

        // Кнопка обновления — во всю ширину: её должно быть видно сразу,
        // без прокрутки и без догадок, что это ссылка.
        updateButton = Ui.button(this, "🔄 Проверить обновления", false);
        updateButton.setTextSize(14f);
        updateButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onUpdateButton();
            }
        });
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        bp.topMargin = Ui.dp(this, 8);
        updateButton.setLayoutParams(bp);
        header.addView(updateButton);

        updateStatus = Ui.text(this, "", Ui.MUTED, 12f);
        updateStatus.setPadding(Ui.dp(this, 2), Ui.dp(this, 5), 0, 0);
        header.addView(updateStatus);
        return header;
    }

    private View buildTabs() {
        LinearLayout tabs = new LinearLayout(this);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        tabs.setPadding(Ui.dp(this, 14), 0, Ui.dp(this, 14), Ui.dp(this, 10));

        remoteTab = Ui.button(this, "📱 Пульт", true);
        remoteTab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                selectTab(true);
            }
        });
        tabs.addView(remoteTab, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        checkTab = Ui.button(this, "🔎 Проверка", false);
        checkTab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                selectTab(false);
            }
        });
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        cp.leftMargin = Ui.dp(this, 8);
        tabs.addView(checkTab, cp);
        return tabs;
    }

    private void selectTab(boolean remote) {
        remotePane.setVisibility(remote ? View.VISIBLE : View.GONE);
        checkPane.setVisibility(remote ? View.GONE : View.VISIBLE);

        remoteTab.setBackgroundColor(remote ? Ui.ACCENT : 0x00000000);
        remoteTab.setTextColor(remote ? 0xFFFFFFFF : Ui.TEXT);
        checkTab.setBackgroundColor(remote ? 0x00000000 : Ui.ACCENT);
        checkTab.setTextColor(remote ? Ui.TEXT : 0xFFFFFFFF);
    }

    // ------------------------------------------------------------------
    // Обновления
    // ------------------------------------------------------------------

    /** Тихая проверка при запуске: раз в сутки, без окон. */
    private void autoCheckUpdates() {
        Updates.maybeAutoCheck(this, new Updates.Callback() {
            @Override
            public void onResult(Updates.Release release, String error) {
                if (release != null) {
                    showFound(release, false);
                }
            }
        });
    }

    private void onUpdateButton() {
        if (downloadedFile != null && downloadedFile.isFile()) {
            Updates.installFile(this, downloadedFile);
            return;
        }
        if (foundRelease != null) {
            askToInstall(foundRelease);
            return;
        }
        checkUpdatesManually();
    }

    private void checkUpdatesManually() {
        if (checking) {
            return;
        }
        checking = true;
        updateButton.setEnabled(false);
        updateButton.setText("⏳ Проверяем…");
        updateStatus.setText("");

        Updates.check(this, new Updates.Callback() {
            @Override
            public void onResult(Updates.Release release, String error) {
                checking = false;
                // Кнопку включаем ВСЕГДА: иначе после одной неудачной проверки
                // она остаётся серой и больше не нажимается.
                updateButton.setEnabled(true);

                if (error != null) {
                    updateButton.setText("🔄 Проверить обновления");
                    updateStatus.setTextColor(Ui.BAD);
                    updateStatus.setText("Не удалось проверить: " + error);
                    return;
                }
                if (release == null) {
                    updateButton.setText("🔄 Проверить обновления");
                    updateStatus.setTextColor(Ui.OK);
                    updateStatus.setText("У вас последняя версия " + Versions.APP_VERSION
                            + " (проверено в " + timeNow() + ")");
                    return;
                }
                showFound(release, true);
            }
        });
    }

    private static String timeNow() {
        return new java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
                .format(new java.util.Date());
    }

    private void showFound(final Updates.Release release, boolean announce) {
        foundRelease = release;
        updateButton.setEnabled(true);
        updateButton.setText("🔄 Обновить до " + release.version);
        updateStatus.setTextColor(Ui.WARN);
        updateStatus.setText("Доступна новая версия " + release.version + " · " + release.humanSize());
        if (announce) {
            askToInstall(release);
        }
    }

    private void askToInstall(final Updates.Release release) {
        String size = release.humanSize();
        String message = "Сейчас установлена версия " + Versions.APP_VERSION
                + ", на GitHub вышла " + release.version + "."
                + (size.isEmpty() ? "" : "\n\nРазмер файла: " + size + ".")
                + "\n\nПриложение скачает APK и откроет системный установщик. "
                + "Данные и настройки сохранятся.";

        new AlertDialog.Builder(this)
                .setTitle("Доступно обновление " + release.version)
                .setMessage(message)
                .setPositiveButton("Скачать и установить", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        startDownload(release);
                    }
                })
                .setNeutralButton("Страница релиза", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        Updates.openReleasesPage(MainActivity.this);
                    }
                })
                .setNegativeButton("Позже", null)
                .show();
    }

    private void startDownload(final Updates.Release release) {
        updateButton.setEnabled(false);
        updateButton.setText("Скачиваю…");
        updateStatus.setTextColor(Ui.MUTED);
        updateStatus.setText("Скачиваю " + release.version + "…");

        Updates.downloadAndInstall(this, release, new Updates.Progress() {
            @Override
            public void onProgress(int percent) {
                updateButton.setText("Скачиваю " + percent + "%");
            }

            @Override
            public void onDone(File file, String error) {
                updateButton.setEnabled(true);
                if (file == null) {
                    updateButton.setText("🔄 Обновить до " + release.version);
                    updateStatus.setTextColor(Ui.BAD);
                    updateStatus.setText("Скачать не удалось: "
                            + (error == null ? "неизвестная ошибка" : error));
                    return;
                }
                downloadedFile = file;
                updateButton.setText("Установить " + release.version);
                updateStatus.setTextColor(Ui.OK);
                updateStatus.setText("Файл скачан — нажмите «Установить»");
            }
        });
    }

    @Override
    public void onBackPressed() {
        if (remotePane != null && remotePane.handleBack()) {
            return;
        }
        super.onBackPressed();
    }

    @Override
    protected void onDestroy() {
        if (remotePane != null) {
            remotePane.shutdown();
        }
        super.onDestroy();
    }
}
