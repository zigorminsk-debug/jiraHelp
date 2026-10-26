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
        header.setPadding(Ui.dp(this, 16), Ui.dp(this, 14), Ui.dp(this, 16), Ui.dp(this, 10));

        TextView title = Ui.title(this, "KerioCertManager", 19f);
        header.addView(title);

        TextView sub = Ui.text(this, "Mobile " + Versions.APP_VERSION
                + " · пульт к программе на ПК и проверка домена", Ui.MUTED, 12.5f);
        sub.setPadding(0, Ui.dp(this, 2), 0, 0);
        header.addView(sub);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(android.view.Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        rp.topMargin = Ui.dp(this, 8);
        row.setLayoutParams(rp);

        updateButton = Ui.smallButton(this, "⬇ Проверить обновления");
        updateButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onUpdateButton();
            }
        });
        row.addView(updateButton, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        updateStatus = Ui.text(this, "", Ui.MUTED, 12f);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        sp.leftMargin = Ui.dp(this, 10);
        updateStatus.setLayoutParams(sp);
        row.addView(updateStatus);

        header.addView(row);
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
        startCheckingUi();
        Updates.check(this, new Updates.Callback() {
            @Override
            public void onResult(Updates.Release release, String error) {
                checking = false;
                if (error != null) {
                    updateButton.setText("⬇ Проверить обновления");
                    updateStatus.setText("не удалось проверить");
                    Toast.makeText(MainActivity.this, error, Toast.LENGTH_LONG).show();
                    return;
                }
                if (release == null) {
                    updateButton.setText("⬇ Проверить обновления");
                    updateStatus.setText("у вас последняя версия");
                    Toast.makeText(MainActivity.this,
                            "Установлена последняя версия " + Versions.APP_VERSION,
                            Toast.LENGTH_SHORT).show();
                    return;
                }
                showFound(release, true);
            }
        });
    }

    private void startCheckingUi() {
        updateButton.setText("⏳ Проверяем…");
        updateButton.setEnabled(false);
        updateStatus.setText("");
    }

    private void showFound(Updates.Release release, boolean announce) {
        foundRelease = release;
        updateButton.setText("⬇ Обновить до " + release.version);
        updateButton.setEnabled(true);
        updateStatus.setText("доступна новая версия");
        updateStatus.setTextColor(Ui.WARN);
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
        updateButton.setText("⬇ 0%");
        updateStatus.setText("скачиваем " + release.version);
        updateStatus.setTextColor(Ui.MUTED);

        Updates.downloadAndInstall(this, release, new Updates.Progress() {
            @Override
            public void onProgress(int percent) {
                updateButton.setText("⬇ " + percent + "%");
            }

            @Override
            public void onDone(File file, String error) {
                updateButton.setEnabled(true);
                if (file == null) {
                    updateButton.setText("⬇ Обновить до " + release.version);
                    updateStatus.setText("скачать не удалось");
                    updateStatus.setTextColor(Ui.BAD);
                    Toast.makeText(MainActivity.this,
                            error == null ? "Не удалось скачать обновление" : error,
                            Toast.LENGTH_LONG).show();
                    return;
                }
                downloadedFile = file;
                updateButton.setText("⬇ Установить " + release.version);
                updateStatus.setText("файл скачан");
                updateStatus.setTextColor(Ui.OK);
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
