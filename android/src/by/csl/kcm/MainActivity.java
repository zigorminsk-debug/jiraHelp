package by.csl.kcm;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Главный экран приложения KerioCertManager Mobile.
 *
 * Две вкладки:
 *   📱 «Пульт»    — подключение к программе на компьютере по Wi-Fi;
 *   🔎 «Проверка» — автономная диагностика домена без компьютера.
 *
 * Никаких библиотек кроме платформы: APK собирается без Gradle и без
 * интернета, поэтому обновлять зависимости не придётся никогда.
 */
public class MainActivity extends Activity {

    private RemotePane remotePane;
    private CheckPane checkPane;
    private Button remoteTab;
    private Button checkTab;

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
