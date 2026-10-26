package by.csl.kcm;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.text.InputType;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

/**
 * «Пульт» — управление программой KerioCertManager, запущенной на компьютере.
 *
 * Телефон и компьютер должны быть в одной сети Wi-Fi. На компьютере
 * включается карточка «📱 Android-пульт»: она показывает адрес и код из
 * 6 цифр. Здесь мы вводим адрес и код и открываем настоящий интерфейс
 * программы внутри WebView — то есть на телефоне доступны все вкладки,
 * выпуск сертификата, установка в Kerio и инструкция.
 */
final class RemotePane extends LinearLayout {

    private static final String PREFS = "kcm_mobile";
    private static final String KEY_ADDR = "remote_addr";
    private static final String KEY_CODE = "remote_code";

    private final Activity activity;
    private EditText addrInput;
    private EditText codeInput;
    private LinearLayout formBox;
    private LinearLayout webBox;
    private WebView webView;
    private final List<String> history = new ArrayList<String>();

    RemotePane(Activity activity) {
        super(activity);
        this.activity = activity;
        setOrientation(VERTICAL);
        setBackgroundColor(Ui.BG);

        formBox = new LinearLayout(activity);
        formBox.setOrientation(VERTICAL);
        formBox.setPadding(Ui.dp(activity, 14), Ui.dp(activity, 14), Ui.dp(activity, 14), Ui.dp(activity, 14));

        webBox = new LinearLayout(activity);
        webBox.setOrientation(VERTICAL);
        webBox.setVisibility(GONE);
        webBox.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.MATCH_PARENT));

        buildForm();
        addView(formBox, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        addView(webBox, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.MATCH_PARENT));
    }

    private void buildForm() {
        LinearLayout intro = Ui.card(activity);
        intro.addView(Ui.title(activity, "📱 Управление с телефона", 17));
        TextView hint = Ui.text(activity,
                "1. На компьютере откройте вкладку «2. Установка в Kerio» → карточку «📱 Android-пульт» "
                        + "и нажмите «Включить пульт».\n"
                        + "2. Напишите здесь адрес, который показал компьютер (например 192.168.1.5:17840), "
                        + "и код из 6 цифр.\n"
                        + "3. Нажмите «Подключиться» — откроется сама программа.",
                Ui.MUTED, 13.5f);
        hint.setLineSpacing(Ui.dp(activity, 3), 1f);
        hint.setPadding(0, Ui.dp(activity, 8), 0, Ui.dp(activity, 12));
        intro.addView(hint);

        SharedPreferences p = activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE);

        addrInput = Ui.input(activity, "192.168.1.5:17840", InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_VARIATION_URI);
        addrInput.setText(p.getString(KEY_ADDR, ""));
        addrInput.setSingleLine(true);
        intro.addView(addrInput, withTop(10));

        codeInput = Ui.input(activity, "Код из 6 цифр", InputType.TYPE_CLASS_NUMBER);
        codeInput.setText(p.getString(KEY_CODE, ""));
        codeInput.setSingleLine(true);
        intro.addView(codeInput, withTop(10));

        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(HORIZONTAL);
        row.setPadding(0, Ui.dp(activity, 14), 0, 0);

        Button connect = Ui.button(activity, "Подключиться", true);
        connect.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                connectClicked();
            }
        });
        row.addView(connect, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button newer = Ui.button(activity, "Другой адрес", false);
        newer.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                showForm();
            }
        });
        LinearLayout.LayoutParams np = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        np.leftMargin = Ui.dp(activity, 8);
        row.addView(newer, np);
        intro.addView(row);

        formBox.addView(intro, Ui.lpMatch());

        LinearLayout tips = Ui.card(activity);
        LinearLayout.LayoutParams tp = Ui.lpMatch();
        tp.topMargin = Ui.dp(activity, 12);
        tips.setLayoutParams(tp);
        tips.addView(Ui.title(activity, "Если не подключается", 15));
        tips.addView(Ui.bullet(activity, "• Компьютер и телефон должны быть в ОДНОЙ сети Wi-Fi "
                + "(гостевая сеть и мобильный интернет не подходят).", Ui.MUTED));
        tips.addView(Ui.bullet(activity, "• На компьютере разрешите программе доступ к сети в окне "
                + "брандмауэра Windows (сеть «частная»).", Ui.MUTED));
        tips.addView(Ui.bullet(activity, "• Адрес берётся из карточки «Android-пульт» — не вводите "
                + "127.0.0.1: это адрес самого компьютера.", Ui.MUTED));
        tips.addView(Ui.bullet(activity, "• Пульт выключается кнопкой на компьютере; тогда телефон "
                + "больше не сможет подключиться.", Ui.MUTED));
        formBox.addView(tips, Ui.lpMatch());
    }

    private LinearLayout.LayoutParams withTop(int topDp) {
        LinearLayout.LayoutParams p = Ui.lpMatch();
        p.topMargin = Ui.dp(activity, topDp);
        return p;
    }

    /** Приводит ввод к виду http://host:port и загружает интерфейс программы. */
    private String buildUrl(String rawAddr, String code) {
        String a = rawAddr == null ? "" : rawAddr.trim();
        if (a.isEmpty()) {
            return null;
        }
        if (!a.startsWith("http://") && !a.startsWith("https://")) {
            a = "http://" + a;
        }
        if (!a.endsWith("/")) {
            a = a + "/";
        }
        if (code != null && code.trim().length() > 0) {
            a = a + "?code=" + code.trim();
        }
        return a;
    }

    private void connectClicked() {
        String url = buildUrl(addrInput.getText().toString(), codeInput.getText().toString());
        if (url == null) {
            Toast.makeText(activity, "Введите адрес из карточки «Android-пульт»", Toast.LENGTH_LONG).show();
            return;
        }
        SharedPreferences.Editor e = activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit();
        e.putString(KEY_ADDR, addrInput.getText().toString().trim());
        e.putString(KEY_CODE, codeInput.getText().toString().trim());
        e.apply();

        InputMethodManager imm = (InputMethodManager) activity.getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) {
            imm.hideSoftInputFromWindow(addrInput.getWindowToken(), 0);
        }
        openWeb(url);
    }

    private void openWeb(String url) {
        formBox.setVisibility(GONE);
        if (webView == null) {
            webView = new WebView(activity);
            WebSettings s = webView.getSettings();
            s.setJavaScriptEnabled(true);
            s.setDomStorageEnabled(true);
            s.setLoadWithOverviewMode(false);
            s.setUseWideViewPort(true);
            s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
            s.setCacheMode(WebSettings.LOAD_NO_CACHE);
            webView.setWebViewClient(new WebViewClient() {
                @Override
                public boolean shouldOverrideUrlLoading(WebView view, String u) {
                    history.add(u);
                    return false;
                }
            });
            webBox.addView(webView, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        }
        webBox.setVisibility(VISIBLE);
        webView.loadUrl(url);
    }

    void showForm() {
        if (webView != null) {
            webView.loadUrl("about:blank");
        }
        webBox.setVisibility(GONE);
        formBox.setVisibility(VISIBLE);
    }

    /** Возврат из WebView историей, иначе — к форме подключения. */
    boolean handleBack() {
        if (webView != null && webBox.getVisibility() == VISIBLE) {
            if (webView.canGoBack() && !history.isEmpty()) {
                history.remove(history.size() - 1);
                webView.goBack();
                return true;
            }
            showForm();
            return true;
        }
        return false;
    }

    /** При выходе из приложения освобождаем WebView — иначе он держит память. */
    void shutdown() {
        if (webView != null) {
            webBox.removeView(webView);
            webView.destroy();
            webView = null;
        }
    }
}
