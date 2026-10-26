package by.csl.kcm;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

/**
 * «Проверка» — автономная диагностика домена прямо с телефона.
 *
 * Работает без компьютера: SSL-сертификат, DNS (MX/SPF/DMARC), почтовые порты
 * и спам-базы. Это те же проверки, что и в настольной программе, но
 * упрощённые — телефон не умеет выпускать сертификаты и менять Kerio.
 */
final class CheckPane extends LinearLayout {

    private final Activity activity;
    private EditText domainInput;
    private Button runButton;
    private LinearLayout results;
    private ScrollView scroll;
    private List<Checks.Section> lastResult = new ArrayList<Checks.Section>();
    private String lastDomain = "";

    CheckPane(Activity activity) {
        super(activity);
        this.activity = activity;
        setOrientation(VERTICAL);
        setBackgroundColor(Ui.BG);
        build();
    }

    private void build() {
        LinearLayout form = Ui.card(activity);
        LinearLayout.LayoutParams fp = Ui.lpMatch();
        fp.leftMargin = Ui.dp(activity, 14);
        fp.rightMargin = Ui.dp(activity, 14);
        fp.topMargin = Ui.dp(activity, 14);
        form.setLayoutParams(fp);

        form.addView(Ui.title(activity, "🔎 Проверка домена и почты", 17));
        TextView hint = Ui.text(activity,
                "Работает без компьютера. Проверяются: SSL-сертификат, DNS-записи "
                        + "(MX, SPF, DMARC), почтовые порты и попадание в спам-базы.",
                Ui.MUTED, 13f);
        hint.setPadding(0, Ui.dp(activity, 6), 0, Ui.dp(activity, 12));
        form.addView(hint);

        domainInput = Ui.input(activity, "mail.example.com", InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_VARIATION_URI);
        domainInput.setSingleLine(true);
        form.addView(domainInput, Ui.lpMatch());

        LinearLayout row = new LinearLayout(activity);
        row.setOrientation(HORIZONTAL);
        LinearLayout.LayoutParams rp = Ui.lpMatch();
        rp.topMargin = Ui.dp(activity, 12);
        row.setLayoutParams(rp);

        runButton = Ui.button(activity, "Проверить", true);
        runButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                startCheck();
            }
        });
        row.addView(runButton, new LinearLayout.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));

        Button copy = Ui.button(activity, "📋 Отчёт", false);
        copy.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                copyReport();
            }
        });
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(
                LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
        cp.leftMargin = Ui.dp(activity, 8);
        row.addView(copy, cp);

        form.addView(row);
        addView(form, Ui.lpMatch());

        scroll = new ScrollView(activity);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(
                LayoutParams.MATCH_PARENT, 0, 1f);
        sp.topMargin = Ui.dp(activity, 12);
        scroll.setLayoutParams(sp);
        scroll.setPadding(Ui.dp(activity, 14), 0, Ui.dp(activity, 14), Ui.dp(activity, 14));

        results = new LinearLayout(activity);
        results.setOrientation(VERTICAL);
        scroll.addView(results, Ui.lpMatch());
        addView(scroll);
    }

    private void startCheck() {
        final String domain = Checks.normalizeDomain(domainInput.getText().toString());
        if (domain.isEmpty()) {
            Toast.makeText(activity, "Введите домен, например mail.example.com", Toast.LENGTH_LONG).show();
            return;
        }
        runButton.setEnabled(false);
        runButton.setText("Проверяю…");
        results.removeAllViews();
        results.addView(Ui.text(activity, "Идёт проверка " + domain
                + ": SSL → DNS → порты → спам-базы… Это занимает до 30 секунд.", Ui.MUTED, 13f));

        new Thread(new Runnable() {
            @Override
            public void run() {
                final List<Checks.Section> sections = Checks.runAll(domain);
                activity.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        lastResult = sections;
                        lastDomain = domain;
                        render(sections);
                        runButton.setEnabled(true);
                        runButton.setText("Проверить");
                    }
                });
            }
        }).start();
    }

    private void render(List<Checks.Section> sections) {
        results.removeAllViews();
        int problems = 0;
        int warnings = 0;
        for (Checks.Section s : sections) {
            for (Checks.Line l : s.lines) {
                if ("fail".equals(l.status)) {
                    problems++;
                } else if ("warn".equals(l.status)) {
                    warnings++;
                }
            }
        }

        LinearLayout summary = Ui.card(activity);
        String verdict;
        int color;
        if (problems > 0) {
            verdict = "Найдено проблем: " + problems;
            color = Ui.BAD;
        } else if (warnings > 0) {
            verdict = "Критичных проблем нет, замечаний: " + warnings;
            color = Ui.WARN;
        } else {
            verdict = "Всё в порядке";
            color = Ui.OK;
        }
        summary.addView(Ui.title(activity, verdict, 16));
        TextView sub = Ui.text(activity, lastDomain + " · проверено с телефона", Ui.MUTED, 12.5f);
        sub.setPadding(0, Ui.dp(activity, 4), 0, 0);
        summary.addView(sub);
        TextView v = Ui.text(activity, verdict, color, 13f);
        v.setVisibility(GONE);
        summary.addView(v);
        results.addView(summary);

        for (Checks.Section s : sections) {
            LinearLayout card = Ui.card(activity);
            LinearLayout.LayoutParams p = Ui.lpMatch();
            p.topMargin = Ui.dp(activity, 10);
            card.setLayoutParams(p);
            card.addView(Ui.title(activity, s.title, 15f));
            for (Checks.Line l : s.lines) {
                card.addView(Ui.bullet(activity, icon(l.status) + " " + l.title
                        + (l.detail.isEmpty() ? "" : "\n" + l.detail), colorOf(l.status)));
            }
            results.addView(card);
        }

        LinearLayout footer = Ui.card(activity);
        LinearLayout.LayoutParams fp = Ui.lpMatch();
        fp.topMargin = Ui.dp(activity, 10);
        footer.setLayoutParams(fp);
        footer.addView(Ui.title(activity, "Что телефон не умеет", 14f));
        footer.addView(Ui.bullet(activity, "• Выпуск сертификата Let's Encrypt и установку в Kerio "
                + "делает программа на компьютере — телефон не хранит ключи.", Ui.MUTED));
        footer.addView(Ui.bullet(activity, "• Полная диагностика Kerio Admin API доступна в режиме "
                + "«📱 Пульт», когда телефон в одной сети с компьютером.", Ui.MUTED));
        results.addView(footer);
    }

    private static String icon(String status) {
        if ("ok".equals(status)) {
            return "✅";
        }
        if ("warn".equals(status)) {
            return "⚠️";
        }
        if ("fail".equals(status)) {
            return "❌";
        }
        return "ℹ️";
    }

    private static int colorOf(String status) {
        if ("ok".equals(status)) {
            return Ui.OK;
        }
        if ("warn".equals(status)) {
            return Ui.WARN;
        }
        if ("fail".equals(status)) {
            return Ui.BAD;
        }
        return Ui.MUTED;
    }

    private String buildReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("KerioCertManager Mobile ").append(Versions.APP_VERSION)
                .append(" — отчёт о проверке\n");
        sb.append("Домен: ").append(lastDomain).append("\n");
        sb.append("Дата: ").append(android.text.format.DateFormat
                .format("dd.MM.yyyy HH:mm", System.currentTimeMillis())).append("\n\n");
        for (Checks.Section s : lastResult) {
            sb.append("== ").append(s.title).append(" ==\n");
            for (Checks.Line l : s.lines) {
                sb.append("[").append(l.status.toUpperCase()).append("] ")
                        .append(l.title).append(": ").append(l.detail).append("\n");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    private void copyReport() {
        if (lastResult.isEmpty()) {
            Toast.makeText(activity, "Сначала нажмите «Проверить»", Toast.LENGTH_LONG).show();
            return;
        }
        ClipboardManager cm = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("KerioCertManager", buildReport()));
            Toast.makeText(activity, "Отчёт скопирован в буфер обмена", Toast.LENGTH_SHORT).show();
        }
    }
}
