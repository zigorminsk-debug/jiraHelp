package by.csl.kcm;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Небольшие помощники для сборки интерфейса кодом.
 *
 * Приложение сознательно не тянет AndroidX/Material: APK собирается без Gradle
 * и без интернета, поэтому весь UI — обычные View из платформы.
 */
final class Ui {

    static final int BG = Color.parseColor("#0B1220");
    static final int CARD = Color.parseColor("#131C2E");
    static final int STROKE = Color.parseColor("#253048");
    static final int TEXT = Color.parseColor("#E2E8F0");
    static final int MUTED = Color.parseColor("#93A4C3");
    static final int ACCENT = Color.parseColor("#2563EB");
    static final int OK = Color.parseColor("#34D399");
    static final int WARN = Color.parseColor("#FBBF24");
    static final int BAD = Color.parseColor("#F87171");

    private Ui() {
    }

    static int dp(Context c, float value) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value,
                c.getResources().getDisplayMetrics()));
    }

    static LinearLayout card(Context c) {
        LinearLayout box = new LinearLayout(c);
        box.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(CARD);
        bg.setCornerRadius(dp(c, 14));
        bg.setStroke(dp(c, 1), STROKE);
        box.setBackground(bg);
        int pad = dp(c, 14);
        box.setPadding(pad, pad, pad, pad);
        return box;
    }

    static LinearLayout.LayoutParams lp(int width, int height) {
        return new LinearLayout.LayoutParams(width, height);
    }

    static LinearLayout.LayoutParams lpMatch() {
        return new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    static TextView title(Context c, String text, float size) {
        TextView t = new TextView(c);
        t.setText(text);
        t.setTextColor(TEXT);
        t.setTextSize(size);
        t.setTypeface(t.getTypeface(), android.graphics.Typeface.BOLD);
        return t;
    }

    static TextView text(Context c, String text, int color, float size) {
        TextView t = new TextView(c);
        t.setText(text);
        t.setTextColor(color);
        t.setTextSize(size);
        return t;
    }

    static Button button(Context c, String text, boolean primary) {
        Button b = new Button(c);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextSize(15f);
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(c, 10));
        if (primary) {
            bg.setColor(ACCENT);
            b.setTextColor(Color.WHITE);
        } else {
            bg.setColor(Color.TRANSPARENT);
            bg.setStroke(dp(c, 1), STROKE);
            b.setTextColor(TEXT);
        }
        b.setBackground(bg);
        b.setPadding(dp(c, 14), dp(c, 10), dp(c, 14), dp(c, 10));
        return b;
    }

    static EditText input(Context c, String hint, int inputType) {
        EditText e = new EditText(c);
        e.setHint(hint);
        e.setInputType(inputType);
        e.setTextColor(TEXT);
        e.setHintTextColor(Color.parseColor("#64748B"));
        e.setTextSize(16f);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.parseColor("#0F172A"));
        bg.setCornerRadius(dp(c, 10));
        bg.setStroke(dp(c, 1), STROKE);
        e.setBackground(bg);
        e.setPadding(dp(c, 12), dp(c, 10), dp(c, 12), dp(c, 10));
        return e;
    }

    static TextView bullet(Context c, String text, int color) {
        TextView t = text(c, text, color, 13.5f);
        t.setLineSpacing(dp(c, 3), 1f);
        t.setPadding(dp(c, 10), dp(c, 7), dp(c, 10), dp(c, 7));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.parseColor("#0F172A"));
        bg.setCornerRadius(dp(c, 8));
        t.setBackground(bg);
        LinearLayout.LayoutParams p = lpMatch();
        p.bottomMargin = dp(c, 6);
        t.setLayoutParams(p);
        return t;
    }

    static View spacer(Context c, int heightDp) {
        View v = new View(c);
        v.setLayoutParams(lp(LinearLayout.LayoutParams.MATCH_PARENT, dp(c, heightDp)));
        return v;
    }

    static TextView badge(Context c, String text, int color) {
        TextView t = text(c, text, color, 12.5f);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.TRANSPARENT);
        bg.setCornerRadius(dp(c, 20));
        bg.setStroke(dp(c, 1), color);
        t.setBackground(bg);
        t.setPadding(dp(c, 9), dp(c, 4), dp(c, 9), dp(c, 4));
        t.setGravity(Gravity.CENTER);
        return t;
    }
}
