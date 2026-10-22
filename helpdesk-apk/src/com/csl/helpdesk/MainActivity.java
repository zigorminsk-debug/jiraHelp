package com.csl.helpdesk;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;
import android.graphics.Color;

public class MainActivity extends Activity {

    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        requestWindowFeature(Window.FEATURE_NO_TITLE);
        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.setStatusBarColor(Color.parseColor("#0d0d1a"));
        window.setNavigationBarColor(Color.parseColor("#1a1a2e"));

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.setDecorFitsSystemWindows(false);
        } else {
            window.getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
            );
        }

        webView = new WebView(this);
        setContentView(webView);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setSupportZoom(false);
        settings.setBuiltInZoomControls(false);
        settings.setDisplayZoomControls(false);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        settings.setMediaPlaybackRequiresUserGesture(false);

        webView.setBackgroundColor(Color.parseColor("#0d0d1a"));
        webView.setWebViewClient(new WebViewClient());
        webView.setWebChromeClient(new WebChromeClient());

        // Add JavaScript bridge
        webView.addJavascriptInterface(new AndroidBridge(), "AndroidBridge");

        webView.loadUrl("file:///android_asset/index.html");
    }

    // Bridge class for JS ↔ Android communication
    public class AndroidBridge {

        @JavascriptInterface
        public void shareTicket(String title, String text) {
            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType("text/plain");
            shareIntent.putExtra(Intent.EXTRA_SUBJECT, title);
            shareIntent.putExtra(Intent.EXTRA_TEXT, text);
            startActivity(Intent.createChooser(shareIntent, "Поделиться через..."));
        }

        @JavascriptInterface
        public void shareToTelegram(String text) {
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.setPackage("org.telegram.messenger");
            intent.putExtra(Intent.EXTRA_TEXT, text);
            try {
                startActivity(Intent.createChooser(intent, "Отправить в Telegram"));
            } catch (ActivityNotFoundException e) {
                runOnUiThread(() -> Toast.makeText(MainActivity.this, "Telegram не установлен", Toast.LENGTH_SHORT).show());
            }
        }

        @JavascriptInterface
        public void shareToViber(String text) {
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.setPackage("com.viber.voip");
            intent.putExtra(Intent.EXTRA_TEXT, text);
            try {
                startActivity(Intent.createChooser(intent, "Отправить в Viber"));
            } catch (ActivityNotFoundException e) {
                runOnUiThread(() -> Toast.makeText(MainActivity.this, "Viber не установлен", Toast.LENGTH_SHORT).show());
            }
        }

        @JavascriptInterface
        public void shareToWhatsApp(String text) {
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.setPackage("com.whatsapp");
            intent.putExtra(Intent.EXTRA_TEXT, text);
            try {
                startActivity(Intent.createChooser(intent, "Отправить в WhatsApp"));
            } catch (ActivityNotFoundException e) {
                runOnUiThread(() -> Toast.makeText(MainActivity.this, "WhatsApp не установлен", Toast.LENGTH_SHORT).show());
            }
        }

        @JavascriptInterface
        public void callPhone(String number) {
            Intent intent = new Intent(Intent.ACTION_DIAL);
            intent.setData(Uri.parse("tel:" + number));
            try {
                startActivity(intent);
            } catch (ActivityNotFoundException e) {
                runOnUiThread(() -> Toast.makeText(MainActivity.this, "Телефон недоступен", Toast.LENGTH_SHORT).show());
            }
        }

        @JavascriptInterface
        public void copyToClipboard(String text) {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText("ticket", text);
            clipboard.setPrimaryClip(clip);
            runOnUiThread(() -> Toast.makeText(MainActivity.this, "Скопировано в буфер обмена", Toast.LENGTH_SHORT).show());
        }
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
