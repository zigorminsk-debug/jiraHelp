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

/** Local, offline WebView shell. No Jira REST implementation was supplied. */
public class MainActivity extends Activity {
    private static final String HOME = "file:///android_asset/index.html";
    private WebView webView;

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
        if (webView != null) {
            webView.removeJavascriptInterface("AndroidBridge");
            webView.stopLoading();
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }
}
