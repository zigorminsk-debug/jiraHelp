package by.csl.kcm;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.DnsResolver;
import android.net.Network;
import android.os.Build;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * DNS-запрос через системный резолвер телефона (Android 10 и новее).
 *
 * Зачем отдельно от {@link java.net.InetAddress}: у InetAddress нет способа
 * узнать причину — «такого имени нет» и «сеть не ответила» выглядят одинаково
 * (исключение UnknownHostException). Для спам-баз это критично: NXDOMAIN
 * означает «адреса в базе нет», а сбой — «проверить не удалось».
 *
 * Android 10 добавил {@code DnsResolver.rawQuery()}: он отдаёт сырой DNS-ответ
 * вместе с кодом ответа (0 — есть данные, 3 — такого имени нет) и ходит через
 * DNS оператора. То есть работает в мобильной сети там, где DNS-over-HTTPS
 * может быть закрыт или ограничен по частоте запросов.
 *
 * Класс ссылается на API 29, поэтому вызывать его можно только после проверки
 * {@link #supported()} — иначе телефон с Android 5–9 не запустит приложение.
 */
final class DnsSystem {

    /** DNS-код «такого имени нет» (NXDOMAIN). */
    private static final int RCODE_NXDOMAIN = 3;

    private static final int CLASS_IN = 1;
    private static final int TYPE_A = 1;
    private static final int FLAGS_NONE = 0;

    private static final Executor EXECUTOR = Executors.newCachedThreadPool();

    /** Ответ системного резолвера. */
    static final class Reply {
        boolean answered;   // сервер ответил (данные есть или имени нет)
        boolean nxdomain;   // ответ «такого имени нет»
        byte[] raw;         // сырой DNS-ответ
        String error;

        Reply() {
        }
    }

    private DnsSystem() {
    }

    /** Есть ли нужный API: DnsResolver появился в Android 10 (API 29). */
    static boolean supported() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q;
    }

    /**
     * Спрашивает A-запись через системный резолвер.
     * Никогда не бросает исключений: при любой проблеме возвращает пустой
     * ответ, и вызывающий код пробует следующий канал.
     */
    static Reply query(Context context, String name) {
        final Reply out = new Reply();
        if (context == null || !supported() || name == null || name.isEmpty()) {
            out.error = "системный резолвер недоступен";
            return out;
        }
        final CountDownLatch latch = new CountDownLatch(1);
        try {
            Network network = activeNetwork(context);
            DnsResolver resolver = DnsResolver.getInstance();
            resolver.rawQuery(
                    network,
                    name,
                    CLASS_IN,
                    TYPE_A,
                    FLAGS_NONE,
                    EXECUTOR,
                    null,
                    new DnsResolver.Callback<byte[]>() {
                        @Override
                        public void onAnswer(byte[] answer, int rcode) {
                            if (rcode == 0) {
                                out.answered = true;
                                out.raw = answer;
                            } else if (rcode == RCODE_NXDOMAIN) {
                                out.answered = true;
                                out.nxdomain = true;
                            } else {
                                out.error = "код ответа DNS " + rcode;
                            }
                            latch.countDown();
                        }

                        @Override
                        public void onError(DnsResolver.DnsException error) {
                            out.error = error == null ? "ошибка DNS" : ("ошибка DNS: " + error.code);
                            latch.countDown();
                        }
                    });
            if (!latch.await(6, TimeUnit.SECONDS)) {
                out.error = "нет ответа за 6 секунд";
            }
        } catch (Throwable t) {
            // Сюда попадаем на старых телефонах и при гонках с сетью.
            out.answered = false;
            out.error = String.valueOf(t.getMessage());
        }
        return out;
    }

    /** Сеть, через которую спрашивать; null означает «сеть по умолчанию». */
    private static Network activeNetwork(Context context) {
        try {
            ConnectivityManager cm = (ConnectivityManager)
                    context.getSystemService(Context.CONNECTIVITY_SERVICE);
            return cm == null ? null : cm.getActiveNetwork();
        } catch (Throwable t) {
            return null;
        }
    }
}
