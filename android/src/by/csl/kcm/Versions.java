package by.csl.kcm;

/**
 * Версия приложения и адрес, откуда оно обновляется.
 *
 * APP_VERSION должна совпадать с version.go и AndroidManifest.xml — это
 * проверяет скрипт сборки APK до компиляции.
 *
 * VERSION_CODE считается по схеме major·10000 + minor·100 + patch, чтобы
 * Android мог сравнивать сборки: 4.9.3 → 40903, 4.10.0 → 41000. Номер обязан
 * расти с каждым выпуском, иначе телефон откажется ставить APK «поверх».
 */
final class Versions {
    static final String APP_VERSION = "4.9.5";
    static final int VERSION_CODE = 40905;

    /** Репозиторий, из которого берутся обновления. */
    static final String REPO = "zigorminsk-debug/jiraHelp";

    private Versions() {
    }

    /** versionCode по версии вида «4.9.3». */
    static int codeOf(String version) {
        int[] p = parse(version);
        return p[0] * 10000 + p[1] * 100 + p[2];
    }

    /** Разбирает «4.9.3» в {4, 9, 3}; мусор превращается в нули. */
    static int[] parse(String version) {
        int[] out = new int[3];
        if (version == null) {
            return out;
        }
        String clean = version.trim();
        if (clean.startsWith("v") || clean.startsWith("V")) {
            clean = clean.substring(1);
        }
        // отрезаем возможный суффикс: «4.9.3-beta» → «4.9.3»
        int cut = clean.indexOf('-');
        if (cut > 0) {
            clean = clean.substring(0, cut);
        }
        String[] parts = clean.split("\\.");
        for (int i = 0; i < 3 && i < parts.length; i++) {
            try {
                out[i] = Integer.parseInt(parts[i].trim());
            } catch (NumberFormatException ignored) {
                out[i] = 0;
            }
        }
        return out;
    }
}
