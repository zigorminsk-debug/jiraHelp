#!/usr/bin/env bash
# build-apk.sh — сборка APK без Gradle и без интернета.
#
# Зачем без Gradle: проект состоит из нескольких Java-файлов и одной ресурсной
# папки. Gradle потребовал бы скачать сотни мегабайт зависимостей, а сервер,
# где собирается релиз, должен быть воспроизводимым. Здесь используются только
# инструменты Android SDK (aapt, d8, zipalign, apksigner) и javac из JDK.
#
# Что делает скрипт:
#   1. проверяет, что версия в Versions.java, AndroidManifest.xml и version.go
#      совпадает — иначе APK «отстанет» от программы;
#   2. компилирует ресурсы через aapt (R.java + resources.apk);
#   3. компилирует Java, переводит классы в dex, склеивает APK;
#   4. выравнивает (zipalign) и подписывает; ключ можно передать секретами
#      (KCM_KEYSTORE_BASE64 / KCM_KEYSTORE_PASS / KCM_KEY_ALIAS), иначе
#      генерируется одноразовый отладочный ключ.
#
# Использование:
#   ANDROID_SDK_ROOT=/path/to/sdk bash android/build-apk.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"

SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
: "${SDK:?Задайте ANDROID_SDK_ROOT или ANDROID_HOME}"
PLATFORM="${ANDROID_PLATFORM:-android-34}"
TOOLS="${ANDROID_BUILD_TOOLS:-35.0.0}"
BT="$SDK/build-tools/$TOOLS"
JAR="$SDK/platforms/$PLATFORM/android.jar"

for tool in aapt d8 zipalign apksigner; do
  [[ -x "$BT/$tool" ]] || { echo "Нет инструмента: $BT/$tool" >&2; exit 1; }
done
[[ -f "$JAR" ]] || { echo "Нет платформы: $JAR" >&2; exit 1; }
command -v javac >/dev/null || { echo "Нет javac — установите JDK 17" >&2; exit 1; }
command -v keytool >/dev/null || { echo "Нет keytool — установите JDK 17" >&2; exit 1; }

# --- 1. Версии должны совпадать -------------------------------------------
APP_VER="$(awk -F'"' '/^const appVersion = "/{print $2; exit}' kerio-letsencrypt-win/version.go)"
JAVA_VER="$(sed -n 's/.*APP_VERSION = "\([0-9.]*\)".*/\1/p' android/src/by/csl/kcm/Versions.java)"
MANIFEST_VER="$(sed -n 's/.*android:versionName="\([0-9.]*\)".*/\1/p' android/AndroidManifest.xml)"
if [[ "$APP_VER" != "$JAVA_VER" || "$APP_VER" != "$MANIFEST_VER" ]]; then
  echo "Версии расходятся: version.go=$APP_VER Versions.java=$JAVA_VER AndroidManifest=$MANIFEST_VER" >&2
  exit 1
fi
echo "Версия приложения: $APP_VER"

OUT="$ROOT/build/android"
rm -rf "$OUT"
mkdir -p "$OUT/gen" "$OUT/classes" "$OUT/dex"

# --- 2. Ресурсы ------------------------------------------------------------
"$BT/aapt" package -f -m -J "$OUT/gen" \
  -M android/AndroidManifest.xml \
  -S android/res \
  -I "$JAR" \
  -F "$OUT/resources.apk"

# --- 3. Компиляция ---------------------------------------------------------
find android/src "$OUT/gen" -name '*.java' -print | sort > "$OUT/sources.txt"
javac -encoding UTF-8 -source 8 -target 8 -nowarn \
  -bootclasspath "$JAR:$BT/core-lambda-stubs.jar" \
  -d "$OUT/classes" @"$OUT/sources.txt"

find "$OUT/classes" -name '*.class' -print | sort > "$OUT/classes.txt"
"$BT/d8" --lib "$JAR" --min-api 21 --output "$OUT/dex" @"$OUT/classes.txt"

cp "$OUT/resources.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && "$BT/aapt" add "$OUT/unsigned.apk" classes.dex)
"$BT/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"

# --- 4. Подпись ------------------------------------------------------------
APK_NAME="KerioCertManager-Mobile-${APP_VER}.apk"
if [[ -n "${KCM_KEYSTORE_BASE64:-}" ]]; then
  echo "Подпись: ключ из секретов репозитория"
  echo "$KCM_KEYSTORE_BASE64" | base64 -d > "$OUT/release.keystore"
  "$BT/apksigner" sign \
    --ks "$OUT/release.keystore" \
    --ks-pass "pass:${KCM_KEYSTORE_PASS:?}" \
    --key-pass "pass:${KCM_KEYSTORE_PASS:?}" \
    --ks-key-alias "${KCM_KEY_ALIAS:-keriocertmanager}" \
    --out "$OUT/$APK_NAME" "$OUT/aligned.apk"
  rm -f "$OUT/release.keystore"
else
  # Одноразовый ключ: подходит для тестов и ручной установки, но обновление
  # поверх другой подписи Android не примет — нужно переустановить приложение.
  echo "Подпись: одноразовый отладочный ключ (секреты не заданы)"
  keytool -genkeypair -noprompt -keystore "$OUT/debug.keystore" \
    -storepass android -keypass android -alias keriocertmanager \
    -dname 'CN=KerioCertManager Mobile,O=Zakharevich I.,C=BY' \
    -keyalg RSA -keysize 2048 -validity 3650
  "$BT/apksigner" sign --ks "$OUT/debug.keystore" \
    --ks-pass pass:android --key-pass pass:android \
    --ks-key-alias keriocertmanager --out "$OUT/$APK_NAME" "$OUT/aligned.apk"
fi

"$BT/apksigner" verify --verbose --print-certs "$OUT/$APK_NAME" > "$OUT/signature.txt"
"$BT/aapt" dump badging "$OUT/$APK_NAME" | sed -n '1,6p'
(cd "$OUT" && sha256sum "$APK_NAME" | tee "$APK_NAME.sha256")
echo "APK: $OUT/$APK_NAME"
