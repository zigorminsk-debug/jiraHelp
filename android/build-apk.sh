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
# Ошибки компиляции печатаем ещё и аннотациями GitHub Actions: так их видно
# в интерфейсе проверки даже когда полный лог недоступен.
run_step() {
  local log="$1"; shift
  if "$@" > "$log" 2>&1; then
    cat "$log"
    return 0
  fi
  cat "$log"
  grep -E 'error:|Error:|FAILED|Exception' "$log" | head -25 | while IFS= read -r line; do
    echo "::error::${line}"
  done
  return 1
}

run_step "$OUT/javac.log" javac -encoding UTF-8 -source 8 -target 8 -nowarn \
  -bootclasspath "$JAR:$BT/core-lambda-stubs.jar" \
  -d "$OUT/classes" @"$OUT/sources.txt" || exit 1

find "$OUT/classes" -name '*.class' -print | sort > "$OUT/classes.txt"
run_step "$OUT/d8.log" "$BT/d8" --lib "$JAR" --min-api 21 --output "$OUT/dex" @"$OUT/classes.txt" || exit 1

cp "$OUT/resources.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && "$BT/aapt" add "$OUT/unsigned.apk" classes.dex)
"$BT/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"

# --- 4. Подпись ------------------------------------------------------------
# Ключ постоянный: без него Android не поставит обновление «поверх».
#   1) секреты репозитория (если заданы) — приоритет;
#   2) файл android/keystore/kcm-release.p12 + keystore.properties;
#   3) одноразовый ключ — только если ничего не нашлось (сборка не для релиза).
APK_NAME="KerioCertManager-Mobile-${APP_VER}.apk"
KS_DIR="android/keystore"
EXPECTED_SHA=""

if [[ -n "${KCM_KEYSTORE_BASE64:-}" ]]; then
  echo "Подпись: ключ из секретов репозитория"
  echo "$KCM_KEYSTORE_BASE64" | base64 -d > "$OUT/release.keystore"
  KS_PATH="$OUT/release.keystore"
  KS_PASS="${KCM_KEYSTORE_PASS:?Нужен KCM_KEYSTORE_PASS}"
  KS_ALIAS="${KCM_KEY_ALIAS:-keriocertmanager}"
  [[ -f "$KS_DIR/keystore.properties" ]] && EXPECTED_SHA="$(sed -n 's/^sha256=//p' "$KS_DIR/keystore.properties")"
elif [[ -f "$KS_DIR/kcm-release.p12" && -f "$KS_DIR/keystore.properties" ]]; then
  echo "Подпись: постоянный ключ из $KS_DIR"
  KS_PATH="$KS_DIR/kcm-release.p12"
  KS_PASS="${KCM_KEYSTORE_PASS:-$(sed -n 's/^storePassword=//p' "$KS_DIR/keystore.properties")}"
  KS_ALIAS="${KCM_KEY_ALIAS:-$(sed -n 's/^keyAlias=//p' "$KS_DIR/keystore.properties")}"
  EXPECTED_SHA="$(sed -n 's/^sha256=//p' "$KS_DIR/keystore.properties")"
  [[ -n "$KS_PASS" ]] || { echo "В keystore.properties нет storePassword" >&2; exit 1; }
else
  # Временный ключ: подходит для ручной проверки, но обновление поверх другой
  # подписи Android не примет — приложение придётся удалить и поставить заново.
  echo "::warning::Подпись: одноразовый ключ — постоянный ключ не найден"
  KS_PATH="$OUT/debug.keystore"
  KS_PASS="android"
  KS_ALIAS="keriocertmanager"
  keytool -genkeypair -noprompt -keystore "$KS_PATH" \
    -storepass "$KS_PASS" -keypass "$KS_PASS" -alias "$KS_ALIAS" \
    -dname 'CN=KerioCertManager Mobile,O=Zakharevich I.,C=BY' \
    -keyalg RSA -keysize 2048 -validity 3650
fi

run_step "$OUT/sign.log" "$BT/apksigner" sign \
  --ks "$KS_PATH" \
  --ks-pass "pass:$KS_PASS" \
  --key-pass "pass:$KS_PASS" \
  --ks-key-alias "$KS_ALIAS" \
  --out "$OUT/$APK_NAME" "$OUT/aligned.apk" || exit 1

[[ -f "$OUT/release.keystore" ]] && rm -f "$OUT/release.keystore"

"$BT/apksigner" verify --verbose --print-certs "$OUT/$APK_NAME" > "$OUT/signature.txt"
"$BT/aapt" dump badging "$OUT/$APK_NAME" | sed -n '1,6p'

# --- 5. Проверка подписи ---------------------------------------------------
# apksigner печатает отпечаток без двоеточий и в нижнем регистре,
# а в keystore.properties он записан в привычном виде — сравниваем нормализованно.
ACTUAL_SHA="$(sed -n 's/^Signer #1 certificate SHA-256 digest: //p' "$OUT/signature.txt" | head -1 | tr -d ':' | tr 'A-Z' 'a-z')"
EXPECTED_NORM="$(printf '%s' "$EXPECTED_SHA" | tr -d ':' | tr 'A-Z' 'a-z')"
echo "Отпечаток подписи SHA-256: ${ACTUAL_SHA:-не определён}"
if [[ -n "$EXPECTED_NORM" && -n "$ACTUAL_SHA" && "$ACTUAL_SHA" != "$EXPECTED_NORM" ]]; then
  echo "::error::APK подписан не тем ключом. Ожидался $EXPECTED_SHA, получен $ACTUAL_SHA"
  echo "Подпись не совпадает с ожидаемой — обновление не установится поверх." >&2
  exit 1
fi
grep -q 'Verified using v2 scheme.*true\|Verified using v1 scheme.*true\|Verified using v3 scheme.*true' \
  "$OUT/signature.txt" || echo "::warning::apksigner не подтвердил ни одну схему подписи"

(cd "$OUT" && sha256sum "$APK_NAME" | tee "$APK_NAME.sha256")
echo "APK: $OUT/$APK_NAME"
