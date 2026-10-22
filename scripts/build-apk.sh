#!/usr/bin/env bash
# Build the existing dependency-free Android project, without Gradle.
set -euo pipefail
cd "$(dirname "$0")/.."
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
: "${SDK:?Set ANDROID_SDK_ROOT or ANDROID_HOME}"
PLATFORM="${ANDROID_PLATFORM:-android-33}"
TOOLS="${ANDROID_BUILD_TOOLS:-35.0.0}"
BT="$SDK/build-tools/$TOOLS"
JAR="$SDK/platforms/$PLATFORM/android.jar"
for tool in aapt d8 zipalign apksigner; do
  [[ -x "$BT/$tool" ]] || { echo "Missing SDK tool: $BT/$tool" >&2; exit 1; }
done
[[ -f "$JAR" ]] || { echo "Missing platform: $JAR" >&2; exit 1; }
command -v javac >/dev/null
command -v keytool >/dev/null
OUT="$PWD/build/android"
rm -rf "$OUT"
mkdir -p "$OUT/gen" "$OUT/classes" "$OUT/dex"
"$BT/aapt" package -f -m -J "$OUT/gen" -M helpdesk-apk/AndroidManifest.xml \
  -S helpdesk-apk/res -A helpdesk-apk/assets -I "$JAR" -F "$OUT/resources.apk"
find helpdesk-apk/src "$OUT/gen" -name '*.java' -print | sort > "$OUT/sources.txt"
javac -encoding UTF-8 -source 8 -target 8 -bootclasspath "$JAR" -d "$OUT/classes" @"$OUT/sources.txt"
find "$OUT/classes" -name '*.class' -print | sort > "$OUT/classes.txt"
"$BT/d8" --lib "$JAR" --min-api 21 --output "$OUT/dex" @"$OUT/classes.txt"
cp "$OUT/resources.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && "$BT/aapt" add "$OUT/unsigned.apk" classes.dex)
"$BT/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
# Disposable debug signing only. No private key or password from the repository.
keytool -genkeypair -noprompt -keystore "$OUT/debug.keystore" -storepass android \
  -keypass android -alias androiddebugkey -dname 'CN=Android Debug,O=Android,C=US' \
  -keyalg RSA -keysize 2048 -validity 3650
"$BT/apksigner" sign --ks "$OUT/debug.keystore" --ks-pass pass:android \
  --key-pass pass:android --out "$OUT/CSL-HelpDesk-debug.apk" "$OUT/aligned.apk"
"$BT/apksigner" verify --verbose "$OUT/CSL-HelpDesk-debug.apk"
"$BT/aapt" dump badging "$OUT/CSL-HelpDesk-debug.apk"
echo "APK: $OUT/CSL-HelpDesk-debug.apk"
