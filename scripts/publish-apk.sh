#!/usr/bin/env bash
# Releases assets do not consume the Actions Artifacts storage quota.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}" "${GITHUB_SHA:?}" "${GH_REPO:?}"
OUT="$PWD/build/android"
APK=CSL-HelpDesk-debug.apk
TAG="apk-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
[[ -s "$OUT/$APK" && -s "$OUT/signature.txt" ]]
(cd "$OUT" && sha256sum "$APK" > SHA256SUMS)
cat > "$OUT/release-notes.md" <<EOF_NOTES
Automated signed **debug/test APK**, not a production release.

- Source commit: $GITHUB_SHA
- Run: https://github.com/$GH_REPO/actions/runs/$GITHUB_RUN_ID
- Offline HelpDesk shell: Jira REST integration is not implemented in the supplied sources.
- Disposable debug signing key changes each build. Export local data before uninstalling an older build if signatures differ.
- Download $APK; SHA256SUMS and signature.txt allow integrity/certificate checks.
- Installation and runtime on a physical Android device are not automatically tested.
EOF_NOTES
# Unique immutable run/attempt tag, never overwrite another build or user release.
gh release create "$TAG" "$OUT/$APK" "$OUT/SHA256SUMS" "$OUT/signature.txt" \
  --target "$GITHUB_SHA" --prerelease --latest=false \
  --title "HelpDesk signed test APK — run $GITHUB_RUN_ID.$GITHUB_RUN_ATTEMPT" \
  --notes-file "$OUT/release-notes.md"
# Require a downloadable, byte-identical release asset before claiming success.
mkdir -p "$OUT/download-check"
gh release download "$TAG" --pattern "$APK" --pattern SHA256SUMS --dir "$OUT/download-check"
(cd "$OUT/download-check" && sha256sum --check SHA256SUMS)
cmp "$OUT/$APK" "$OUT/download-check/$APK"
URL="https://github.com/$GH_REPO/releases/tag/$TAG"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  printf '## Signed APK ready\n\n[Download release](%s)\n\n[APK](https://github.com/%s/releases/download/%s/%s)\n\nSignature verification and uploaded/downloaded SHA-256 verification passed. Test/debug signing; offline shell, not production Jira integration.\n' \
    "$URL" "$GH_REPO" "$TAG" "$APK" >> "$GITHUB_STEP_SUMMARY"
fi
printf 'Verified release: %s\n' "$URL"
