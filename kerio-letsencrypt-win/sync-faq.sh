#!/usr/bin/env bash
# sync-faq.sh — «одна инструкция, два места».
#
# Корневой FAQ.md — единственный источник правды: он же уходит в ZIP рядом с
# .exe, его же читают на GitHub. Программа компилирует инструкцию внутрь себя
# из ui/FAQ.md (go:embed), потому что embed не умеет брать файлы выше пакета.
#
# Поэтому после КАЖДОЙ правки FAQ.md запустите этот скрипт:
#
#     bash kerio-letsencrypt-win/sync-faq.sh
#
# Если забыть — упадёт go test (TestEmbeddedFAQMatchesRoot) и сборка в CI
# не выпустится: программа физически не сможет показать старую инструкцию.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/../FAQ.md"
dst="$here/ui/FAQ.md"

if [ ! -f "$src" ]; then
  echo "ОШИБКА: не найден $src" >&2
  exit 1
fi
if [ ! -d "$here/ui" ]; then
  echo "ОШИБКА: не найдена папка $here/ui" >&2
  exit 1
fi

cp "$src" "$dst"
echo "ui/FAQ.md обновлён из FAQ.md: $(wc -c < "$dst" | tr -d ' ') Б, строк: $(wc -l < "$dst" | tr -d ' ')"
