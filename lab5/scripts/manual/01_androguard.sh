#!/usr/bin/env bash
# Этап 1. Автоматический разбор APK через audit_apk.py (androguard).
# Это основной источник точных цифр; ручные этапы его проверяют.
# Пишет в lab5/work/manual/static/androguard, results/ не трогает.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

FORCE=1
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    -h|--help)
      cat <<'EOF'
usage: 01_androguard.sh [--force]

Запускает lab5/scripts/audit_apk.py через venv analysis в отдельный каталог.
Ожидание: native 339, classes 59178, methods 260516, loadLibrary 8.
EOF
      exit 0
      ;;
    *) die "неизвестный аргумент: $arg" ;;
  esac
done

OUT="$MANUAL_OUT/static/androguard"
PY="$LAB5/work/venvs/analysis/bin/python"
SCRIPT="$LAB5/scripts/audit_apk.py"

check_apk
need_exec "$PY"
need_file "$SCRIPT"

ensure_out "$OUT" "$FORCE"
start_log "$OUT"

info "OUT: $OUT"
info "Запускаю audit_apk.py (androguard). Это может занять несколько минут."

"$PY" "$SCRIPT" "$APK" "$OUT/out" > "$OUT/audit.log" 2>&1
tail -n 20 "$OUT/audit.log" || true

need_file "$OUT/out/natives.txt"
need_file "$OUT/out/manifest.txt"
need_file "$OUT/out/api-hits.txt"

{
  printf '== natives ==\n'
  head -3 "$OUT/out/natives.txt"
  printf '\n== ключевые API ==\n'
  grep -E '^(loadLibrary|openInputStream|webviewLoadUrl|addJavascriptInterface|setJavaScriptEnabled|cipherGetInstance|getSharedPreferences)[[:space:]]' \
    "$OUT/out/api-hits.txt" || true
} | tee "$OUT/summary.txt"

printf '\nГотово. Полные файлы: %s\n' "$OUT/out"
