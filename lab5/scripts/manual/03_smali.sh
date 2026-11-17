#!/usr/bin/env bash
# Этап 3. Smali: apktool --no-res + rg.
# Считает native-методы, ключевые invoke-вызовы и места loadLibrary.
# Пишет в lab5/work/manual/static/smali, results/ не трогает.

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
usage: 03_smali.sh [--force]

Декодирует APK в smali через apktool --no-res и считает:
  - native-методы (ожидание 339);
  - key invoke-вызовы: loadLibrary, openInputStream, WebView.loadUrl и др.;
  - контекст вокруг System->loadLibrary.

Пишет в lab5/work/manual/static/smali.
EOF
      exit 0
      ;;
    *) die "неизвестный аргумент: $arg" ;;
  esac
done

OUT="$MANUAL_OUT/static/smali"
check_apk
need apktool
need rg

ensure_out "$OUT" "$FORCE"
start_log "$OUT"

info "OUT: $OUT"
info "Декодирую APK в smali (без ресурсов). Это может занять 1-2 минуты."

if ! apktool d -f --no-res -o "$OUT/apktool" "$APK" > "$OUT/apktool.log" 2>&1; then
  tail -n 40 "$OUT/apktool.log" || true
  die "apktool завершился с ошибкой; лог: $OUT/apktool.log"
fi
info "apktool: ok (лог $OUT/apktool.log)"

SMALI="$OUT/apktool"
if ! find "$SMALI" -type f -name '*.smali' -print -quit | grep -q .; then
  die "в $SMALI нет .smali; проверь apktool"
fi

NATIVE_COUNT="$(count_native_smali "$SMALI")"
{
  rg -n --glob '*.smali' '^\s*\.method .*\bnative\b' "$SMALI" 2>/dev/null || true
} > "$OUT/native.txt"

{
  printf 'native methods: %s\n' "$NATIVE_COUNT"
  printf '\nПримеры:\n'
  head -5 "$OUT/native.txt" || true
} | tee "$OUT/native-summary.txt"

{
  rg -n 'processBufferBug' "$SMALI" 2>/dev/null || true
} > "$OUT/processBufferBug.txt"

# name|needle. NEEDLE — подстрока smali-вызова.
PATTERNS=(
  'loadLibrary|System;->loadLibrary'
  'systemLoad|System;->load('
  'runtimeExec|Runtime;->exec'
  'processBuilder|ProcessBuilder;-><init>'
  'webviewLoadUrl|WebView;->loadUrl'
  'webviewLoadData|WebView;->loadData'
  'addJavascriptInterface|addJavascriptInterface'
  'setJavaScriptEnabled|setJavaScriptEnabled'
  'evaluateJavascript|evaluateJavascript'
  'setAllowFileAccess|setAllowFileAccess'
  'setAllowUniversalAccessFromFileURLs|setAllowUniversalAccessFromFileURLs'
  'shouldOverrideUrlLoading|shouldOverrideUrlLoading'
  'cipherGetInstance|Cipher;->getInstance'
  'messageDigest|MessageDigest;->getInstance'
  'secretKeySpec|SecretKeySpec;-><init>'
  'trustManagerCheck|checkServerTrusted'
  'sslContext|SSLContext;->getInstance'
  'certificatePinner|CertificatePinner'
  'httpURLConnection|HttpURLConnection'
  'httpsURLConnection|HttpsURLConnection'
  'okhttpNewCall|OkHttpClient;->newCall'
  'okhttpUrl|Request$Builder;->url'
  'openFileOutput|openFileOutput'
  'getSharedPreferences|getSharedPreferences'
  'rawQuery|rawQuery'
  'execSQL|execSQL'
  'contentQuery|ContentResolver;->query'
  'openInputStream|openInputStream'
  'intentGetData|Intent;->getData'
  'intentGetDataString|Intent;->getDataString'
  'intentGetStringExtra|Intent;->getStringExtra'
  'intentGetParcelableExtra|Intent;->getParcelableExtra'
  'intentGetClipData|Intent;->getClipData'
  'sendBroadcast|sendBroadcast'
  'startActivity|startActivity'
  'logd|Log;->d'
  'loge|Log;->e'
  'fileOutputStreamInit|FileOutputStream;-><init>'
  'fileInputStreamInit|FileInputStream;-><init>'
  'pathClassLoader|PathClassLoader'
  'webviewSettings|WebView;->getSettings'
)

: > "$OUT/api-hits.txt"
printf '%-40s %s\n' 'name' 'count' >> "$OUT/api-hits.txt"
for item in "${PATTERNS[@]}"; do
  name="${item%%|*}"
  needle="${item#*|}"
  count="$(count_invoke "$SMALI" "$needle")"
  printf '%-40s %s\n' "$name" "$count" | tee -a "$OUT/api-hits.txt"
done

{
  rg -n -B 4 'System;->loadLibrary' "$SMALI" 2>/dev/null || true
} > "$OUT/load-libraries.txt"

{
  printf 'loadLibrary sites: %s\n' "$(grep -c 'loadLibrary' "$OUT/load-libraries.txt" || true)"
  printf '\nconst-string рядом:\n'
  rg 'const-string|loadLibrary|\.method' "$OUT/load-libraries.txt" 2>/dev/null | head -40 || true
} | tee "$OUT/load-libraries-summary.txt"

printf '\nОжидание: native 339, loadLibrary 8, openInputStream 40, WebView.loadUrl 36.\n'
printf 'Полные списки: %s\n' "$OUT"
