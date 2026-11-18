#!/usr/bin/env bash
# Этап 11. Показ нативного вызова: сканер грузит libcamera360-arcadia.so,
# Frida перехватывает нативный open этой библиотеки.
# Запуск без аргументов: 60 секунд, сканер откроется сам через 6 секунд.
# Аргумент: длительность сессии Frida в секундах.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

OUT="$MANUAL_OUT/dynamic/frida"
PKG="ru.yandex.mail"
SCANNER="$PKG/com.yandex.mail360.camera.doc.scanner.DocScannerCameraActivity"
JS="$HERE/scanner-native.js"
SERVER_LOCAL="$LAB5/work/tools/frida/frida-server-17.4.0-android-x86_64"
DURATION="${1:-60}"

need adb
need frida
need stdbuf
need_file "$JS"

state="$(adb get-state 2>/dev/null || true)"
[[ "$state" == "device" ]] || die "adb не видит устройство; сначала: 08_emulator.sh up"

info "adb root"
adb root >/dev/null 2>&1 || true
adb wait-for-device

if ! adb shell test -x /data/local/tmp/frida-server; then
  need_file "$SERVER_LOCAL"
  info "Копирую frida-server"
  adb push "$SERVER_LOCAL" /data/local/tmp/frida-server
  adb shell chmod 755 /data/local/tmp/frida-server
fi

info "Перезапускаю frida-server"
adb shell 'pkill -x frida-server 2>/dev/null || true' || true
sleep 1
adb shell 'nohup /data/local/tmp/frida-server >/data/local/tmp/frida.log 2>&1 &' || true
sleep 2
frida-ps -U >/dev/null 2>&1 || die "frida-server не отвечает; смотри /data/local/tmp/frida.log"

info "Чистый старт приложения"
adb shell am force-stop "$PKG" || true
sleep 1
adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
sleep 3

PID="$(adb shell pidof "$PKG" | tr -d '\r' | awk '{print $1}')"
[[ "$PID" =~ ^[0-9]+$ ]] || die "не нашёл PID $PKG"

mkdir -p "$OUT"
info "PID $PID; сессия Frida $DURATION с; сканер откроется через 6 с"
( sleep 6; adb shell am start -n "$SCANNER" >/dev/null 2>&1 || true ) &

set +e
sleep "$DURATION" | stdbuf -oL -eL frida -U -p "$PID" -l "$JS" | tee "$OUT/scanner-native.log"
set -e

if grep -qF 'camera360' "$OUT/scanner-native.log"; then
  info "Нативный вызов виден:"
  grep -F 'camera360' "$OUT/scanner-native.log" || true
else
  warn "camera360 в логе нет. Проверь, что сканер открылся и приложение не упало."
fi
info "Лог: $OUT/scanner-native.log"
