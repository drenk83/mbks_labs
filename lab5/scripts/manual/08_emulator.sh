#!/usr/bin/env bash
# Этап 8. Эмулятор и сценарий с внешним .eml.
# Подкоманды: status, up, install, eml, start, scanner, demo, down.
# Работает с AVD lab5_api34 и пакетом ru.yandex.mail.
# Пишет в lab5/work/manual/dynamic/emulator.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

OUT="$MANUAL_OUT/dynamic/emulator"
PKG="ru.yandex.mail"
REMOTE_EML="/data/data/$PKG/files/lab5-external.eml"

usage() {
  cat <<'EOF'
usage: 08_emulator.sh [команда]

Без аргументов: demo — поднять эмулятор, поставить APK, открыть .eml и сканер.

  status              показать состояние эмулятора
  up [--headless]     поднять AVD lab5_api34 (по умолчанию с окном)
  install             установить APK в эмулятор
  eml                 положить внешний .eml в приватный каталог почты
  start               открыть .eml через EmlActivity и снять скриншот
  scanner             открыть DocScannerCameraActivity и снять скриншот
  demo                up + install + eml + start + scanner
  down                остановить эмулятор
EOF
}

need_adb() {
  need adb
}

require_device() {
  need_adb
  local state
  state="$(adb get-state 2>/dev/null || true)"
  [[ "$state" == "device" ]] || die "adb не видит устройство; сначала: $0 up"
}

do_status() {
  need_adb
  "$LAB5/scripts/emu-status.sh" || true
}

do_up() {
  local headless=0
  for arg in "$@"; do
    case "$arg" in
      --headless) headless=1 ;;
      *) die "up: неизвестный аргумент $arg" ;;
    esac
  done
  need_adb
  if (( headless )); then
    "$LAB5/scripts/emu-up.sh"
  else
    "$LAB5/scripts/emu-up.sh" --window
  fi
  do_status
}

do_install() {
  require_device
  info "Устанавливаю $APK"
  if ! adb install -r "$APK"; then
    warn "adb install не удался. Если это INSTALL_FAILED_UPDATE_INCOMPATIBLE:"
    warn "  adb uninstall $PKG"
    die "установка не завершена"
  fi
  adb shell pm list packages | grep -q "package:$PKG" || die "пакет $PKG не появился"
  info "Пакет установлен: $PKG"
}

make_eml() {
  mkdir -p "$OUT"
  cat > "$OUT/lab5-external.eml" <<'EOF'
From: attacker@example.invalid
To: victim@example.invalid
Subject: lab5 external eml
Date: Tue, 17 Nov 2026 00:00:00 +0300
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

LAB5-EML-MARKER
External .eml opened by Yandex Mail.
EOF
}

do_eml() {
  require_device
  mkdir -p "$OUT"
  make_eml
  info "adb root (нужен для записи в /data/data/$PKG/files)"
  adb root || true
  adb wait-for-device

  if ! adb push "$OUT/lab5-external.eml" "$REMOTE_EML"; then
    warn "adb push не удался, пробую cat через shell"
    adb shell "cat > '$REMOTE_EML'" < "$OUT/lab5-external.eml" \
      || die "не удалось положить .eml; проверь adb root"
  fi

  local uid
  uid="$(adb shell stat -c %u "/data/data/$PKG" | tr -d '\r')"
  [[ -n "$uid" ]] || die "не удалось определить uid пакета $PKG"
  adb shell chown "$uid:$uid" "$REMOTE_EML" || warn "chown не удался"
  adb shell chmod 640 "$REMOTE_EML"
  adb shell ls -l "$REMOTE_EML"
  info "Файл на устройстве: $REMOTE_EML (uid=$uid, mode=640)"
}

do_start() {
  require_device
  mkdir -p "$OUT"
  # Чистый старт: иначе, если сверху остался сканер, am start может
  # отдать intent уже запущенной верхней активности.
  adb shell am force-stop "$PKG" || true
  sleep 1
  info "Открываю .eml через EmlActivity"
  local out
  out="$(adb shell am start -a android.intent.action.VIEW \
    -d "file://$REMOTE_EML" \
    -t message/rfc822 \
    -n "$PKG/com.yandex.mail.eml.EmlActivity" 2>&1)"
  printf '%s\n' "$out"
  if printf '%s' "$out" | grep -qiE 'Error|does not exist|Exception'; then
    die "am start не сработал"
  fi
  # WebView рисует письмо не мгновенно; 8 секунд хватает,
  # чтобы на скриншоте появился LAB5-EML-MARKER.
  sleep 8
  adb exec-out screencap -p > "$OUT/screen-eml.png"
  [[ -s "$OUT/screen-eml.png" ]] || die "скриншот пустой"
  info "Скриншот: $OUT/screen-eml.png"
}

do_scanner() {
  require_device
  mkdir -p "$OUT"
  info "Открываю DocScannerCameraActivity"
  local out
  out="$(adb shell am start \
    -n "$PKG/com.yandex.mail360.camera.doc.scanner.DocScannerCameraActivity" 2>&1)"
  printf '%s\n' "$out"
  sleep 2
  adb exec-out screencap -p > "$OUT/screen-scanner.png"
  [[ -s "$OUT/screen-scanner.png" ]] || die "скриншот пустой"
  info "Скриншот: $OUT/screen-scanner.png"
}

do_demo() {
  do_up "$@"
  do_install
  do_eml
  do_start
  do_scanner
  info "Готово. Остановить: $0 down"
}

do_down() {
  need_adb
  "$LAB5/scripts/emu-down.sh"
}

cmd="${1:-}"
case "$cmd" in
  --headless) do_demo --headless ;;
  status) do_status ;;
  up) shift; do_up "$@" ;;
  install) do_install ;;
  eml) do_eml ;;
  start) do_start ;;
  scanner) do_scanner ;;
  demo) shift; do_demo "$@" ;;
  down) do_down ;;
  -h|--help|help) usage ;;
  '') do_demo ;;
  *) usage; die "неизвестная команда: $cmd" ;;
esac
