#!/usr/bin/env bash
# Этап 9. Frida: сервер, поиск PID, трасса EmlActivity/openInputStream, карта модулей.
# Подкоманды: status, server, ps, trace [--auto], modules, all.
# Пишет в lab5/work/manual/dynamic/frida.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

OUT="$MANUAL_OUT/dynamic/frida"
PKG="ru.yandex.mail"
REMOTE_EML="/data/data/$PKG/files/lab5-external.eml"
SERVER_LOCAL="$LAB5/work/tools/frida/frida-server-17.4.0-android-x86_64"
TRACE_JS="$HERE/simple-trace.js"

usage() {
  cat <<'EOF'
usage: 09_frida.sh [команда]

Без аргументов: all — server + trace --auto + modules.

  status           версия Frida, adb, процессы
  server           adb root + push + запуск frida-server
  ps               показать процессы, похожие на Yandex Mail
  trace [--auto]   attach по PID и трасса simple-trace.js
                   --auto сам откроет .eml и сканер через несколько секунд
  modules          второй attach: карта модулей, ищем camera360
  all              server + trace --auto + modules

Пишет в lab5/work/manual/dynamic/frida.
EOF
}

need_adb() {
  need adb
}

require_device() {
  need_adb
  local state
  state="$(adb get-state 2>/dev/null || true)"
  [[ "$state" == "device" ]] || die "adb не видит устройство; сначала: 08_emulator.sh up"
}

check_frida() {
  need frida
  need stdbuf
  need timeout
  local v
  v="$(frida --version 2>/dev/null || true)"
  info "frida --version: ${v:-unknown}"
  if [[ "$v" != "17.4.0" ]]; then
    warn "ожидался клиент Frida 17.4.0; если это 16.x из venv analysis — открой новый терминал и снова source lab5/work/env.sh"
  fi
}

get_pid() {
  local pid
  pid="$(frida-ps -Uai 2>/dev/null \
    | awk '$2 == "Yandex" && $3 == "Mail" {print $1; exit}' \
    | tr -d '\r')"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  printf '%s' "$pid"
}

start_app() {
  require_device
  info "Запускаю приложение, чтобы появился процесс"
  adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
  sleep 2
}

do_status() {
  check_frida
  need_adb
  adb devices || true
  printf '\nПроцессы почты:\n'
  frida-ps -Uai 2>/dev/null | grep -i mail || echo '  не найдено'
}

do_server() {
  require_device
  check_frida
  need_file "$SERVER_LOCAL"
  info "adb root"
  adb root || true
  adb wait-for-device
  info "Копирую frida-server"
  adb push "$SERVER_LOCAL" /data/local/tmp/frida-server
  adb shell chmod 755 /data/local/tmp/frida-server
  info "Запускаю frida-server"
  # pkill -x, а не -f: иначе pkill совпадает с собственной командной строкой
  # adb shell, в которой тоже есть слово frida-server, и убивает сам себя.
  adb shell "pkill -x frida-server 2>/dev/null || true" || true
  adb shell '/data/local/tmp/frida-server >/data/local/tmp/frida.log 2>&1 &' || true
  sleep 2
  if frida-ps -U >/dev/null 2>&1; then
    info "frida-server отвечает"
  else
    warn "frida-server не отвечает; смотри /data/local/tmp/frida.log"
    adb shell 'tail -n 20 /data/local/tmp/frida.log' || true
  fi
}

do_ps() {
  check_frida
  require_device
  frida-ps -Uai 2>/dev/null | grep -i mail || {
    warn "Yandex Mail не найден; запусти приложение или .eml"
    frida-ps -Uai 2>/dev/null | head -20 || true
  }
}

do_trace() {
  local auto=0
  for arg in "$@"; do
    case "$arg" in
      --auto) auto=1 ;;
      *) die "trace: неизвестный аргумент $arg" ;;
    esac
  done

  check_frida
  require_device
  need_file "$TRACE_JS"
  mkdir -p "$OUT"

  local pid
  if (( auto )); then
    # Чистый старт, чтобы .eml открылся в EmlActivity, а не в
    # оставшемся сверху сканере.
    adb shell am force-stop "$PKG" || true
    sleep 1
    start_app
    pid="$(get_pid || true)"
  else
    pid="$(get_pid || true)"
    if [[ -z "$pid" ]]; then
      start_app
      pid="$(get_pid || true)"
    fi
  fi
  [[ -n "$pid" ]] || die "не нашёл PID Yandex Mail; запусти приложение и повтори"

  if (( auto )); then
    info "Через 3 с открою .eml, через 10 с — сканер"
    (
      sleep 3
      adb shell am start -a android.intent.action.VIEW \
        -d "file://$REMOTE_EML" \
        -t message/rfc822 \
        -n "$PKG/com.yandex.mail.eml.EmlActivity" >/dev/null 2>&1 || true
      sleep 7
      adb shell am start \
        -n "$PKG/com.yandex.mail360.camera.doc.scanner.DocScannerCameraActivity" \
        >/dev/null 2>&1 || true
    ) &
  fi

  info "PID $pid; сессия Frida 30 секунд"
  info "Если --auto не указан, открой .eml в другом терминале: 08_emulator.sh start"
  set +e
  timeout 45s bash -c \
    'sleep 30 | stdbuf -oL -eL frida -U -p "$1" -l "$2"' \
    _ "$pid" "$TRACE_JS" | tee "$OUT/trace.log"
  rc=${PIPESTATUS[0]}
  set -e
  if (( rc == 124 )); then
    info "Frida остановлен по таймауту 30 с; события уже в $OUT/trace.log"
  elif (( rc != 0 )); then
    warn "Frida завершился с кодом $rc"
  fi

  if grep -qF 'openInputStream' "$OUT/trace.log"; then
    info "openInputStream найден:"
    grep -F 'openInputStream' "$OUT/trace.log" || true
  else
    warn "openInputStream в трассе не найден"
  fi
}

do_modules() {
  check_frida
  require_device
  mkdir -p "$OUT"
  local pid
  pid="$(get_pid || true)"
  [[ -n "$pid" ]] || die "не нашёл PID Yandex Mail; сначала запусти приложение"

  cat > "$OUT/modules.js" <<'EOF'
var mods = Process.enumerateModules();
var hits = mods.filter(function (m) {
  return m.name.indexOf('camera360') !== -1;
}).map(function (m) {
  return m.name + ' | ' + m.path;
});
send({ pid: Process.id, hits: hits, total: mods.length });
EOF

  info "PID $pid; второй attach на 10 секунд"
  set +e
  timeout 20s bash -c \
    'sleep 10 | stdbuf -oL -eL frida -U -p "$1" -l "$2"' \
    _ "$pid" "$OUT/modules.js" | tee "$OUT/modules.log"
  rc=${PIPESTATUS[0]}
  set -e
  if (( rc == 124 )); then
    info "модули: Frida остановлен по таймауту 10 с"
  elif (( rc != 0 )); then
    warn "модули: Frida завершился с кодом $rc"
  fi

  if grep -qF 'camera360' "$OUT/modules.log"; then
    info "camera360 найден:"
    grep -F 'camera360' "$OUT/modules.log" || true
  else
    warn "camera360 в карте модулей не найден; сканер мог не успеть загрузиться"
  fi
}

do_all() {
  do_server
  do_ps
  do_trace --auto
  do_modules
}

cmd="${1:-}"
case "$cmd" in
  status) do_status ;;
  server) do_server ;;
  ps) do_ps ;;
  trace) shift; do_trace "$@" ;;
  modules) do_modules ;;
  all) do_all ;;
  -h|--help|help) usage ;;
  '') do_all ;;
  *) usage; die "неизвестная команда: $cmd" ;;
esac
