#!/usr/bin/env bash
# Поднимает AVD lab5_api34 и ждёт конца загрузки.
# Второй экземпляр не запускает. Почту и Frida не трогает.
# --window показывает окно. Без аргумента запуск без окна, как в рабочем прогоне.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/lab5/work/env.sh"

window=0
if [[ "${1-}" == "--window" ]]; then
  window=1
elif [[ $# -gt 0 ]]; then
  echo "Использование: $0 [--window]" >&2
  exit 2
fi

avd_pids() {
  local pid args
  while read -r pid args; do
    case "$args" in
      *emu-up.sh*|*emu-down.sh*|*emu-status.sh*) continue ;;
    esac
    case "$args" in
      *lab5_api34*)
        case "$args" in
          *qemu-system*|*emulator*) printf '%s\n' "$pid" ;;
        esac
        ;;
    esac
  done < <(ps -eo pid=,args=)
}

booted() {
  local line serial state boot
  line="$(adb devices | awk 'NR > 1 && $1 ~ /^emulator-/ { print $1, $2; exit }' || true)"
  [[ -n "$line" ]] || return 1
  serial="${line%% *}"
  state="${line#* }"
  [[ "$state" == "device" ]] || return 1
  boot="$(timeout 5 adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
  [[ "$boot" == "1" ]]
}

if booted; then
  echo "эмулятор уже запущен"
  exit 0
fi

if [[ -n "$(avd_pids | paste -sd, - || true)" ]] || adb devices | awk 'NR > 1 && $1 ~ /^emulator-/ { found=1 } END { exit !found }'; then
  echo "эмулятор уже стартует, второй не поднимаю"
else
  if ! command -v emulator >/dev/null; then
    echo "команда emulator не найдена после source lab5/work/env.sh" >&2
    exit 1
  fi
  mkdir -p /tmp/lab5
  args=(
    -avd lab5_api34
    -no-audio -no-boot-anim -no-metrics
    -gpu guest -memory 2048 -cores 2 -no-snapshot
    -feature -Vulkan
  )
  if [[ "$window" -eq 0 ]]; then
    args+=(-no-window)
  fi
  echo "запуск: emulator ${args[*]}"
  echo "лог: /tmp/lab5/emulator.log"
  nohup emulator "${args[@]}" >/tmp/lab5/emulator.log 2>&1 &
  disown || true
fi

deadline=$((SECONDS + 120))
until booted; do
  if (( SECONDS >= deadline )); then
    echo "загрузка не завершилась за 120 с, смотри /tmp/lab5/emulator.log" >&2
    exit 1
  fi
  sleep 2
done
echo "эмулятор запущен"
