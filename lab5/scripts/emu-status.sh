#!/usr/bin/env bash
# Печатает, запущен ли AVD lab5_api34. Ничего не стартует и не останавливает.
# Код 0: adb видит emulator- в состоянии device и sys.boot_completed=1.
# Код 1: эмулятор не готов.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/lab5/work/env.sh"

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

pids="$(avd_pids | paste -sd, - || true)"
if [[ -n "$pids" ]]; then
  echo "qemu: pid $pids"
else
  echo "qemu: нет"
fi

line="$(adb devices | awk 'NR > 1 && $1 ~ /^emulator-/ { print $1, $2; exit }' || true)"
serial=""
state=""
if [[ -n "$line" ]]; then
  serial="${line%% *}"
  state="${line#* }"
  echo "adb: $serial $state"
else
  echo "adb: нет устройства emulator-"
fi

boot="—"
if [[ "$state" == "device" ]]; then
  boot="$(timeout 5 adb -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
  [[ -n "$boot" ]] || boot="—"
fi
echo "boot_completed: $boot"

if [[ "$state" == "device" && "$boot" == "1" ]]; then
  echo "эмулятор запущен"
  exit 0
fi
echo "эмулятор не запущен"
exit 1
