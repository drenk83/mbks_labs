#!/usr/bin/env bash
# Останавливает AVD lab5_api34. Чужие qemu не трогает.

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

adb_sees_emulator() {
  adb devices | awk 'NR > 1 && $1 ~ /^emulator-/ { found=1 } END { exit !found }'
}

if ! adb_sees_emulator && [[ -z "$(avd_pids | paste -sd, - || true)" ]]; then
  echo "эмулятор не запущен"
  exit 0
fi

if adb_sees_emulator; then
  adb -e emu kill || true
fi

deadline=$((SECONDS + 20))
while adb_sees_emulator || [[ -n "$(avd_pids | paste -sd, - || true)" ]]; do
  if (( SECONDS >= deadline )); then
    break
  fi
  sleep 1
done

pids="$(avd_pids || true)"
if [[ -z "$pids" ]]; then
  echo "эмулятор остановлен"
  exit 0
fi

echo "adb не остановил процесс, завершаю только lab5_api34"
# shellcheck disable=SC2086
kill $pids || true
sleep 2
pids="$(avd_pids || true)"
if [[ -n "$pids" ]]; then
  # shellcheck disable=SC2086
  kill -KILL $pids || true
fi
echo "эмулятор остановлен"
