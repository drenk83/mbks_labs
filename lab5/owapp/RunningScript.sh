#!/bin/bash
# Локальная замена BenchmarkSuite/RunningScript.sh.
# Каталог APK по умолчанию — lab5/owapp/apk, его заполняет DownloadScript.sh.
# MobSF и SEBASTiAN на этом стенде не запускаются: нет доступа к docker.sock и нет sudo.
# Trueseeing и APKHunt для Yandex Mail уже прогнаны отдельно, команды совпадают с этим скриптом.

set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APK_DIR="${1:-$ROOT/owapp/apk}"
OUT="$ROOT/results/owapp"
mkdir -p "$OUT"

shopt -s nullglob
apks=("$APK_DIR"/*.apk)
if [ "${#apks[@]}" -eq 0 ]; then
  echo "В $APK_DIR нет apk. Сначала ./DownloadScript.sh"
  exit 1
fi

for apk in "${apks[@]}"; do
  base_name="$(basename "$apk" .apk)"
  echo "Trueseeing: $apk"
  trueseeing -eqc "as;gj! $OUT/${base_name}-trueseeing.json" "$apk"
  echo "APKHunt: $apk"
  apkhunt -p "$apk" -l
  echo "SEBASTiAN пропущен: нет Docker и sudo"
  echo "MobSF пропущен: сокет Docker недоступен"
done
