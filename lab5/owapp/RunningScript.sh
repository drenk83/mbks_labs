#!/bin/bash
# OWApp RunningScript для варианта 11.
# Запускает инструменты OWApp на APK из lab5/owapp/apk:
#   Trueseeing, APKHunt, SEBASTiAN (Docker). MobSF пропускается:
#   в OWApp он ставится локально и запускается через MobsfReport.py.
#
# Просто запусти:
#   ./DownloadScript.sh
#   ./RunningScript.sh
#
# Режимы:
#   --check         проверить APK, инструменты и Docker, ничего не сканировать
#   --trueseeing    только Trueseeing
#   --apkhunt       только APKHunt (долго, 22+ минуты)
#   --sebastian     только SEBASTiAN (нужен Docker)
#   --all           всё доступное (по умолчанию)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
if [[ -f "$ROOT/work/env.sh" ]]; then
  source "$ROOT/work/env.sh"
fi
APK_DIR_DEFAULT="$ROOT/owapp/apk"
OUT="$ROOT/results/owapp"
TS="$ROOT/work/venvs/analysis/bin/trueseeing"
APKHUNT="$ROOT/work/tools/bin/apkhunt"

MODE="all"
APK_DIR=""

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check|--trueseeing|--apkhunt|--sebastian|--all)
      MODE="${1#--}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      echo "Неизвестный флаг: $1" >&2
      usage
      exit 2
      ;;
    *)
      APK_DIR="$1"
      shift
      ;;
  esac
done

APK_DIR="${APK_DIR:-$APK_DIR_DEFAULT}"
if [[ ! -d "$APK_DIR" ]]; then
  echo "Нет каталога с APK: $APK_DIR" >&2
  exit 1
fi
APK_DIR="$(cd "$APK_DIR" && pwd)"
mkdir -p "$OUT"

shopt -s nullglob
apks=("$APK_DIR"/*.apk)
if [[ "${#apks[@]}" -eq 0 ]]; then
  echo "В $APK_DIR нет apk. Сначала ./DownloadScript.sh" >&2
  exit 1
fi

docker_mode() {
  # Возвращает 0, если Docker доступен. В DOCKER_CMD кладёт docker или sudo docker.
  DOCKER_CMD=()
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker не установлен" >&2
    return 1
  fi
  if docker info >/dev/null 2>&1; then
    DOCKER_CMD=(docker)
    return 0
  fi
  if ! systemctl is-active --quiet docker; then
    echo "Docker не запущен, пробую sudo systemctl start docker" >&2
    sudo systemctl start docker || true
    sleep 2
  fi
  if docker info >/dev/null 2>&1; then
    DOCKER_CMD=(docker)
    return 0
  fi
  if sudo docker info >/dev/null 2>&1; then
    DOCKER_CMD=(sudo docker)
    echo "Docker доступен через sudo" >&2
    return 0
  fi
  echo "Docker не отвечает. Запусти: sudo systemctl enable --now docker" >&2
  return 1
}

check_mode() {
  echo "APK dir: $APK_DIR"
  echo "APK files: ${#apks[@]}"
  printf '  %s\n' "${apks[@]}"
  [[ -x "$TS" ]] && echo "Trueseeing: $TS" || echo "Trueseeing: НЕТ"
  [[ -x "$APKHUNT" ]] && echo "APKHunt: $APKHUNT" || echo "APKHunt: НЕТ"
  if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
      echo "Docker: ok (без sudo)"
    elif sudo -n docker info >/dev/null 2>&1; then
      echo "Docker: ok (через sudo)"
    else
      echo "Docker: не готов (нужен sudo или запуск docker.service)"
    fi
  else
    echo "Docker: не установлен"
  fi
}

run_trueseeing() {
  [[ -x "$TS" ]] || { echo "Нет $TS" >&2; return 1; }
  for apk in "${apks[@]}"; do
    local base json log
    base="$(basename "$apk" .apk)"
    json="$OUT/${base}-trueseeing.json"
    log="$OUT/${base}-trueseeing.log"
    echo "Trueseeing: $apk"
    "$TS" -eqc "as;gj! $json" "$apk" > "$log" 2>&1 || {
      echo "Trueseeing завершился с ошибкой; лог: $log" >&2
      return 1
    }
    grep -E 'done, found' "$log" | tail -n 1 || true
    if command -v jq >/dev/null 2>&1; then
      jq -r '"groups=" + (.app.issues|tostring)' "$json" 2>/dev/null || true
    fi
  done
}

run_apkhunt() {
  [[ -x "$APKHUNT" ]] || { echo "Нет $APKHUNT" >&2; return 1; }
  for apk in "${apks[@]}"; do
    local base log
    base="$(basename "$apk" .apk)"
    log="$OUT/${base}-apkhunt.log"
    echo "APKHunt: $apk (долго, 22+ минуты)"
    (cd "$OUT" && "$APKHUNT" -p "$apk" -l) > "$log" 2>&1 || {
      echo "APKHunt завершился с ошибкой; лог: $log" >&2
      return 1
    }
    grep -E 'Total exported|Total time taken' "$log" | tail -n 8 || true
  done
}

run_sebastian() {
  if ! docker_mode; then
    echo "SEBASTiAN пропущен: Docker недоступен" >&2
    return 1
  fi
  local seb="$OUT/sebastian"
  mkdir -p "$seb"
  for apk in "${apks[@]}"; do
    local base local_apk run_args
    base="$(basename "$apk" .apk)"
    local_apk="$seb/$(basename "$apk")"
    if ! ln -f "$apk" "$local_apk" 2>/dev/null; then
      cp -f "$apk" "$local_apk"
    fi
    echo "SEBASTiAN: $apk"
    "${DOCKER_CMD[@]}" pull talossec/sebastian:latest
    run_args=(--rm -u "$(id -u):$(id -g)" -v "$seb:/workdir")
    if [[ -t 0 && -t 1 ]]; then
      run_args+=(-it)
    fi
    "${DOCKER_CMD[@]}" run "${run_args[@]}" talossec/sebastian:latest \
      -gr "$(basename "$local_apk")" 2>&1 | tee "$seb/${base}-sebastian.log"
  done
}

echo "OWApp RunningScript, режим: $MODE"
echo "APK dir: $APK_DIR"
echo "Результаты: $OUT"

case "$MODE" in
  check)
    check_mode
    ;;
  trueseeing)
    run_trueseeing
    ;;
  apkhunt)
    run_apkhunt
    ;;
  sebastian)
    run_sebastian
    ;;
  all)
    run_trueseeing
    run_apkhunt
    if docker_mode; then
      run_sebastian
    else
      echo "SEBASTiAN пропущен: Docker недоступен" >&2
    fi
    echo "MobSF пропущен: в OWApp он ставится локально и запускается через MobsfReport.py"
    ;;
  *)
    usage
    exit 2
    ;;
esac

echo "Готово. Результаты: $OUT"
