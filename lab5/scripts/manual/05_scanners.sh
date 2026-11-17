#!/usr/bin/env bash
# Этап 5. Автоматические статические сканеры.
# По умолчанию запускает только Trueseeing (около 1 минуты).
# APKHunt (22+ минуты) и FlowDroid (8 ГБ) — только по явному флагу.
# Пишет в lab5/work/manual/static/scanners, results/ не трогает.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

RUN_TRUESEEING=0
RUN_APKHUNT=0
RUN_FLOWDROID=0
FORCE=1

usage() {
  cat <<'EOF'
usage: 05_scanners.sh [--trueseeing] [--apkhunt] [--flowdroid] [--all] [--force]

Без флагов: --trueseeing.
  --trueseeing  Trueseeing 2.2.11, около 1 минуты
  --apkhunt     APKHunt, 22+ минуты, пишет SAST-дерево
  --flowdroid   FlowDroid, 8 ГБ heap, может оборваться по памяти
  --all         все три
  --force       разрешить запись в непустой каталог

Пишет в lab5/work/manual/static/scanners.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --trueseeing) RUN_TRUESEEING=1 ;;
    --apkhunt) RUN_APKHUNT=1 ;;
    --flowdroid) RUN_FLOWDROID=1 ;;
    --all) RUN_TRUESEEING=1; RUN_APKHUNT=1; RUN_FLOWDROID=1 ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "неизвестный аргумент: $arg" ;;
  esac
done

if (( RUN_TRUESEEING + RUN_APKHUNT + RUN_FLOWDROID == 0 )); then
  RUN_TRUESEEING=1
fi

OUT="$MANUAL_OUT/static/scanners"
check_apk
need jq
need rg

ensure_out "$OUT" "$FORCE"
start_log "$OUT"

info "OUT: $OUT"

if (( RUN_TRUESEEING )); then
  TS="$LAB5/work/venvs/analysis/bin/trueseeing"
  need_exec "$TS"
  info "Trueseeing: старт (около 1 минуты)"
  if "$TS" -eqc "as;gj! $OUT/trueseeing.json" "$APK" > "$OUT/trueseeing.log" 2>&1; then
    grep -E 'done, found' "$OUT/trueseeing.log" | tail -n 1 || true
  else
    tail -n 20 "$OUT/trueseeing.log" || true
    die "Trueseeing завершился с ошибкой; лог: $OUT/trueseeing.log"
  fi
  need_file "$OUT/trueseeing.json"
  {
    printf 'package=%s\n' "$(jq -r '.app.package' "$OUT/trueseeing.json")"
    printf 'version=%s\n' "$(jq -r '.app.version_name' "$OUT/trueseeing.json")"
    printf 'groups=%s\n' "$(jq -r '.app.issues' "$OUT/trueseeing.json")"
    jq -r '.issues | group_by(.severity)[] | "\(.[0].severity)=\(length)"' "$OUT/trueseeing.json"
  } | tee "$OUT/trueseeing-summary.txt"
fi

if (( RUN_APKHUNT )); then
  need apkhunt
  info "APKHunt: старт, это надолго (22+ минуты)"
  LINK="$OUT/yandex-mail-8-81-2.apk"
  if ! ln -f "$APK" "$LINK" 2>/dev/null; then
    cp -f "$APK" "$LINK"
  fi
  if (cd "$OUT" && apkhunt -p "$LINK" -l) > "$OUT/apkhunt-run.log" 2>&1; then
    info "APKHunt: завершён"
  else
    warn "APKHunt завершился с ненулевым кодом; смотри $OUT/apkhunt-run.log"
  fi
  APK_LOG="$(ls -t "$OUT"/APKHunt_*.txt 2>/dev/null | head -1 || true)"
  if [[ -n "$APK_LOG" ]]; then
    {
      grep -n 'Total exported\|Total time taken' "$APK_LOG" || true
      printf '\nmanifest exported=true: %s\n' \
        "$(grep -c 'android:exported="true"' \
          "$OUT"/yandex-mail-8-81-2_SAST/resources/AndroidManifest.xml 2>/dev/null || true)"
    } | tee "$OUT/apkhunt-summary.txt"
  else
    warn "APKHunt не оставил APKHunt_*.txt"
  fi
fi

if (( RUN_FLOWDROID )); then
  need java
  CP_FILE="$LAB5/work/tools/flowdroid/classpath.txt"
  SINKS="$LAB5/work/tools/flowdroid/SourcesAndSinks.txt"
  PLATFORMS="$LAB5/work/android-sdk/platforms"
  need_file "$CP_FILE"
  need_file "$SINKS"
  [[ -d "$PLATFORMS" ]] || die "нет каталога platforms: $PLATFORMS"
  info "FlowDroid: старт, heap 8g; возможен DataFlowOutOfMemory"
  set +e
  java -Xmx8g -cp "$(cat "$CP_FILE")" \
    soot.jimple.infoflow.cmd.MainClass \
    -a "$APK" \
    -p "$PLATFORMS" \
    -s "$SINKS" \
    -o "$OUT/flowdroid.xml" \
    -cg CHA -ca FAST -l NONE -dt 480 -ct 120 -mt 4 -lp 2>&1 | tee "$OUT/flowdroid.log"
  rc=${PIPESTATUS[0]}
  set -e
  if (( rc != 0 )); then
    warn "FlowDroid вернул код $rc; если XML есть, разбираю его"
  fi
  if [[ -f "$OUT/flowdroid.xml" ]]; then
    {
      printf 'termination=%s\n' "$(xmllint --xpath 'string(/*/@TerminationState)' "$OUT/flowdroid.xml")"
      printf 'results=%s\n' "$(xmllint --xpath 'count(//Result)' "$OUT/flowdroid.xml")"
      printf 'sources=%s\n' "$(xmllint --xpath 'count(//Source)' "$OUT/flowdroid.xml")"
    } | tee "$OUT/flowdroid-summary.txt"
  else
    warn "FlowDroid не создал $OUT/flowdroid.xml"
  fi
fi

printf '\nГотово. Артефакты: %s\n' "$OUT"
