#!/usr/bin/env bash
# Этап 10. Проверка: сверяет ручные артефакты и results/ с ожидаемыми числами.
# Ничего тяжёлого не запускает.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
usage: 10_check.sh

Сверяет манифест, native, API hits, .so, Frida, FlowDroid,
Trueseeing и APKHunt с ожидаемыми числами.
Ничего тяжёлого не запускает.
EOF
  exit 0
fi
if (( $# > 0 )); then
  die "неизвестный аргумент: $1"
fi

need jq
need xmllint
need rg

info "Проверяю APK и артефакты"
check_apk

MANIFEST_XML="$MANUAL_OUT/static/manifest/apktool/AndroidManifest.xml"
if [[ ! -f "$MANIFEST_XML" ]]; then
  MANIFEST_XML="$LAB5/results/apkhunt/yandex-mail-8-81-2_SAST/resources/AndroidManifest.xml"
fi
MANIFEST_JSON="$LAB5/results/manifest.json"

MANIFEST_MODE=""
if [[ -f "$MANIFEST_XML" ]]; then
  MANIFEST_MODE="xml"
elif [[ -f "$MANIFEST_JSON" ]]; then
  MANIFEST_MODE="json"
else
  die "нет ни ручного манифеста, ни results/manifest.json"
fi
info "Манифест: $MANIFEST_MODE"

m_string() {
  local what="$1" yml="$MANUAL_OUT/static/manifest/apktool/apktool.yml" val=""
  if [[ "$MANIFEST_MODE" == "xml" ]]; then
    case "$what" in
      package) xml_string "$MANIFEST_XML" '/*[local-name()="manifest"]/@package' ;;
      version_name)
        if [[ -f "$yml" ]]; then
          val="$(awk '/^versionInfo:/{f=1;next} f && /^[^ ]/{f=0} f && /versionName:/{print $2; exit}' "$yml")"
        fi
        if [[ -z "$val" ]]; then
          val="$(xml_string "$MANIFEST_XML" '/*[local-name()="manifest"]/@*[local-name()="versionName"]')"
        fi
        if [[ -z "$val" && -f "$MANIFEST_JSON" ]]; then
          val="$(jq -r '.version_name' "$MANIFEST_JSON")"
        fi
        printf '%s' "$val"
        ;;
      version_code)
        if [[ -f "$yml" ]]; then
          val="$(awk '/^versionInfo:/{f=1;next} f && /^[^ ]/{f=0} f && /versionCode:/{print $2; exit}' "$yml")"
        fi
        if [[ -z "$val" ]]; then
          val="$(xml_string "$MANIFEST_XML" '/*[local-name()="manifest"]/@*[local-name()="versionCode"]')"
        fi
        if [[ -z "$val" && -f "$MANIFEST_JSON" ]]; then
          val="$(jq -r '.version_code' "$MANIFEST_JSON")"
        fi
        printf '%s' "$val"
        ;;
      allow_backup) xml_string "$MANIFEST_XML" '//*[local-name()="application"]/@*[local-name()="allowBackup"]' ;;
      *) die "m_string: $what" ;;
    esac
  else
    case "$what" in
      package) jq -r '.package' "$MANIFEST_JSON" ;;
      version_name) jq -r '.version_name' "$MANIFEST_JSON" ;;
      version_code) jq -r '.version_code' "$MANIFEST_JSON" ;;
      allow_backup) jq -r '.application.allowBackup' "$MANIFEST_JSON" ;;
      *) die "m_string: $what" ;;
    esac
  fi
}

m_count() {
  local tag="$1" mode="$2"
  if [[ "$MANIFEST_MODE" == "xml" ]]; then
    xml_count "$MANIFEST_XML" "$tag" "$mode"
    return
  fi

  local key
  case "$tag" in
    activity) key="activities" ;;
    activity-alias) key="activity_aliases" ;;
    service) key="services" ;;
    receiver) key="receivers" ;;
    provider) key="providers" ;;
    *) die "m_count: $tag" ;;
  esac

  case "$mode" in
    total) jq --arg k "$key" '.[$k] | length' "$MANIFEST_JSON" ;;
    exported) jq --arg k "$key" '[.[$k][] | select(.exported == "true")] | length' "$MANIFEST_JSON" ;;
    no_perm) jq --arg k "$key" '[.[$k][] | select(.exported == "true" and ((.permission // "") == ""))] | length' "$MANIFEST_JSON" ;;
    *) die "m_count: mode $mode" ;;
  esac
}

# --- Манифест ---
expect_eq "package" "ru.yandex.mail" "$(m_string package)"
expect_eq "versionName" "8.81.2" "$(m_string version_name)"
expect_eq "versionCode" "105397" "$(m_string version_code)"
expect_eq "allowBackup" "false" "$(m_string allow_backup)"

expect_eq "activity total" 108 "$(m_count activity total)"
expect_eq "activity exported" 14 "$(m_count activity exported)"
expect_eq "activity exported no permission" 9 "$(m_count activity no_perm)"
expect_eq "activity-alias total" 7 "$(m_count activity-alias total)"
expect_eq "activity-alias exported" 7 "$(m_count activity-alias exported)"
expect_eq "activity-alias exported no permission" 7 "$(m_count activity-alias no_perm)"
expect_eq "service total" 32 "$(m_count service total)"
expect_eq "service exported" 5 "$(m_count service exported)"
expect_eq "service exported no permission" 1 "$(m_count service no_perm)"
expect_eq "receiver total" 35 "$(m_count receiver total)"
expect_eq "receiver exported" 14 "$(m_count receiver exported)"
expect_eq "receiver exported no permission" 9 "$(m_count receiver no_perm)"
expect_eq "provider total" 20 "$(m_count provider total)"
expect_eq "provider exported" 3 "$(m_count provider exported)"
expect_eq "provider exported no permission" 3 "$(m_count provider no_perm)"

# --- Native ---
NATIVE_TXT="$MANUAL_OUT/static/smali/native.txt"
if [[ -f "$NATIVE_TXT" ]]; then
  NATIVE_COUNT="$(wc -l < "$NATIVE_TXT" | tr -d ' ')"
else
  NATIVE_COUNT="$(awk '/^native methods:/ {print $3; exit}' "$LAB5/results/natives.txt")"
fi
expect_eq "native methods" 339 "$NATIVE_COUNT"

# --- API hits ---
API_TXT="$MANUAL_OUT/static/smali/api-hits.txt"
if [[ ! -f "$API_TXT" ]]; then
  API_TXT="$LAB5/results/api-hits.txt"
fi
api_count() {
  local key="$1"
  awk -v k="$key" '$1 == k {print $2; found=1; exit} END {if (!found) print ""}' "$API_TXT"
}
expect_eq "loadLibrary" 8 "$(api_count loadLibrary)"
expect_eq "openInputStream" 40 "$(api_count openInputStream)"
expect_eq "WebView.loadUrl" 36 "$(api_count webviewLoadUrl)"
expect_eq "addJavascriptInterface" 25 "$(api_count addJavascriptInterface)"
expect_eq "setJavaScriptEnabled" 21 "$(api_count setJavaScriptEnabled)"
expect_eq "Cipher.getInstance" 15 "$(api_count cipherGetInstance)"
expect_eq "getSharedPreferences" 135 "$(api_count getSharedPreferences)"

# --- .so ---
LIBDIR="$MANUAL_OUT/static/native-so/x86_64"
if [[ ! -d "$LIBDIR" ]]; then
  LIBDIR="$LAB5/work/native/x86_64"
fi
if [[ -d "$LIBDIR" ]]; then
  LIB_COUNT="$(find "$LIBDIR" -maxdepth 1 -type f -name '*.so' | wc -l | tr -d ' ')"
  expect_eq "x86_64 libraries" 4 "$LIB_COUNT"
  for name in libcamera360-arcadia.so libeye.so libjingle_peerconnection_so.so libYandexSpeechKitJni.4.15.7.so; do
    expect_file "library $name" "$LIBDIR/$name"
  done
  LIBPNG_COUNT="$({ strings -a "$LIBDIR"/*.so 2>/dev/null | rg -io 'libpng|png_read|png_create' || true; } | wc -l | tr -d ' ')"
  expect_eq "libpng in app .so" 0 "$LIBPNG_COUNT"
else
  printf 'FAIL  %-42s missing %s\n' "x86_64 libraries" "$LIBDIR"
  CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi

# --- Frida ---
TRACE_LOG="$MANUAL_OUT/dynamic/frida/trace.log"
[[ -f "$TRACE_LOG" ]] || TRACE_LOG="$LAB5/results/frida/trace.log"
MODULES_LOG="$MANUAL_OUT/dynamic/frida/modules.log"
[[ -f "$MODULES_LOG" ]] || MODULES_LOG="$LAB5/results/frida/modules-pid9066.log"

expect_contains "Frida: EmlActivity" "$TRACE_LOG" "EmlActivity"
expect_contains "Frida: openInputStream" "$TRACE_LOG" "openInputStream"
expect_contains "Frida: DocScannerCameraActivity" "$TRACE_LOG" "DocScannerCameraActivity"
expect_contains "Frida: camera360" "$MODULES_LOG" "camera360"

MANUAL_EMU="$MANUAL_OUT/dynamic/emulator"
if [[ -d "$MANUAL_EMU" ]]; then
  expect_file "manual screen-eml.png" "$MANUAL_EMU/screen-eml.png"
  expect_file "manual screen-scanner.png" "$MANUAL_EMU/screen-scanner.png"
fi

# --- FlowDroid ---
FLOW_XML="$MANUAL_OUT/static/scanners/flowdroid.xml"
[[ -f "$FLOW_XML" ]] || FLOW_XML="$LAB5/results/flowdroid/yandex-mail.xml"
if [[ -f "$FLOW_XML" ]]; then
  expect_eq "FlowDroid termination" "DataFlowOutOfMemory" \
    "$(xmllint --xpath 'string(/*/@TerminationState)' "$FLOW_XML" 2>/dev/null || true)"
  expect_eq "FlowDroid results" 18 "$(xmllint --xpath 'count(//Result)' "$FLOW_XML" 2>/dev/null || true)"
  expect_eq "FlowDroid sources" 36 "$(xmllint --xpath 'count(//Source)' "$FLOW_XML" 2>/dev/null || true)"
else
  printf 'FAIL  %-42s missing %s\n' "FlowDroid XML" "$FLOW_XML"
  CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi

# --- Trueseeing ---
TS_JSON="$MANUAL_OUT/static/scanners/trueseeing.json"
[[ -f "$TS_JSON" ]] || TS_JSON="$LAB5/results/trueseeing/yandex-mail.json"
if [[ -f "$TS_JSON" ]]; then
  expect_eq "Trueseeing package" "ru.yandex.mail" "$(jq -r '.app.package' "$TS_JSON")"
  expect_eq "Trueseeing version" "8.81.2" "$(jq -r '.app.version_name' "$TS_JSON")"
  expect_eq "Trueseeing groups" 37 "$(jq -r '.app.issues' "$TS_JSON")"
  expect_eq "Trueseeing Info" 26 "$(jq '[.issues[] | select(.severity == "Info")] | length' "$TS_JSON")"
  expect_eq "Trueseeing Medium" 6 "$(jq '[.issues[] | select(.severity == "Medium")] | length' "$TS_JSON")"
  expect_eq "Trueseeing Low" 5 "$(jq '[.issues[] | select(.severity == "Low")] | length' "$TS_JSON")"
  expect_eq "Trueseeing High" 0 "$(jq '[.issues[] | select(.severity == "High")] | length' "$TS_JSON")"
else
  printf 'FAIL  %-42s missing %s\n' "Trueseeing JSON" "$TS_JSON"
  CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi

# --- APKHunt ---
APK_LOG="$(ls -t "$MANUAL_OUT/static/scanners"/APKHunt_*.txt 2>/dev/null | head -1 || true)"
[[ -n "$APK_LOG" ]] || APK_LOG="$(ls -t "$LAB5/results/apkhunt"/APKHunt_*.txt 2>/dev/null | head -1 || true)"
if [[ -n "$APK_LOG" && -f "$APK_LOG" ]]; then
  expect_eq "APKHunt exported=0 lines" 4 "$(grep -c 'Total exported.*are: 0' "$APK_LOG" || true)"
  expect_contains "APKHunt time" "$APK_LOG" "22m"
  SAST_MANIFEST="$LAB5/results/apkhunt/yandex-mail-8-81-2_SAST/resources/AndroidManifest.xml"
  if [[ -f "$SAST_MANIFEST" ]]; then
    expect_eq "APKHunt manifest exported=true" 43 "$(grep -c 'android:exported="true"' "$SAST_MANIFEST" || true)"
  else
    warn "нет $SAST_MANIFEST; проверка 43 пропущена"
  fi
else
  printf 'FAIL  %-42s missing APKHunt log\n' "APKHunt log"
  CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi

# --- mfva ---
expect_file "mfva README" "$LAB5/sources/mfva/README.md"

# --- Отчёт и рисунки ---
expect_file "report.md" "$LAB5/report.md"
expect_file "mbks_lab_5.docx" "$LAB5/mbks_lab_5.docx"

MISSING_FIGS=0
for i in 01 02 03 04 05 06 07 08 09 10; do
  if [[ ! -f "$LAB5/figures/fig$i.png" ]]; then
    MISSING_FIGS=$((MISSING_FIGS + 1))
  fi
done
if (( MISSING_FIGS > 0 )); then
  warn "нет $MISSING_FIGS из 10 рисунков в lab5/figures (это не ошибка, пока скриншоты не сняты)"
else
  info "все 10 рисунков на месте"
fi

warn "не запускай build_report_docx.mjs, пока не решишь: он читает короткий report.md и перезапишет полный docx"

finish_checks
