#!/usr/bin/env bash
# Этап 2. Манифест: apktool --only-manifest + xmllint.
# Пишет в lab5/work/manual/static/manifest, results/ не трогает.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/lib.sh"

FORCE=1
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    -h|--help)
      cat <<'EOF'
usage: 02_manifest.sh [--force]

Декодирует AndroidManifest.xml через apktool и считает:
  - package, versionName, versionCode, allowBackup;
  - total / exported=true / exported=true без permission
    для activity, activity-alias, service, receiver, provider.

Пишет в lab5/work/manual/static/manifest.
EOF
      exit 0
      ;;
    *) die "неизвестный аргумент: $arg" ;;
  esac
done

OUT="$MANUAL_OUT/static/manifest"
check_apk
need apktool
need xmllint

ensure_out "$OUT" "$FORCE"
start_log "$OUT"

info "OUT: $OUT"
info "Декодирую только манифест (без smali)"

if ! apktool d -f -s --only-manifest -o "$OUT/apktool" "$APK" > "$OUT/apktool.log" 2>&1; then
  tail -n 40 "$OUT/apktool.log" || true
  die "apktool завершился с ошибкой; лог: $OUT/apktool.log"
fi
info "apktool: ok (лог $OUT/apktool.log)"

MANIFEST="$OUT/apktool/AndroidManifest.xml"
YML="$OUT/apktool/apktool.yml"
need_file "$MANIFEST"
xmllint --noout "$MANIFEST"
xmllint --format "$MANIFEST" > "$OUT/AndroidManifest.pretty.xml"

# apktool выносит versionCode/versionName/minSdk/targetSdk в apktool.yml,
# а в декодированном манифесте их может не быть.
PKG="$(xml_string "$MANIFEST" '/*[local-name()="manifest"]/@package')"
ALLOW_BACKUP="$(xml_string "$MANIFEST" '//*[local-name()="application"]/@*[local-name()="allowBackup"]')"
VERSION_NAME=""
VERSION_CODE=""
MIN_SDK=""
TARGET_SDK=""
if [[ -f "$YML" ]]; then
  VERSION_NAME="$(awk '/^versionInfo:/{f=1;next} f && /^[^ ]/{f=0} f && /versionName:/{print $2; exit}' "$YML")"
  VERSION_CODE="$(awk '/^versionInfo:/{f=1;next} f && /^[^ ]/{f=0} f && /versionCode:/{print $2; exit}' "$YML")"
  MIN_SDK="$(awk '/^sdkInfo:/{f=1;next} f && /^[^ ]/{f=0} f && /minSdkVersion:/{print $2; exit}' "$YML")"
  TARGET_SDK="$(awk '/^sdkInfo:/{f=1;next} f && /^[^ ]/{f=0} f && /targetSdkVersion:/{print $2; exit}' "$YML")"
fi
# Запасной путь: атрибуты в манифесте, если apktool их всё же оставил.
[[ -n "$VERSION_NAME" ]] || VERSION_NAME="$(xml_string "$MANIFEST" '/*[local-name()="manifest"]/@*[local-name()="versionName"]')"
[[ -n "$VERSION_CODE" ]] || VERSION_CODE="$(xml_string "$MANIFEST" '/*[local-name()="manifest"]/@*[local-name()="versionCode"]')"
[[ -n "$MIN_SDK" ]] || MIN_SDK="$(xml_string "$MANIFEST" '//*[local-name()="uses-sdk"]/@*[local-name()="minSdkVersion"]')"
[[ -n "$TARGET_SDK" ]] || TARGET_SDK="$(xml_string "$MANIFEST" '//*[local-name()="uses-sdk"]/@*[local-name()="targetSdkVersion"]')"

{
  printf 'package=%s\n' "$PKG"
  printf 'versionName=%s\n' "$VERSION_NAME"
  printf 'versionCode=%s\n' "$VERSION_CODE"
  printf 'minSdk=%s\n' "$MIN_SDK"
  printf 'targetSdk=%s\n' "$TARGET_SDK"
  printf 'allowBackup=%s\n' "$ALLOW_BACKUP"
} | tee "$OUT/summary.txt"

printf '\n%-15s %-6s %-9s %s\n' 'tag' 'total' 'exported' 'no_permission'
printf '%s\n' '------------------------------------------------'
: > "$OUT/counts.txt"
printf 'tag\ttotal\texported\tno_perm\n' >> "$OUT/counts.txt"

TOTAL_EXPORTED=0
for tag in activity activity-alias service receiver provider; do
  total="$(xml_count "$MANIFEST" "$tag" total)"
  exported="$(xml_count "$MANIFEST" "$tag" exported)"
  no_perm="$(xml_count "$MANIFEST" "$tag" no_perm)"
  TOTAL_EXPORTED=$((TOTAL_EXPORTED + exported))
  printf '%-15s %-6s %-9s %s\n' "$tag" "$total" "$exported" "$no_perm"
  printf '%s\t%s\t%s\t%s\n' "$tag" "$total" "$exported" "$no_perm" >> "$OUT/counts.txt"
done

printf '\nexported=true всего: %s\n' "$TOTAL_EXPORTED"
printf 'grep по атрибуту: %s\n' "$(grep -c 'android:exported="true"' "$MANIFEST" || true)"

: > "$OUT/exported.txt"
for tag in activity activity-alias service receiver provider; do
  printf '\n== %s ==\n' "$tag" >> "$OUT/exported.txt"
  {
    xmllint --xpath \
      "//*[local-name()='$tag'][@*[local-name()='exported']='true']/@*[local-name()='name']" \
      "$MANIFEST" 2>/dev/null || true
  } | sed 's/ android:name=/\nandroid:name=/g' >> "$OUT/exported.txt"
done

printf '\nСписки компонентов: %s\n' "$OUT/exported.txt"
printf 'Ожидание: activity 14, alias 7, service 5, receiver 14, provider 3; всего 43.\n'
