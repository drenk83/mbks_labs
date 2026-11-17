#!/usr/bin/env bash
# Этап 4. Нативные библиотеки x86_64: file, readelf, nm, strings.
# Пишет в lab5/work/manual/static/native-so, results/ не трогает.

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
usage: 04_native_so.sh [--force]

Достаёт lib/x86_64/*.so из APK и смотрит:
  - file: ELF/NDK;
  - readelf -d: зависимости;
  - readelf -sW / nm -D: Java_* и JNI_OnLoad;
  - strings: OSS-маркеры и libpng.

Пишет в lab5/work/manual/static/native-so.
EOF
      exit 0
      ;;
    *) die "неизвестный аргумент: $arg" ;;
  esac
done

OUT="$MANUAL_OUT/static/native-so"
LIBDIR="$OUT/x86_64"
check_apk
need unzip
need file
need readelf
need nm
need strings
need rg

ensure_out "$OUT" "$FORCE"
start_log "$OUT"

mkdir -p "$LIBDIR"
info "OUT: $OUT"
info "Достаю lib/x86_64/*.so"
unzip -o -j "$APK" 'lib/x86_64/*.so' -d "$LIBDIR" >/dev/null

shopt -s nullglob
LIBS=("$LIBDIR"/*.so)
if (( ${#LIBS[@]} == 0 )); then
  die "в APK нет lib/x86_64/*.so"
fi

file "${LIBS[@]}" | tee "$OUT/file.txt"

: > "$OUT/summary.txt"
printf '%-36s %-8s %-10s %-6s %s\n' 'library' 'Java_' 'JNI_OnLoad' 'libpng' 'NDK' | tee -a "$OUT/summary.txt"
printf '%s\n' '----------------------------------------------------------------------------' | tee -a "$OUT/summary.txt"

for so in "${LIBS[@]}"; do
  name="$(basename "$so")"
  java_exports="$({ readelf -sW "$so" 2>/dev/null | rg -o 'Java_' || true; } | wc -l)"
  jni_onload="$({ readelf -sW "$so" 2>/dev/null | rg -o 'JNI_OnLoad' || true; } | wc -l)"
  libpng="$({ strings -a "$so" 2>/dev/null | rg -io 'libpng|png_read|png_create' || true; } | wc -l)"
  ndk="$(file "$so" | rg -o 'NDK r[0-9]+' | head -1 || true)"
  printf '%-36s %-8s %-10s %-6s %s\n' "$name" "$java_exports" "$jni_onload" "$libpng" "$ndk" | tee -a "$OUT/summary.txt"

  readelf -d "$so" > "$OUT/readelf-dynamic-${name}.txt" 2>&1 || true
  { readelf -sW "$so" 2>/dev/null | rg 'Java_|JNI_OnLoad' || true; } > "$OUT/jni-${name}.txt"
  { nm -D --defined-only "$so" 2>/dev/null | rg 'Java_|JNI_OnLoad' || true; } > "$OUT/nm-${name}.txt"
  { strings -a "$so" 2>/dev/null | rg -i 'opencv|webrtc|boringssl|libyuv|libvpx|opus|speechkit|ndk|clang|gcc|protobuf|abseil|libpng' || true; } > "$OUT/oss-${name}.txt"
done

printf '\nОжидание: 4 библиотеки; libpng = 0 во всех четырёх.\n'
printf 'Полные данные: %s\n' "$OUT"
