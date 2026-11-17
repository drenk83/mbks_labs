#!/usr/bin/env bash
# Общая библиотека для ручных этапов ЛР5.
# Подключается из stage-скриптов: source "$HERE/../lib.sh".
# Ничего не запускает сама, только задаёт пути и функции.

set -euo pipefail

MANUAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$MANUAL_DIR/../../.." && pwd)"
LAB5="$ROOT/lab5"
APK="$LAB5/work/apk/Yandex Mail_8.81.2_APKPure.apk"
EXPECTED_SHA256="6fb616ce30b13dc911a9dcdd2ddfeb3450a4eb6cbf49a99733c5aefa8680463c"
MANUAL_OUT="$LAB5/work/manual"

# shellcheck disable=SC1091
if [[ -f "$LAB5/work/env.sh" ]]; then
  source "$LAB5/work/env.sh"
fi

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '==> %s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "не найдена команда: $1"
}

need_file() {
  [[ -f "$1" ]] || die "не найден файл: $1"
}

need_exec() {
  [[ -x "$1" ]] || die "не найден исполняемый файл: $1"
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

check_apk() {
  need_file "$APK"
  local got
  got="$(sha256_file "$APK")"
  if [[ "$got" != "$EXPECTED_SHA256" ]]; then
    printf 'ERROR: SHA-256 APK не совпал.\n  expected: %s\n  got:      %s\n  file:     %s\n' \
      "$EXPECTED_SHA256" "$got" "$APK" >&2
    exit 1
  fi
  info "APK: $APK"
  info "SHA-256: $got"
}

# ensure_out DIR [FORCE]
# Не даёт молча перезаписать непустой каталог. FORCE=1 разрешает.
ensure_out() {
  local out="$1" force="${2:-0}"
  if [[ -e "$out" && -n "$(find "$out" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null || true)" && "$force" != "1" ]]; then
    die "каталог уже не пуст: $out (добавь --force для перезаписи)"
  fi
  mkdir -p "$out"
}

start_log() {
  local out="$1"
  mkdir -p "$out"
  # stdout и stderr идут и в терминал, и в run.log
  exec > >(tee "$out/run.log") 2>&1
}

# xml_count FILE TAG [total|exported|no_perm]
# local-name() нужен, потому что xmllint не подхватывает префикс android:.
xml_count() {
  local file="$1" tag="$2" mode="${3:-total}"
  case "$mode" in
    total)
      xmllint --xpath "count(//*[local-name()='$tag'])" "$file"
      ;;
    exported)
      xmllint --xpath "count(//*[local-name()='$tag'][@*[local-name()='exported']='true'])" "$file"
      ;;
    no_perm)
      xmllint --xpath "count(//*[local-name()='$tag'][@*[local-name()='exported']='true'][not(@*[local-name()='permission'])])" "$file"
      ;;
    *)
      die "xml_count: неизвестный режим $mode"
      ;;
  esac
}

# xml_string FILE XPATH
xml_string() {
  local file="$1" xpath="$2"
  xmllint --xpath "string($xpath)" "$file"
}

count_native_smali() {
  local dir="$1"
  { rg --glob '*.smali' '^\s*\.method .*\bnative\b' "$dir" 2>/dev/null || true; } | wc -l
}

# count_invoke DIR NEEDLE
# NEEDLE — подстрока smali-вызова, например 'System;->loadLibrary'.
# Экранируем regex-метасимволы в NEEDLE, но оставляем наш '.*'.
count_invoke() {
  local dir="$1" needle="$2" escaped
  escaped="$(printf '%s' "$needle" | sed 's/[][\\.^$*+?(){}|]/\\&/g')"
  { rg --glob '*.smali' "invoke.*${escaped}" "$dir" 2>/dev/null || true; } | wc -l
}

# Для 70-check.sh.
CHECKS_FAILED=0

expect_eq() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    printf 'PASS  %-42s %s\n' "$name" "$actual"
  else
    printf 'FAIL  %-42s expected %s, got %s\n' "$name" "$expected" "$actual"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
  fi
}

expect_file() {
  local name="$1" path="$2"
  if [[ -f "$path" ]]; then
    printf 'PASS  %-42s %s\n' "$name" "$path"
  else
    printf 'FAIL  %-42s missing %s\n' "$name" "$path"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
  fi
}

expect_contains() {
  local name="$1" file="$2" needle="$3"
  if [[ -f "$file" ]] && grep -qF -- "$needle" "$file"; then
    printf 'PASS  %-42s %s\n' "$name" "$needle"
  else
    printf 'FAIL  %-42s %s not found in %s\n' "$name" "$needle" "$file"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
  fi
}

expect_not_contains() {
  local name="$1" file="$2" needle="$3"
  if [[ -f "$file" ]] && ! grep -qF -- "$needle" "$file"; then
    printf 'PASS  %-42s no %s\n' "$name" "$needle"
  else
    printf 'FAIL  %-42s unexpectedly found %s in %s\n' "$name" "$needle" "$file"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
  fi
}

finish_checks() {
  if ((CHECKS_FAILED > 0)); then
    printf '\nFAILED: %s check(s)\n' "$CHECKS_FAILED" >&2
    exit 1
  fi
  printf '\nAll checks passed.\n'
}
