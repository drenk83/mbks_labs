#!/usr/bin/env sh
# Готовит сводки и PNG-изображения с выводом команд для отчёта.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RES="$ROOT/results"
SHOT="$ROOT/screenshots"
PLUGIN="$ROOT/work/plugins/lab4-msadpcm-tidy.so"

mkdir -p "$RES" "$SHOT"
python3 "$ROOT/scripts/summarize.py"

{
    printf "CodeQL: "
    "$ROOT/work/tools/codeql/codeql" version 2>/dev/null | head -1
    printf "semgrep: "
    "$ROOT/work/venvs/semgrep/bin/semgrep" --version
    printf "CodeChecker: "
    "$ROOT/work/venvs/codechecker/bin/CodeChecker" version 2>/dev/null |
        grep -m1 "Base package version"
    printf "clang: "
    clang --version | head -1
    printf "libsndfile vulnerable: "
    grep -m1 AC_INIT "$ROOT/work/src/libsndfile-1.0.30/configure.ac"
    printf "libsndfile fixed: "
    grep -m1 AC_INIT "$ROOT/work/src/libsndfile-1.1.0/configure.ac"
} > "$RES/versions.txt"

{
    echo '$ clang-tidy --load=... --checks=-*,lab4-msadpcm-block-size .../1.0.30/src/ms_adpcm.c'
    clang-tidy --load="$PLUGIN" \
        --checks='-*,lab4-msadpcm-block-size' \
        "$ROOT/work/src/libsndfile-1.0.30/src/ms_adpcm.c" -- \
        -std=gnu11 -I"$ROOT/work/build/normal-1.0.30/src" \
        -I"$ROOT/work/src/libsndfile-1.0.30/src" \
        -I"$ROOT/work/src/libsndfile-1.0.30/include" 2>&1 |
        grep -E "warning|^ +[0-9]+ \|" | head -4
    echo
    echo '$ .../1.1.0/src/ms_adpcm.c'
    out=$(clang-tidy --load="$PLUGIN" \
        --checks='-*,lab4-msadpcm-block-size' \
        "$ROOT/work/src/libsndfile-1.1.0/src/ms_adpcm.c" -- \
        -std=gnu11 -I"$ROOT/work/build/normal-1.1.0/src" \
        -I"$ROOT/work/src/libsndfile-1.1.0/src" \
        -I"$ROOT/work/src/libsndfile-1.1.0/include" 2>&1 || true)
    if [ -z "$out" ]; then
        echo "(правило не сработало — ожидаемо для исправленной версии)"
    else
        echo "$out"
    fi
} > "$RES/clang-tidy-plugin.txt"

"$ROOT/scripts/make-shot.sh" "$SHOT/01-versions.png" \
    "Версии инструментов и проекта" "$RES/versions.txt" 1100
"$ROOT/scripts/make-shot.sh" "$SHOT/02-poc.png" \
    "PoC: падение 1.0.30 и отказ 1.1.0" "$RES/poc-summary.txt" 1200
"$ROOT/scripts/make-shot.sh" "$SHOT/03-codeql.png" \
    "CodeQL: пять CWE и своё правило" "$RES/codeql-summary.txt" 1100
"$ROOT/scripts/make-shot.sh" "$SHOT/04-semgrep.png" \
    "semgrep: штатные наборы и своё правило" "$RES/semgrep-summary.txt" 1100
"$ROOT/scripts/make-shot.sh" "$SHOT/05-codechecker.png" \
    "CodeChecker: штатный набор и своё правило" "$RES/codechecker-summary.txt" 1300
"$ROOT/scripts/make-shot.sh" "$SHOT/06-clang-tidy.png" \
    "Правило CodeChecker (clang-tidy plugin)" "$RES/clang-tidy-plugin.txt" 1200

echo "готово: $SHOT"
