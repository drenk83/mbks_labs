#!/usr/bin/env sh
# Готовит сводки и PNG-изображения с выводом команд для отчёта.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RES="$ROOT/results"
SHOT="$ROOT/screenshots"
JOERN="$ROOT/work/tools/joern/joern-cli/joern"

mkdir -p "$RES" "$SHOT"
python3 "$ROOT/scripts/summarize.py"

{
    printf "CodeQL: "
    "$ROOT/work/tools/codeql/codeql" version 2>/dev/null | head -1
    printf "semgrep: "
    "$ROOT/work/venvs/semgrep/bin/semgrep" --version
    if [ -x "$JOERN" ]; then
        # joern --version открывает REPL, поэтому версия берётся из имени jar.
        querydb=$(printf '%s\n' "$ROOT"/work/tools/joern/joern-cli/lib/joernext-querydb-io.joern.querydb-*.jar)
        ver=${querydb##*-}
        printf "joern: %s\n" "${ver%.jar}"
        printf "JDK: "
        "$ROOT/work/tools/jdk-21/bin/java" -version 2>&1 | head -1
    fi
    printf "clang: "
    grep -m1 "clang version" "$ROOT/work/build/normal-1.0.30/config.log"
    printf "libsndfile vulnerable: "
    grep -m1 AC_INIT "$ROOT/work/src/libsndfile-1.0.30/configure.ac"
    printf "libsndfile fixed: "
    grep -m1 AC_INIT "$ROOT/work/src/libsndfile-1.1.0/configure.ac"
} > "$RES/versions.txt"

"$ROOT/scripts/make-shot.sh" "$SHOT/01-versions.png" \
    "Версии инструментов и проекта" "$RES/versions.txt" 1100
"$ROOT/scripts/make-shot.sh" "$SHOT/02-poc.png" \
    "PoC: падение 1.0.30 и отказ 1.1.0" "$RES/poc-summary.txt" 1200
"$ROOT/scripts/make-shot.sh" "$SHOT/03-codeql.png" \
    "CodeQL: пять CWE и своё правило" "$RES/codeql-summary.txt" 1100
"$ROOT/scripts/make-shot.sh" "$SHOT/04-semgrep.png" \
    "semgrep: штатные наборы и своё правило" "$RES/semgrep-summary.txt" 1100
"$ROOT/scripts/make-shot.sh" "$SHOT/05-joern.png" \
    "joern: штатный набор и своё правило" "$RES/joern-summary.txt" 1200
"$ROOT/scripts/make-shot.sh" "$SHOT/06-joern-custom.png" \
    "joern: своё правило на 1.0.30 и 1.1.0" "$RES/joern-custom-summary.txt" 1100

echo "готово: $SHOT"
