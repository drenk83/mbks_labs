#!/usr/bin/env sh
# Штатный joern-scan по src/ libsndfile 1.0.30 и своё правило
# на 1.0.30 и 1.1.0.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
JAVA_HOME="$ROOT/work/tools/jdk-21"
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

JOERN="$ROOT/work/tools/joern/joern-cli/joern"
SCAN="$ROOT/work/tools/joern/joern-cli/joern-scan"
RES="$ROOT/results"
RULE="$ROOT/rules/joern/msadpcm-block-size.sc"
RUNS="$ROOT/work/joern-runs"

mkdir -p "$RES" "$RUNS"

if [ ! -x "$JOERN" ]; then
    echo "joern не найден: $JOERN" >&2
    exit 1
fi

echo "== штатный joern-scan, 1.0.30"
mkdir -p "$RUNS/scan-1.0.30"
(
    cd "$RUNS/scan-1.0.30"
    "$SCAN" --language c \
        "$ROOT/work/src/libsndfile-1.0.30/src" \
        > "$RES/joern-builtin-1.0.30.txt" 2>&1
) || true

echo "== своё правило, 1.0.30"
mkdir -p "$RUNS/custom-1.0.30"
(
    cd "$RUNS/custom-1.0.30"
    "$JOERN" --script "$RULE" \
        --param inputPath="$ROOT/work/src/libsndfile-1.0.30/src" \
        --param outFile="$RES/joern-custom-1.0.30.txt"
) > "$RES/joern-custom-1.0.30.log" 2>&1

echo "== своё правило, 1.1.0"
mkdir -p "$RUNS/custom-1.1.0"
(
    cd "$RUNS/custom-1.1.0"
    "$JOERN" --script "$RULE" \
        --param inputPath="$ROOT/work/src/libsndfile-1.1.0/src" \
        --param outFile="$RES/joern-custom-1.1.0.txt"
) > "$RES/joern-custom-1.1.0.log" 2>&1

echo "готово: $RES/joern-builtin-1.0.30.txt"
echo "        $RES/joern-custom-1.0.30.txt"
echo "        $RES/joern-custom-1.1.0.txt"
