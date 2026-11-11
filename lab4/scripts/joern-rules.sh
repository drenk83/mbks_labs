#!/usr/bin/env sh

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export JAVA_HOME="$ROOT/work/tools/jdk-21"
export PATH="$JAVA_HOME/bin:$PATH"

JOERN="$ROOT/work/tools/joern/joern-cli/joern"
SCAN="$ROOT/work/tools/joern/joern-cli/joern-scan"
RES="$ROOT/results"
RULE="$ROOT/rules/joern/msadpcm-block-size.sc"
RUNS="$ROOT/work/joern-runs"

cd "$RUNS/scan-1.0.30"
echo "== штатный joern-scan, 1.0.30"
"$SCAN" --overwrite --language c "$ROOT/work/src/libsndfile-1.0.30/src" \
    > "$RES/joern-builtin-1.0.30.txt" 2>&1

cd "$RUNS/custom-1.0.30"
echo "== своё правило, 1.0.30"
"$JOERN" --script "$RULE" \
    --param inputPath="$ROOT/work/src/libsndfile-1.0.30/src" \
    --param outFile="$RES/joern-custom-1.0.30.txt" \
    > "$RES/joern-custom-1.0.30.log" 2>&1

cd "$RUNS/custom-1.1.0"
echo "== своё правило, 1.1.0"
"$JOERN" --script "$RULE" \
    --param inputPath="$ROOT/work/src/libsndfile-1.1.0/src" \
    --param outFile="$RES/joern-custom-1.1.0.txt" \
    > "$RES/joern-custom-1.1.0.log" 2>&1
