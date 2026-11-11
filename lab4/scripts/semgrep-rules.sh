#!/usr/bin/env sh

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SEMGREP="$ROOT/work/venvs/semgrep/bin/semgrep"
RES="$ROOT/results"

cd "$ROOT/work/src/libsndfile-1.0.30"

echo "== p/c"
"$SEMGREP" --config=p/c --metrics=off --disable-version-check src > "$RES/semgrep-builtin-1.0.30.txt" 2>&1

echo "== p/default"
"$SEMGREP" --config=p/default --metrics=off --disable-version-check src > "$RES/semgrep-default-1.0.30.txt" 2>&1

echo "== p/security-audit"
"$SEMGREP" --config=p/security-audit --metrics=off --disable-version-check src > "$RES/semgrep-security-audit-1.0.30.txt" 2>&1

echo "== своё правило, 1.0.30"
"$SEMGREP" --config="$ROOT/rules/semgrep/msadpcm-block-size.yaml" \
    --metrics=off --disable-version-check src > "$RES/semgrep-custom-1.0.30.txt" 2>&1

cd "$ROOT/work/src/libsndfile-1.1.0"

echo "== своё правило, 1.1.0"
"$SEMGREP" --config="$ROOT/rules/semgrep/msadpcm-block-size.yaml" \
    --metrics=off --disable-version-check src > "$RES/semgrep-custom-1.1.0.txt" 2>&1
