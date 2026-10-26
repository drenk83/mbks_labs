#!/usr/bin/env sh
# Запускает semgrep: штатные наборы p/c, p/default, p/security-audit
# и собственное правило на 1.0.30 и 1.1.0.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SEMGREP="$ROOT/work/venvs/semgrep/bin/semgrep"
RES="$ROOT/results"

mkdir -p "$RES"

if [ ! -x "$SEMGREP" ]; then
    echo "ставлю semgrep в work/venvs/semgrep"
    uv venv --python 3.13 "$ROOT/work/venvs/semgrep"
    uv pip install --python "$ROOT/work/venvs/semgrep/bin/python" \
        'semgrep==1.182.1'
fi

cd "$ROOT/work/src/libsndfile-1.0.30"
echo "== p/c"
"$SEMGREP" --config=p/c --metrics=off src > "$RES/semgrep-builtin-1.0.30.txt" 2>&1 || true
echo "== p/default"
"$SEMGREP" --config=p/default --metrics=off src > "$RES/semgrep-default-1.0.30.txt" 2>&1 || true
echo "== p/security-audit"
"$SEMGREP" --config=p/security-audit --metrics=off src \
    > "$RES/semgrep-security-audit-1.0.30.txt" 2>&1 || true
"$SEMGREP" --config=p/security-audit --metrics=off --json \
    -o "$RES/semgrep-security-audit-1.0.30.json" src >/dev/null 2>&1 || true

echo "== своё правило, 1.0.30"
"$SEMGREP" --config="$ROOT/rules/semgrep/msadpcm-block-size.yaml" \
    --metrics=off src > "$RES/semgrep-custom-1.0.30.txt" 2>&1 || true

cd "$ROOT/work/src/libsndfile-1.1.0"
echo "== своё правило, 1.1.0"
"$SEMGREP" --config="$ROOT/rules/semgrep/msadpcm-block-size.yaml" \
    --metrics=off src > "$RES/semgrep-custom-1.1.0.txt" 2>&1 || true

python3 "$ROOT/scripts/summarize.py"
echo "готово: $RES"
