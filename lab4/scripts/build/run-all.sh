#!/usr/bin/env sh
# Полный прогон лабораторной: скачивание, сборка, PoC, CodeQL, semgrep,
# joern и сводки.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

"$ROOT/scripts/build/01-fetch.sh"
"$ROOT/scripts/build/02-build.sh"
"$ROOT/scripts/poc.sh"
"$ROOT/scripts/build/04-codeql.sh"
"$ROOT/scripts/build/05-semgrep.sh"
"$ROOT/scripts/build/06-joern.sh"

python3 "$ROOT/scripts/build/summarize.py"

echo "всё готово; отчёт: $ROOT/report.md"
