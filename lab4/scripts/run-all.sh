#!/usr/bin/env sh
# Полный прогон лабораторной: скачивание, сборка, PoC, CodeQL, semgrep
# и изображения для отчёта. Прогон joern в этот скрипт пока не входит.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

"$ROOT/scripts/01-fetch.sh"
"$ROOT/scripts/02-build.sh"
"$ROOT/scripts/03-poc.sh"
"$ROOT/scripts/04-codeql.sh"
"$ROOT/scripts/05-semgrep.sh"
"$ROOT/scripts/07-screenshots.sh"

echo "всё готово; отчёт: $ROOT/report.md"
