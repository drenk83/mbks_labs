#!/usr/bin/env bash
# Просто запусти: ./00_all.sh
# Весь статический анализ + проверка. Около 1,5 минуты.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

"$HERE/01_androguard.sh"
"$HERE/02_manifest.sh"
"$HERE/03_smali.sh"
"$HERE/04_native_so.sh"
"$HERE/05_scanners.sh"
"$HERE/10_check.sh"
