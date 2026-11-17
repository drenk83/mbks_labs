#!/usr/bin/env bash
# Просто запусти: ./07_flowdroid.sh
# Нужно около 8 ГБ памяти; возможен обрыв DataFlowOutOfMemory.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/05_scanners.sh" --flowdroid
