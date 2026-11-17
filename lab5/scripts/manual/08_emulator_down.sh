#!/usr/bin/env bash
# Просто запусти: ./08_emulator_down.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/08_emulator.sh" down
