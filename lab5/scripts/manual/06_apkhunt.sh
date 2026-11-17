#!/usr/bin/env bash
# Просто запусти: ./06_apkhunt.sh
# Долго: около 22 минут.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/05_scanners.sh" --apkhunt
