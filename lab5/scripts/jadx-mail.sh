#!/usr/bin/env bash
# Открывает APK Яндекс Почты в JADX GUI. Дерево на диске не пишет и не чистит.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/lab5/work/env.sh"

apk="$ROOT/lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk"
gui="$ROOT/lab5/work/tools/jadx/bin/jadx-gui"

if [[ ! -f "$apk" ]]; then
  echo "нет APK: $apk" >&2
  exit 1
fi
if [[ ! -x "$gui" ]]; then
  echo "нет jadx-gui: $gui" >&2
  exit 1
fi

exec "$gui" "$apk"
