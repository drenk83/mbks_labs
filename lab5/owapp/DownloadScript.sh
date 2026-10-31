#!/bin/bash
# Локальная замена BenchmarkSuite/DownloadScript.sh из
# https://github.com/Mobile-IoT-Security-Lab/OWApp-Benchmarking-Suite (тег дерева на 2026-10-31).
# В этом дереве файла download_script.py уже нет: загрузка датасета живёт в DownloadScript.sh
# и требует sudo apt-get. Для варианта 11 датасет OWApp не нужен.
# Скрипт только кладёт APK преподавателя в каталог, который ждёт RunningScript.sh.

set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/work/apk/Yandex Mail_8.81.2_APKPure.apk"
DEST="$ROOT/owapp/apk"
mkdir -p "$DEST"
ln -f "$SRC" "$DEST/yandex-mail-8-81-2.apk"
echo "APK: $DEST/yandex-mail-8-81-2.apk"
sha256sum "$DEST/yandex-mail-8-81-2.apk"
echo "Дальше RunningScript смотрит этот каталог. ToolScript (sudo, Docker, apt) на стенде не запускался."
