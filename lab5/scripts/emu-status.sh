#!/bin/bash
# Показывает, загрузился ли эмулятор.

cd "$(dirname "$0")/../.."
source lab5/work/env.sh

adb devices

boot=$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
if [ -z "$boot" ]; then
  boot="нет"
fi
echo "boot_completed: $boot"

if [ "$boot" = "1" ]; then
  echo "эмулятор запущен"
  exit 0
fi

echo "эмулятор не запущен"
exit 1
