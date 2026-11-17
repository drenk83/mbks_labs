#!/bin/bash
# Запускает эмулятор lab5_api34 с окном и ждёт загрузку Android.

cd "$(dirname "$0")/../.."
source lab5/work/env.sh

mkdir -p /tmp/lab5

# если уже запущен, второй не поднимаем
if ps aux | grep lab5_api34 | grep -v grep >/dev/null || adb devices | grep -q emulator; then
  echo "эмулятор уже есть, второй не запускаю"
else
  echo "запускаю эмулятор, лог: /tmp/lab5/emulator.log"
  # -gpu guest: swiftshader на этой машине роняет qemu
  nohup emulator -avd lab5_api34 \
    -no-audio -no-boot-anim -no-metrics \
    -gpu guest -memory 2048 -cores 2 -no-snapshot \
    -feature -Vulkan \
    > /tmp/lab5/emulator.log 2>&1 &
fi

echo "жду загрузку..."
i=0
while [ "$i" -lt 60 ]; do
  boot=$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
  if [ "$boot" = "1" ]; then
    echo "эмулятор запущен"
    exit 0
  fi
  sleep 2
  i=$((i + 1))
done

echo "не загрузился за 2 минуты, смотри /tmp/lab5/emulator.log"
exit 1
