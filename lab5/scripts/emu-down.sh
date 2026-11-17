#!/bin/bash
# Останавливает эмулятор lab5_api34.

cd "$(dirname "$0")/../.."
source lab5/work/env.sh

adb emu kill
sleep 3

# если окно не закрылось, убиваем только наш avd
pids=$(ps aux | grep lab5_api34 | grep -v grep | awk '{print $2}')
if [ -n "$pids" ]; then
  kill $pids
  sleep 2
  pids=$(ps aux | grep lab5_api34 | grep -v grep | awk '{print $2}')
  if [ -n "$pids" ]; then
    kill -9 $pids
  fi
fi

echo "эмулятор остановлен"
