source work/env.sh

adb root
adb push work/tools/frida/frida-server-17.4.0-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell '/data/local/tmp/frida-server >/data/local/tmp/frida.log 2>&1 &'



frida-ps -Uai | grep -i mail

sleep 40 | stdbuf -oL -eL frida -U -p PID -l scripts/manual/simple-trace.js


sleep 60 | stdbuf -oL -eL frida -U -p PID -l scripts/manual/scanner-native.js

