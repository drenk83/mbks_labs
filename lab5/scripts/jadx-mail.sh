#!/bin/bash
# Открывает APK Яндекс Почты в окне JADX.

cd "$(dirname "$0")/../.."
source lab5/work/env.sh

lab5/work/tools/jadx/bin/jadx-gui "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk"
