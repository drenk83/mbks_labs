# Ранбук: анализ Yandex Mail в ЛР5

Вариант 11. Чёрный ящик — Yandex Mail 8.81.2, пакет `ru.yandex.mail`.
Белый ящик — `mfva`, пакет `com.appknox.mfva`.

Файл описывает, как выполнялся анализ Yandex Mail, что и в каком порядке запускать скриптами и руками, какие цифры должны получиться и чем текущая работа отличается от отчётов из `~/Documents/mbks/3`.

---

## 1. Что это за лабораторная

ЛР5, вариант 11, два приложения:

| Роль | Приложение | Пакет | Что делали |
|---|---|---|---|
| Белый ящик | `mfva` (в задании опечатка `mvfa`) | `com.appknox.mfva` | читали исходники, разбирали по 8 категориям MASVS |
| Чёрный ящик | Yandex Mail 8.81.2 | `ru.yandex.mail` | APK → JADX → манифест → эмулятор → Frida → статические анализаторы |

Задание требует: MASVS/MSTG, декомпиляцию, разбор манифеста, поиск Source/Sink, запуск в эмуляторе, трассу Frida, перечень native-методов, OSS-компоненты в `.so`, FlowDroid, OWApp, отчёт.

### 1.1. Если нужно быстро проверить, что всё на месте

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
source lab5/work/env.sh
lab5/scripts/manual/10_check.sh
```

`10_check.sh` — только чтение, ничего не запускает. Он сверяет APK, манифест, native, API, `.so`, Frida, FlowDroid, Trueseeing и APKHunt. Сейчас даёт `55 PASS`, `0 FAIL`; предупреждения про отсутствующие рисунки и docx не считаются ошибкой. Если нужного артефакта нет в `work/manual/`, проверка берёт его из `results/`.

Если нужно перегенерировать статику с нуля:

```sh
cd lab5/scripts/manual
./00_all.sh
```

Это около 2–3 минут: androguard, apktool-манифест, smali, `.so`, Trueseeing и проверка. APKHunt и FlowDroid в `00_all.sh` не входят — они запускаются отдельно.

### 1.2. Где что лежит

- `lab5/report.md` — короткая рабочая версия отчёта, 10 мест под рисунки.
- `lab5/mbks_lab_5.docx` — полный отчёт (около 35 тыс. символов, 2 скриншота телефона).
- `lab5/Журнал_действий.md` — что и как запускали, с командами и цифрами.
- `lab5/Лаб5_самоучитель_и_защита.md` и `guide.html` — разжёванный разбор для защиты.
- `lab5/scripts/` — общие скрипты: `audit_apk.py`, `jadx-mail.sh`, `trace.js`, `run_trace.py`, `emu-up.sh`, `emu-status.sh`, `emu-down.sh`, `build_report_docx.mjs`.
- `lab5/scripts/manual/` — пошаговые скрипты `00_all.sh` … `10_check.sh`, `lib.sh`, `simple-trace.js` и `README.md`.
- `lab5/results/` — архивный эталон: манифест, native-методы, API-hits, трасса Frida, XML FlowDroid, JSON Trueseeing, лог APKHunt, OWApp.
- `lab5/sources/` — только исходники mfva; в git не входит. Дерево JADX почты удалено, классы открывает `jadx-mail.sh`. `10_check.sh` проверяет `sources/mfva/README.md`.
- `lab5/work/` — APK, Android SDK, AVD, JADX, Frida-server, venv’ы, инструменты. В git не входит.
- `lab5/work/manual/` — выходы ручных скриптов: `static/` и `dynamic/`. Тоже не входит в git, перегенерируется.
- `lab5/owapp/` — локальные `DownloadScript.sh` и `RunningScript.sh`; `owapp/apk/` с копией APK и артефактами APKHunt в git не входит.
- `lab5/figures/` — рисунки `fig01.png` … `fig10.png`; пока не созданы.

### 1.3. Что считать эталоном

| Источник | Что это | Можно ли перезаписывать |
|---|---|---|
| `lab5/results/` | архивный прогон, цифры для отчёта | нет, скрипты его не трогают |
| `lab5/work/manual/` | свежий прогон теми же командами | да, скрипты пишут сюда |
| `lab5/results/owapp/` | прогон через OWApp, сейчас частичный | да, `RunningScript.sh` перезапишет |
| `lab5/work/apk/` | исходный APK | нет |

Если цифры в `work/manual` немного отличаются от `results`, это нормально: Trueseeing, например, даёт разное общее число срабатываний при одном и том же APK. Для отчёта остаются цифры из `results`, а `work/manual` нужен, чтобы показать, что ты умеешь получать их сам.

Важно: **полный отчёт в docx, а `report.md` — краткая версия**. Сборщик `build_report_docx.mjs` читает именно `report.md`. Если сейчас запустить его, он перезапишет полный docx короткой версией. Это надо учитывать перед пересборкой.

---

## 2. Как анализировали Yandex Mail — по шагам

### 2.1. Подготовка

Скрипты из `lab5/scripts/manual/` сами подхватывают `lab5/work/env.sh`, поэтому запускать их можно из любого каталога. `source` нужен только для ручных команд и для интерактивного JADX.

Из корня репозитория:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
source lab5/work/env.sh

sha256sum "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk"
java -version
jadx --version
frida --version
```

Ожидается:

- SHA-256 `6fb616ce30b13dc911a9dcdd2ddfeb3450a4eb6cbf49a99733c5aefa8680463c`;
- Java 21 (Temurin);
- JADX 1.5.6;
- Frida 17.4.0.

Если `frida --version` показывает 16.7.19 — в `PATH` попал `venvs/analysis`; нужен новый терминал и снова `source`.

### 2.2. JADX: манифест и код

```sh
lab5/scripts/jadx-mail.sh
```

Скрипт открывает APK в JADX GUI. Первый разбор идёт несколько минут.

Что смотреть:

1. `AndroidManifest.xml` — искать `EmlActivity`.
   - `android:exported="true"`;
   - `android:permission` отсутствует;
   - фильтр `ACTION_VIEW` на `message/rfc822` и `application/eml`;
   - второй фильтр на путь `.*\.eml`.

2. `Ctrl+N` → `EmlActivity`.
   - `onCreate` берёт `getIntent().getData()`;
   - вызывает `ContentResolver.openInputStream`;
   - читает текст и кладёт в WebView.

3. `Ctrl+N` → `DocScannerCameraActivity`.
   - у неё нет `exported` и нет фильтра;
   - в `onCreate` при пустом bundle вызывает `System.loadLibrary("camera360-arcadia")`.

Это и есть главная цепочка:

```text
чужое приложение / «Файлы»
  → ACTION_VIEW на .eml
  → EmlActivity.onCreate
  → ContentResolver.openInputStream
  → текст в WebView
```

Сканер — отдельная цепочка:

```text
DocScannerCameraActivity (не exported)
  → пустой bundle
  → System.loadLibrary("camera360-arcadia")
```

### 2.3. Статический разбор APK через androguard

Основной путь — `01_androguard.sh`. Он запускает `scripts/audit_apk.py` через `work/venvs/analysis` и складывает всё в `work/manual/static/androguard`, не трогая `results/`:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
lab5/scripts/manual/01_androguard.sh
```

Что получится в `lab5/work/manual/static/androguard/`:

- `out/manifest.txt` / `out/manifest.json`;
- `out/natives.txt` / `out/natives.json` — все native-методы;
- `out/native-sinks.txt` — те же методы в формате стока FlowDroid;
- `out/load-libraries.json` — места загрузки библиотек;
- `out/api-hits.txt` / `out/api-hits.json` — счётчики опасных вызовов;
- `summary.txt` — короткая выжимка;
- `audit.log`, `run.log` — полный вывод.

Ключевые цифры:

- классов 59 178;
- методов 260 516;
- native-методов 339;
- активности: 108 всего, 20 с входом снаружи;
- сервисы: 32 / 12;
- приёмники: 35 / 29;
- провайдеры: 20, экспортированы 3.

Важно: 20 активностей «с входом снаружи» — это метрика androguard. У apktool по атрибуту `android:exported="true"` будет 14 активностей, 5 сервисов, 14 приёмников и 3 провайдера, всего 43. Это разные способы считать поверхность атаки, они не противоречат друг другу.

Именно эти цифры надо называть, а не «ноль экспортированных» из APKHunt.

Ручной эквивалент без stage-скрипта:

```sh
lab5/work/venvs/analysis/bin/python lab5/scripts/audit_apk.py \
  "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk" \
  /tmp/lab5-audit-out
```

### 2.4. Нативные библиотеки и OSS

Скриптом:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
lab5/scripts/manual/04_native_so.sh
```

Он достаёт `lib/x86_64/*.so` из APK и пишет в `lab5/work/manual/static/native-so/`:

- `x86_64/*.so` — четыре библиотеки;
- `file.txt` — тип ELF и NDK;
- `summary.txt` — таблица `Java_`, `JNI_OnLoad`, `libpng`, `NDK`;
- `readelf-dynamic-*.txt` — зависимости;
- `jni-*.txt`, `nm-*.txt` — экспорты `Java_*` и `JNI_OnLoad`;
- `oss-*.txt` — маркеры OpenCV, WebRTC, BoringSSL, libyuv, libvpx, Opus, SpeechKit.

В APK четыре библиотеки x86_64:

```text
libcamera360-arcadia.so          OpenCV, сканер документов; NDK r22, Java_ 235, JNI_OnLoad нет
libjingle_peerconnection_so.so   WebRTC, BoringSSL, libyuv, libvpx, Opus; NDK r20, Java_ 170
libYandexSpeechKitJni.4.15.7.so  SpeechKit 4.15.7; Java_ 115
libeye.so                        EyeNative, камера эффектов; NDK r21e, Java_ 8
```

Ожидание: четыре ELF x86-64, у `libpng` — нули во всех четырёх. Готовая сводка: `lab5/results/oss-summary.txt`.

Ручной эквивалент:

```sh
mkdir -p /tmp/lab5-native
unzip -o -j "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk" \
  'lib/x86_64/*.so' -d /tmp/lab5-native

file /tmp/lab5-native/*.so
grep -a -E -c 'libpng|png_read|png_create' /tmp/lab5-native/*.so
```

### 2.5. Эмулятор и сценарий с `.eml`

Эмулятор: AVD `lab5_api34`, API 34, google_apis, x86_64.

Скриптом:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
lab5/scripts/manual/08_emulator.sh
```

Без аргументов это `demo`: поднять эмулятор с окном, установить APK, положить `.eml`, открыть письмо, открыть сканер, снять два скриншота. Всё пишется в `lab5/work/manual/dynamic/emulator/`:

- `lab5-external.eml` — письмо с маркером;
- `screen-eml.png` — письмо;
- `screen-scanner.png` — сканер.

Подкоманды:

| Команда | Что делает |
|---|---|
| `./08_emulator.sh status` | состояние AVD через `emu-status.sh` |
| `./08_emulator.sh up` | поднять AVD с окном |
| `./08_emulator.sh install` | установить APK |
| `./08_emulator.sh eml` | создать и положить `.eml` в `/data/data/ru.yandex.mail/files/` |
| `./08_emulator.sh start` | открыть `.eml` через `EmlActivity`, снять `screen-eml.png` |
| `./08_emulator.sh scanner` | открыть `DocScannerCameraActivity`, снять `screen-scanner.png` |
| `./08_emulator.sh demo` | `up` + `install` + `eml` + `start` + `scanner` |
| `./08_emulator.sh down` | остановить эмулятор |

`./08_emulator.sh up` поднимает AVD с окном. Запуска без окна нет.

Что происходит внутри:

1. `emu-up.sh` поднимает AVD с окном и ждёт `sys.boot_completed=1` до 120 с.
2. `adb install -r` ставит APK. Если ошибка `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, скрипт подсказывает `adb uninstall ru.yandex.mail`.
3. `adb root`, затем `.eml` кладётся в приватный каталог почты, `chown` на uid приложения и `chmod 640`.
4. `am start -a android.intent.action.VIEW -d file:///... -t message/rfc822 -n ru.yandex.mail/com.yandex.mail.eml.EmlActivity`.
5. Пауза 8 секунд, чтобы WebView успел отрисовать письмо, затем `screencap`.
6. Сканер запускается по имени компонента, пауза 2 секунды, второй `screencap`.

На экране письма должна быть тема `lab5 external eml` и маркер `LAB5-EML-MARKER`. Сканер не exported, поэтому из чужого приложения он не запустится; запуск с root adb — это не атака, а способ показать загрузку библиотеки.

Ручной эквивалент, если нужно понимать каждую команду:

```sh
lab5/scripts/emu-status.sh
lab5/scripts/emu-up.sh
adb devices

adb install -r "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk"
adb shell monkey -p ru.yandex.mail -c android.intent.category.LAUNCHER 1
```

Письмо:

```sh
cat > /tmp/lab5-external.eml <<'EOF'
From: attacker@example.invalid
To: victim@example.invalid
Subject: lab5 external eml
Date: Tue, 17 Nov 2026 00:00:00 +0300
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

LAB5-EML-MARKER
External .eml opened by Yandex Mail.
EOF

adb root
adb push /tmp/lab5-external.eml /data/data/ru.yandex.mail/files/lab5-external.eml
uid=$(adb shell stat -c %u /data/data/ru.yandex.mail | tr -d '\r')
adb shell chown "$uid:$uid" /data/data/ru.yandex.mail/files/lab5-external.eml
adb shell chmod 640 /data/data/ru.yandex.mail/files/lab5-external.eml
```

Если `adb push` не может создать файл:

```sh
adb shell "cat > /data/data/ru.yandex.mail/files/lab5-external.eml" < /tmp/lab5-external.eml
```

Запуск и скриншоты:

```sh
adb shell am force-stop ru.yandex.mail
adb shell am start -a android.intent.action.VIEW \
  -d file:///data/data/ru.yandex.mail/files/lab5-external.eml \
  -t message/rfc822 \
  -n ru.yandex.mail/com.yandex.mail.eml.EmlActivity
sleep 8
adb exec-out screencap -p > /tmp/lab5-eml.png

adb shell am start -n ru.yandex.mail/com.yandex.mail360.camera.doc.scanner.DocScannerCameraActivity
sleep 2
adb exec-out screencap -p > /tmp/lab5-scanner.png
```

Остановка:

```sh
lab5/scripts/manual/08_emulator_down.sh
# или
lab5/scripts/manual/08_emulator.sh down
```

### 2.6. Frida: трасса чтения `.eml`

Скриптом:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
lab5/scripts/manual/09_frida.sh
```

Без аргументов это `all`: `server` + `ps` + `trace --auto` + `modules`. Всё пишется в `lab5/work/manual/dynamic/frida/`:

- `trace.log` — события `EmlActivity`, `openInputStream`, сканера;
- `modules.log` — карта модулей и `camera360`;
- `modules.js` — скрипт второго attach.

Подкоманды:

| Команда | Что делает |
|---|---|
| `./09_frida.sh status` | версия Frida, `adb devices`, процессы почты |
| `./09_frida.sh server` | `adb root`, push `frida-server-17.4.0`, запуск |
| `./09_frida.sh ps` | ищет процесс `Yandex Mail` |
| `./09_frida.sh trace` | attach по PID и трасса `simple-trace.js` |
| `./09_frida.sh trace --auto` | сам открывает `.eml` через 3 с и сканер через 10 с |
| `./09_frida.sh modules` | второй attach на 10 с, ищет `camera360` |
| `./09_frida.sh all` | всё перечисленное |

Что происходит в `trace --auto`:

1. `adb shell am force-stop ru.yandex.mail` — чтобы сверху не остался сканер.
2. Запуск приложения через `monkey`, пауза 2 с.
3. PID берётся из `frida-ps -Uai` по двум столбцам `Yandex Mail`.
4. Через 3 с открывается `.eml`, через 10 с — сканер.
5. Сессия Frida держится 30 с, общий `timeout` — 45 с.

В `trace.log` должны появиться:

```text
EmlActivity.onCreate action=android.intent.action.VIEW
  type=message/rfc822
  data=file:///data/data/ru.yandex.mail/files/lab5-external.eml
  bundleNull=true
openInputStream uri=file:///data/data/ru.yandex.mail/files/lab5-external.eml
DocScannerCameraActivity.onCreate bundleNull=true
```

`modules.log`:

```text
libcamera360-arcadia.so | /data/app/.../base.apk!/lib/x86_64/libcamera360-arcadia.so
total 330
```

`09_frida.sh` использует `simple-trace.js`: только `EmlActivity.onCreate`, `DocScannerCameraActivity.onCreate` и `ContentResolver.openInputStream`. Большой `lab5/scripts/trace.js` остаётся для продвинутого разбора: он дополнительно ставит observer на модули и хуки на JNI-экспорты, но с ним легче уронить процесс почты.

Ручной эквивалент. Сервер:

```sh
adb root
adb push lab5/work/tools/frida/frida-server-17.4.0-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell '/data/local/tmp/frida-server >/data/local/tmp/frida.log 2>&1 &'
```

Процесс:

```sh
frida-ps -Uai | grep -i mail
```

В списке имя процесса — `Yandex Mail`, не `ru.yandex.mail`. Берём PID. Сессия (важно: `sleep` держит stdin, иначе Frida сразу выходит):

```sh
PID=$(frida-ps -Uai | awk '/Yandex Mail/ {print $1; exit}')
sleep 120 | stdbuf -oL -eL frida -U -p "$PID" -l lab5/scripts/trace.js | tee /tmp/lab5-trace.log
```

Пока сессия жива, во втором терминале запускаем `am start` из раздела 2.5. Второй attach — карта модулей:

```sh
cat > /tmp/lab5-modules.js <<'EOF'
var mods = Process.enumerateModules();
var hits = mods.filter(function (m) {
  return m.name.indexOf('camera360') !== -1;
}).map(function (m) {
  return m.name + ' | ' + m.path;
});
send({ pid: Process.id, hits: hits, total: mods.length });
EOF

sleep 10 | stdbuf -oL -eL frida -U -p "$PID" -l /tmp/lab5-modules.js
```

Готовые логи архивного прогона: `results/frida/trace.log`, `results/frida/modules-pid9066.log`. Свежий прогон скриптом: `work/manual/dynamic/frida/trace.log`, `work/manual/dynamic/frida/modules.log`.

### 2.7. FlowDroid

Скриптом:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
lab5/scripts/manual/07_flowdroid.sh
```

Это обёртка над `05_scanners.sh --flowdroid`. Пишет `work/manual/static/scanners/flowdroid.xml`, `flowdroid.log` и `flowdroid-summary.txt`. Нужно около 8 ГБ памяти; возможен обрыв `DataFlowOutOfMemory`.

Ручной эквивалент:

```sh
java -Xmx8g -cp "$(cat lab5/work/tools/flowdroid/classpath.txt)" \
  soot.jimple.infoflow.cmd.MainClass \
  -a "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk" \
  -p lab5/work/android-sdk/platforms \
  -s lab5/work/tools/flowdroid/SourcesAndSinks.txt \
  -o /tmp/lab5-flowdroid.xml \
  -cg CHA -ca FAST -l NONE -dt 480 -ct 120 -mt 4 -lp
```

Что получилось:

- 18 результатов, 36 источников;
- `TerminationState="DataFlowOutOfMemory"`;
- в XML: `TotalRuntimeSeconds=340`, `MaxMemoryConsumption=8379`;
- в консоли решатель: 86 секунд, 8512 МБ.

Скрипт пишет XML в `work/manual/static/scanners/flowdroid.xml`, архивный файл — `results/flowdroid/yandex-mail.xml`. `10_check.sh` сначала ищет свежий, потом архивный.

18 путей — это аналитика, курсоры, кэш Lottie, `SharingFileProvider`, выбор компонента Passport. Письма и `openInputStream` среди них нет. Это **не** доказательство, что пути нет: прогон оборвался по памяти. Для письма доказательство — код `EmlActivity` и трасса Frida.

Важно: `grep -c '<Result>'` на этом XML даст `1`, потому что XML в одну строку. Считать так:

```sh
python3 - <<'PY'
import xml.etree.ElementTree as ET
r = ET.parse('lab5/results/flowdroid/yandex-mail.xml').getroot()
print('termination', r.get('TerminationState'))
print('results', len(r.findall('.//Results/Result')))
print('sources', len(r.findall('.//Results/Result/Sources/Source')))
PY
```

Или:

```sh
grep -o '<Result>' lab5/results/flowdroid/yandex-mail.xml | wc -l
```

### 2.8. Trueseeing

Скриптом:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
lab5/scripts/manual/05_scanners.sh
```

Без флагов `05_scanners.sh` запускает только Trueseeing, около 50–70 секунд. Пишет `work/manual/static/scanners/trueseeing.json`, `trueseeing.log` и `trueseeing-summary.txt`.

Ожидание: `done, found ... issues (... sec.)`. В JSON 37 групп:

- Info 26;
- Medium 6;
- Low 5;
- High нет.

Общее число срабатываний у Trueseeing плавает: в архивном прогоне было `8068`, в свежих — `8072` и `8077`. Групп всегда 37, разбивка по severity та же. Для отчёта бери `results/trueseeing/yandex-mail.json`; расхождение общего числа не означает, что APK другой.

Ручной эквивалент:

```sh
lab5/work/venvs/analysis/bin/trueseeing \
  -eqc 'as;gj! /tmp/lab5-trueseeing.json' \
  "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk"
```

Проверка:

```sh
python3 - <<'PY'
import json
from collections import Counter
d = json.load(open('lab5/results/trueseeing/yandex-mail.json'))
print(d['app']['package'], d['app']['version_name'], d['app']['issues'])
print(Counter(i['severity'] for i in d['issues']))
PY
```

### 2.9. APKHunt

Скриптом:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
lab5/scripts/manual/06_apkhunt.sh
```

Это обёртка над `05_scanners.sh --apkhunt`. Идёт 22+ минуты, пишет `work/manual/static/scanners/`: `apkhunt-run.log`, `apkhunt-summary.txt`, `APKHunt_*.txt/html`, SAST-дерево и jar. `10_check.sh` читает сводку оттуда, а если её нет — из `results/apkhunt/`.

APKHunt не принимает имя с пробелами и точками, поэтому нужна жёсткая ссылка:

```sh
ln -f "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk" /tmp/yandex-mail-8-81-2.apk
cd /tmp
apkhunt -p /tmp/yandex-mail-8-81-2.apk -l
```

Идёт около 22 минут, внутри запускает JADX и dex2jar. В сводке:

- четыре строки `Total exported ... are: 0`;
- `Total time taken for hunting: 22m14.841748933s`;
- `allowBackup="true"` не найден, `debuggable="true"` не найден;
- журналы 455 файлов / 1451 вхождение;
- жёсткие ссылки 250 / 473.

Ноль экспортированных — **ошибка сводки**. В манифесте того же прогона:

```sh
grep -c 'android:exported="true"' \
  lab5/results/apkhunt/yandex-mail-8-81-2_SAST/resources/AndroidManifest.xml
```

Даёт `43`. Для поверхности атаки используем androguard: 20 активностей из 108, 12 сервисов из 32, 29 приёмников из 35, 3 провайдера из 20.

### 2.10. OWApp

В наборе OWApp есть `DownloadScript.sh` и `RunningScript.sh`. В задании упомянут `download_script.py`, но в репозитории его нет.

`DownloadScript.sh` — локальная замена загрузки датасета. Пакеты не ставит, датасет не качает, только делает жёсткую ссылку APK в `lab5/owapp/apk/yandex-mail-8-81-2.apk` и печатает SHA-256:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs/lab5/owapp
./DownloadScript.sh
```

`RunningScript.sh` запускает инструменты по APK из `owapp/apk/` и пишет в `lab5/results/owapp/`:

| Режим | Что запускает | Куда пишет |
|---|---|---|
| `--check` | проверка APK, Trueseeing, APKHunt, Docker; ничего не сканирует | только вывод |
| `--trueseeing` | Trueseeing | `results/owapp/<base>-trueseeing.json/log` |
| `--apkhunt` | APKHunt, 22+ минуты | `results/owapp/<base>-apkhunt.log`; `APKHunt_*.txt/html` и SAST — рядом с APK в `owapp/apk/` |
| `--sebastian` | SEBASTiAN в Docker | `results/owapp/sebastian/` |
| `--all` | Trueseeing + APKHunt + SEBASTiAN, если Docker доступен | всё перечисленное |

Без флага — `--all`. Можно передать другой каталог с APK первым аргументом. Перед запуском полезно:

```sh
./RunningScript.sh --check
```

`--check` покажет, видит ли скрипт `trueseeing`, `apkhunt` и Docker. Для SEBASTiAN скрипт сам пробует `sudo systemctl start docker` и `sudo docker`; пароль sudo вводится в терминале. MobSF в этом скрипте не запускается: в OWApp он ставится локально и работает через `MobsfReport.py`.

Фактический прогон 2026-11-17:

- Trueseeing завершился: `done, found 8072 issues (49.09 sec.)`, 37 групп, Info 26 / Medium 6 / Low 5 / High 0. Это тот же APK по SHA-256, что и в `results`.
- APKHunt стартовал в 23:07:17, но был прерван примерно через минуту. В `results/owapp/yandex-mail-8-81-2-apkhunt.log` 1136 строк, последняя — про Realm Database; строк `Total time taken` и `Scan has been finished` нет. Текст и HTML APKHunt по 78 КБ лежат в `owapp/apk/`, но это **неполный** прогон.
- SEBASTiAN не дал результата: Docker-часть не подтверждена, каталога `results/owapp/sebastian/` нет.
- MobSF пропущен по устройству OWApp.

Поэтому в отчёте для APKHunt используются цифры архивного полного прогона из `results/apkhunt/` (22m14.841748933s), а OWApp-прогон упоминается как частичный. Если нужен полный OWApp-результат, запусти `./RunningScript.sh --apkhunt` и дождись финальной строки.

---

## 3. Ручной runbook: два маршрута

### Маршрут A. Быстрый, 10–15 минут, без эмулятора

Главный инструмент — `10_check.sh`. Он ничего не запускает и не перезаписывает:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
source lab5/work/env.sh
lab5/scripts/manual/10_check.sh
```

Сейчас это `55 PASS`, `0 FAIL`. Два предупреждения — про отсутствующие `figures/` и про риск `build_report_docx.mjs` — не являются ошибкой. Если нужного артефакта нет в `work/manual/`, скрипт берёт его из `results/`.

Если хочется посмотреть глазами, минимальный набор:

```sh
sha256sum "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk"

sed -n '1,6p'   lab5/results/manifest.txt
sed -n '74,77p' lab5/results/manifest.txt
sed -n '1,4p'   lab5/results/natives.txt
sed -n '1,12p'  lab5/results/api-hits.txt

grep -E 'EmlActivity|openInputStream|DocScanner|watched=' \
  lab5/results/frida/trace.log
grep camera360 lab5/results/frida/modules-pid9066.log
```

И открыть:

- `lab5/results/frida/screen-eml.png` — письмо с маркером;
- `lab5/results/frida/screen-scanner.png` — сканер.

Это позволяет «показать» работу. Но не показывает, как её делали. Для этого — маршрут B.

### Маршрут B. Полный, 2–4 часа

Порядок такой:

1. **Статика скриптами** — 2–3 минуты.
   - `cd lab5/scripts/manual`;
   - `./00_all.sh`;
   - внутри: `01_androguard.sh`, `02_manifest.sh`, `03_smali.sh`, `04_native_so.sh`, `05_scanners.sh` (Trueseeing), `10_check.sh`;
   - выходы в `work/manual/static/`, `results/` не трогаются;
   - дальше команды `./...` в этом маршруте — из `lab5/scripts/manual`.

2. **JADX** — 15–20 минут.
   - `lab5/scripts/jadx-mail.sh`;
   - манифест: `EmlActivity`, `exported`, фильтры;
   - `EmlActivity`: `getData`, `openInputStream`, WebView;
   - `DocScannerCameraActivity`: `loadLibrary("camera360-arcadia")`.

3. **APKHunt** — 22–25 минут, опционально.
   - `./06_apkhunt.sh`;
   - читать сводку, но не верить `exported=0`;
   - проверить 43 вхождения `android:exported="true"` в SAST-манифесте.

4. **FlowDroid** — 5–15 минут, 8 ГБ, опционально.
   - `./07_flowdroid.sh`;
   - ожидать `DataFlowOutOfMemory` и 18 результатов;
   - не делать вывод «пути нет» по оборванному прогону.

5. **Эмулятор + `.eml`** — 20–30 минут.
   - `./08_emulator.sh`;
   - письмо и сканер снимаются в `work/manual/dynamic/emulator/`;
   - `./08_emulator_down.sh` в конце.

6. **Frida** — 10–20 минут.
   - `./09_frida.sh` (server + trace --auto + modules);
   - трасса и карта модулей в `work/manual/dynamic/frida/`;
   - `openInputStream` и `camera360` должны быть в логах.

7. **Проверка** — 10 секунд.
   - `./10_check.sh`;
   - он увидит свежие `work/manual` и сверит их с ожидаемыми числами.

8. **Рисунки** — 20–30 минут.
   - `Инструкция_скриншоты.md` уже описывает 10 кадров;
   - `fig01.png` … `fig10.png` в `lab5/figures/`;
   - рисунки 1–4 — `sed` по коду mfva;
   - рисунок 5 — манифест + `grep '<permission'` (пустой вывод);
   - рисунки 6–8 — JADX GUI;
   - рисунок 9 — Python-сводка Trueseeing;
   - рисунок 10 — APKHunt + `grep -c`.

9. **Отчёт** — осторожно.
   - `report.md` — краткая версия, в нём 10 placeholder’ов;
   - `mbks_lab_5.docx` — полная версия, в ней 2 фото;
   - `build_report_docx.mjs` читает `report.md`, поэтому перед запуском реши, какую версию оставлять. Иначе потеряешь полный текст.

---

## 4. Грабли, которые лучше знать заранее

| Симптом | Причина | Что делать |
|---|---|---|
| `frida --version` = 16.7.19 | в PATH попал `venvs/analysis` | новый терминал, снова `source lab5/work/env.sh` |
| Frida сразу пишет `Thank you for using Frida` | закрылся stdin | `sleep 120 \| stdbuf -oL -eL frida ...` |
| `frida -f` не доходит до Java | особенность этой почты | только attach по PID |
| `frida-ps` не находит `ru.yandex.mail` | имя процесса `Yandex Mail` | искать по имени, PID — первый столбец |
| `camera360` нет в `modules.log` | сканер не был на переднем плане или не успел загрузиться | сначала `./08_emulator.sh scanner`, потом `./09_frida.sh modules`; в `all` сканер открывается через 10 с |
| `EmlActivity` падает на WebView | широкий хук `loadLibrary` или всех `Activity` | `09_frida.sh` использует `simple-trace.js`: только `EmlActivity`, сканер и `openInputStream` |
| `am start -n ...LoginActivity` → `does not exist` | это alias | цель — `StartWizardActivity`; для письма нужен `EmlActivity` |
| `00_all.sh` не запустил APKHunt и FlowDroid | они вынесены из быстрого маршрута | отдельно `./06_apkhunt.sh` и `./07_flowdroid.sh` |
| `05_scanners.sh` сделал только Trueseeing | без флагов это режим по умолчанию | `--apkhunt`, `--flowdroid` или `--all` |
| `08_emulator.sh` открыл окно и всё сделал сам | без аргументов это `demo` | для отдельных шагов: `up`, `install`, `eml`, `start`, `scanner` |
| `09_frida.sh` завершился по таймауту | трасса держится 30 с, карта модулей 10 с | это нормально, события уже в `trace.log` и `modules.log` |
| Trueseeing показывает 8068, 8072 или 8077 | общее число срабатываний плавает | групп всегда 37: Info 26, Medium 6, Low 5, High 0 |
| `10_check.sh` падает на `jq`/`xmllint`/`rg` | нет зависимости | поставить пакеты; проверка читает APK и `results/` |
| повторный запуск статических скриптов перезаписал `work/manual` | так и задумано, `--force` фактически всегда включён | `results/` не трогается; для чистого прогона удали только `work/manual` |
| OWApp-лог APKHunt обрывается на Realm Database | прогон прерван | считать его частичным; полный результат — `results/apkhunt/`, либо снова `./RunningScript.sh --apkhunt` |
| `10_check.sh` падает на проверке `APKHunt time` | в `work/manual/static/scanners` остался неполный `APKHunt_*.txt` | удалить неполный файл или дождаться `./06_apkhunt.sh`; проверка берёт самый свежий лог |
| APKHunt пишет exported 0 | ошибка сводки | смотреть `results/manifest.txt` и `grep -c` |
| `grep -c '<Result>'` даёт 1 | XML в одну строку | `grep -o` + `wc -l` или Python |
| FlowDroid ест 8 ГБ | так и было | не перезапускать без нужды, смотреть XML |
| `trueseeing version` → `requires a tty` | версия без терминала | на скан не влияет |
| `sources/yandex-mail` нет | дерево удалено специально | классы открывает `jadx-mail.sh`; манифест есть в `results/apkhunt/..._SAST` |
| `figures/` нет | скриншоты ещё не сняты | `mkdir -p lab5/figures` |

---

## 5. Сравнение с отчётами из `~/Documents/mbks/3`

Там лежит три вещи:

| Файл | Что это |
|---|---|
| `report3.docx` | ЛР3, Дударь Я.А., 2025: `mvfa` + Yandex Mail 8.81.2 |
| `lab3/lab3/отчет3.docx` | ЛР3, Орлова С.С., 2025: почти тот же текст, более полная/исправленная версия |
| `лаб3.docx` | ЛР3, Черкасова Д.В.: Goatlin + VK, **другой вариант**, к Yandex Mail не относится |

Два первых отчёта — по сути один и тот же вариант 11, что и текущая ЛР5. Поэтому сравнение осмысленное.

### 5.1. Что было в старых отчётах

- macOS, `brew install jadx`, `brew install android-platform-tools`.
- JADX GUI; в отчёте Орловой написано, что JADX не показал `AndroidManifest.xml`, поэтому использовали `apktool` и папку `mail_apk`.
- MobSF (скриншот), Trueseeing (скриншот), Frida, Python-скрипт для native-методов, скрипт для OSS в `.so`, `frida-trace -U -i "png_*"`.
- Сценарий: `am start -a android.intent.action.SEND -t "text/plain" -e android.intent.extra.TEXT "https://..." -n ru.yandex.mail/.ui.LoginActivity_common` — открывается экран создания письма со ссылкой.
- Таблицы Source/Sink — общие, по разрешениям и экспортированным компонентам.
- Вывод: «возможны XSS, RCE, SSRF, path traversal» и т.п.

### 5.2. Таблица сравнения

| Критерий | Старые ЛР3 (`mbks/3`) | Текущая ЛР5 |
|---|---|---|
| Приложения | `mvfa` + Yandex Mail 8.81.2 | те же |
| Платформа | macOS, brew, Android Studio AVD | Linux, Android SDK/AVD API 34, Frida-server |
| Декомпиляция | JADX GUI + apktool | JADX 1.5.6 + androguard 4.1.4 |
| Манифест | общий список «экспортированных», часть неверна | точные counts: 20/108, 12/32, 29/35, 3/20; `EmlActivity` с фильтрами |
| Сценарий | `SEND`/`VIEW` на `LoginActivity_common`, письмо со ссылкой | `ACTION_VIEW` на `EmlActivity` + специально созданный `.eml` с маркером |
| Доказательство сценария | скриншот compose-экрана | скриншот письма с `LAB5-EML-MARKER` + строка `openInputStream` в трассе |
| Frida | широкие хуки: все `FileInputStream`, OkHttp, `startActivity` | точечные хуки: `EmlActivity`, сканер, `openInputStream` |
| Native | Python-регекс по декомпилированным `.java` + `strings` по `.so`; `frida-trace png_*` | androguard: 339 определений; 4 библиотеки; OSS-версии; `libpng` = 0; реальная загрузка `camera360` |
| Data-flow | нет | FlowDroid: 18 результатов, 36 источников, OOM |
| Автоматика | MobSF + Trueseeing (скриншоты) | Trueseeing 8068/37 групп + APKHunt 22 мин + FlowDroid + androguard; те же этапы завёрнуты в `scripts/manual` |
| Доказательная база | скриншоты, без хеша и точных версий | SHA-256, versionCode, точные counts, артефакты в `results/` |
| Оценка рисков | XSS/RCE/SSRF как «возможные», без проверки | честно: `EmlActivity` читает и показывает, выполнения кода в этом классе нет |
| Слабые места | нет FlowDroid/APKHunt, нет внешнего `.eml`, часть компонентов указана неверно | FlowDroid оборван, JNI-вход не пойман, MobSF не запускался, SEBASTiAN без Docker, OWApp APKHunt не догнан, не все рисунки сняты |

### 5.3. Что в старых отчётах неточно

Это важно, чтобы не скопировать ошибки:

1. **`FirebaseMessagingService`** в старом отчёте попал в «экспортированные сервисы». В текущем манифесте у него `exported=false`. `DownloadService` и `TelemostActivity` в этой сборке вообще нет. Список старый/неточный.

2. **MobSF-выгрузка** `yamail_apk.json` содержит `exported_activities: 736` при 108 активностях. Это явно не число экспортированных; в отчёте эта цифра не использовалась, но показывает, почему нужен androguard.

3. **Сценарий `LoginActivity_common`** — это не `.eml`. Он отправляет внешний текст/ссылку в редактор письма. Это тоже валидный вектор, но он не доказывает `EmlActivity` и `openInputStream`. Старый отчёт смешивает «письмо со ссылкой» и «чужой `.eml`».

4. **XSS/RCE** в старом отчёте — гипотеза «если есть уязвимость в парсере». В текущем отчёте сказано точнее: `EmlActivity` только читает поток и кладёт текст в WebView; выполнения кода в этом классе нет.

5. **Frida-трасса старого отчёта** — это в основном загрузка картинки из письма и временные файлы, а не чтение внешнего `.eml`. Широкие хуки дают много шума и не изолируют источник.

6. **`frida-trace -i "png_*"`** в старом отчёте — проверка libpng, но в текущем анализе libpng в четырёх `.so` вообще нет (0 совпадений). Это не значит, что старый прогон «неправильный»: возможно, там был другой набор библиотек/другая сборка, но в текущей сборке проверять нечего.

7. **Trueseeing**: старый JSON даёт 38 групп (Info 27), текущий — 37 (Info 26). APK-хеш тот же, значит, разница в версии/конфигурации инструмента. Не надо делать вывод «приложение изменилось».

### 5.4. Что из старых отчётов можно взять

- Общую структуру: цель → ход работы → белый ящик → чёрный ящик → Frida → native → автоматика → вывод.
- Простое объяснение MASVS-категорий.
- Идею сценария с внешней ссылкой через `SEND` как **дополнительный** вектор (но не вместо `.eml`).
- Скриншоты MobSF/Trueseeing как пример того, как выглядят отчёты сканеров (не копируя цифры).
- Мысль, что `LoginActivity` — alias, а не настоящая активность.

### 5.5. Чем текущий отчёт сильнее

- Есть точный APK и хеш, а не «Yandex Mail 8.81.2».
- Есть проверяемая цепочка «внешний `.eml` → `EmlActivity` → `openInputStream` → WebView», подтверждённая скриншотом и трассой.
- Есть точные counts androguard, а не «примерно 20 компонентов».
- Есть 339 native-методов с определениями, а не просто список.
- Есть реальная загрузка `libcamera360-arcadia.so` в карте модулей.
- Есть FlowDroid, Trueseeing, APKHunt и разбор ошибки APKHunt.
- Есть честные ограничения: OOM, нет JNI-входа, MobSF не запускался, SEBASTiAN без Docker.

### 5.6. Где текущий отчёт ещё слаб

- FlowDroid оборван по памяти; 18 путей не включают письмо.
- 339 native-стоков не добавлялись в `SourcesAndSinks.txt`; достижимость native разбиралась вручную.
- Нет трассы входа в конкретную JNI-функцию; есть только факт загрузки библиотеки.
- OWApp `RunningScript.sh` выполнен частично: Trueseeing завершён, APKHunt прерван, SEBASTiAN и Docker не подтверждены. MobSF не запускался.
- Trueseeing даёт разное общее число срабатываний; в отчёте используется архивное `8068`, хотя свежие прогоны дают `8072` и `8077` при тех же 37 группах.
- Разбор Yandex Mail сделан по шагам задания, а не по всем номерам MSTG-тестов.
- В `report.md` 10 рисунков ещё не вставлены; в docx только 2 фото, `figures/` пуст.

---

## 6. Что делать сегодня

1. Прочитать `report.md` + `Журнал_действий.md` — 15 минут.
2. Прогнать `lab5/scripts/manual/10_check.sh` — 1 минута, убедиться, что 55 проверок на месте.
3. Если нужен свежий статический опыт — `cd lab5/scripts/manual && ./00_all.sh`, 2–3 минуты. Все выходы лягут в `work/manual/static/`.
4. Открыть JADX и самому найти `EmlActivity` и сканер — 20 минут. Это главное, что нужно уметь показывать.
5. Снять рисунки 6–8 в JADX и 1–5, 9–10 по `Инструкция_скриншоты.md`.
6. Если нужен полный динамический опыт — `./08_emulator.sh` и `./09_frida.sh`. Это 30–50 минут, но именно здесь появляется `openInputStream` и `camera360`.
7. Trueseeing можно перезапустить (1 минута). APKHunt — только если не жалко 22 минут. FlowDroid — только если есть свободные 8 ГБ и желание увидеть OOM своими глазами.
8. Перед пересборкой docx ещё раз прочитать предупреждение про `build_report_docx.mjs`: он читает короткий `report.md`.

---

## 7. Короткая шпаргалка «что показать»

### 7.1. Скриптами

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs

# Всё проверить, ничего не запуская
lab5/scripts/manual/10_check.sh

# Перегенерировать статику: androguard, манифест, smali, .so, Trueseeing
cd lab5/scripts/manual
./00_all.sh

# Динамика
./08_emulator.sh
./09_frida.sh
./10_check.sh
```

### 7.2. Архивные артефакты

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
source lab5/work/env.sh

# APK
sha256sum "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk"

# Манифест и native
sed -n '1,6p'   lab5/results/manifest.txt
sed -n '74,77p' lab5/results/manifest.txt
sed -n '1,4p'   lab5/results/natives.txt

# Трасса
grep -E 'EmlActivity|openInputStream|DocScanner|watched=' lab5/results/frida/trace.log
grep camera360 lab5/results/frida/modules-pid9066.log

# FlowDroid
grep -o 'TerminationState="[^"]*"' lab5/results/flowdroid/yandex-mail.xml
python3 - <<'PY'
import xml.etree.ElementTree as ET
r = ET.parse('lab5/results/flowdroid/yandex-mail.xml').getroot()
print('results', len(r.findall('.//Results/Result')))
print('sources', len(r.findall('.//Results/Result/Sources/Source')))
PY

# Trueseeing
python3 - <<'PY'
import json
from collections import Counter
d = json.load(open('lab5/results/trueseeing/yandex-mail.json'))
print(d['app']['package'], d['app']['version_name'], d['app']['issues'])
print(Counter(i['severity'] for i in d['issues']))
PY

# APKHunt
grep -n "Total exported\|Total time taken" \
  lab5/results/apkhunt/APKHunt_yandex-mail-8-81-2_2026-10-31_18-48-53.txt
grep -c 'android:exported="true"' \
  lab5/results/apkhunt/yandex-mail-8-81-2_SAST/resources/AndroidManifest.xml
```

---

## 8. Скрипты и артефакты: полный справочник

### 8.1. Верхнеуровневые скрипты `lab5/scripts/`

| Скрипт | Что делает | Куда пишет / как использовать |
|---|---|---|
| `audit_apk.py` | androguard: манифест, native-методы, API-hits, loadLibrary | каталог передаётся вторым аргументом; `01_androguard.sh` вызывает его сам |
| `jadx-mail.sh` | открывает APK в JADX GUI | ничего не пишет на диск; дерево не создаёт |
| `trace.js` | большой Frida-скрипт: `EmlActivity`, сканер, `openInputStream`, module observer, JNI-экспорты | для продвинутого разбора; с ним легче уронить процесс, чем с `simple-trace.js` |
| `run_trace.py` | Python-сессия Frida для `trace.js` | в итоговой трассе не использовался: в Frida 17 `session.create_script` не видит `Java`; оставлен как история |
| `emu-up.sh` | поднимает AVD `lab5_api34` с окном, ждёт загрузку | лог `/tmp/lab5/emulator.log` |
| `emu-status.sh` | печатает `adb devices` и `boot_completed` | только чтение; код 0, если эмулятор готов |
| `emu-down.sh` | останавливает AVD `lab5_api34` | чужой qemu без этого имени не трогает |
| `build_report_docx.mjs` | собирает docx из `report.md` | **осторожно**: читает короткий `report.md` и перезапишет полный `mbks_lab_5.docx` |

### 8.2. Stage-скрипты `lab5/scripts/manual/`

Все запускаются без аргументов, кроме флагов, указанных ниже. Сами подхватывают `lab5/work/env.sh`, поэтому `source` перед ними не обязателен. Пишут в `lab5/work/manual/`, `results/` не трогают.

| Скрипт | Что делает | Куда пишет | Время | Ожидание / флаги |
|---|---|---|---|---|
| `00_all.sh` | `01` + `02` + `03` + `04` + `05` + `10` | `work/manual/` | 2–3 мин | только статика; APKHunt/FlowDroid не запускает |
| `01_androguard.sh` | `audit_apk.py` через venv analysis | `work/manual/static/androguard/out`, `summary.txt`, `audit.log` | 1–2 мин | classes 59178, methods 260516, native 339, loadLibrary 8 |
| `02_manifest.sh` | apktool `--only-manifest` + xmllint | `work/manual/static/manifest` | 10–20 с | exported=true: activity 14, alias 7, service 5, receiver 14, provider 3; всего 43 |
| `03_smali.sh` | apktool `--no-res` + rg | `work/manual/static/smali` | 30–60 с | native 339, loadLibrary 8, openInputStream 40, WebView.loadUrl 36 |
| `04_native_so.sh` | unzip `.so` + file/readelf/nm/strings | `work/manual/static/native-so` | 5–10 с | 4 библиотеки x86_64, libpng 0 |
| `05_scanners.sh` | Trueseeing по умолчанию | `work/manual/static/scanners` | 1 мин / 22+ мин / 5–15 мин | 37 групп: Info 26, Medium 6, Low 5, High 0; `--apkhunt`, `--flowdroid`, `--all` |
| `06_apkhunt.sh` | обёртка `05 --apkhunt` | `work/manual/static/scanners` | 22+ мин | exported=0 — ошибка сводки; в SAST-манифесте 43 `exported=true` |
| `07_flowdroid.sh` | обёртка `05 --flowdroid` | `work/manual/static/scanners/flowdroid.xml` | 5–15 мин | 18 results, 36 sources, `DataFlowOutOfMemory` |
| `08_emulator.sh` | AVD + APK + `.eml` + скриншоты | `work/manual/dynamic/emulator` | 20–30 мин | `status/up/install/eml/start/scanner/demo/down`; без аргументов — `demo` с окном |
| `08_emulator_down.sh` | обёртка `08 down` | — | 5–20 с | останавливает AVD |
| `09_frida.sh` | frida-server + трасса + модули | `work/manual/dynamic/frida` | 10–20 мин | `status/server/ps/trace [--auto]/modules/all`; трасса 30 с, модули 10 с |
| `10_check.sh` | сверка артефактов и чисел | только вывод | 5–10 с | 55 PASS; код 1 при FAIL; читает `work/manual`, иначе `results/` |
| `lib.sh` | общая библиотека: пути, SHA, лог, xmllint, проверки | подключается через `source` | — | не запускается сама |
| `simple-trace.js` | узкая Frida-трасса: `EmlActivity`, сканер, `openInputStream` | через `09_frida.sh` | — | без module observer, меньше риска уронить почту |
| `README.md` | короткая инструкция по stage-скриптам | — | — | дублирует эту главу, но короче |

### 8.3. Куда что пишется

| Путь | Что внутри | Перезаписывается |
|---|---|---|
| `work/manual/static/androguard/` | `out/manifest.*`, `out/natives.*`, `native-sinks.txt`, `api-hits.*`, `summary.txt` | да, при повторном `01` |
| `work/manual/static/manifest/` | декодированный манифест, `counts.txt`, `exported.txt` | да, при повторном `02` |
| `work/manual/static/smali/` | smali-дерево, `native.txt`, `api-hits.txt`, `load-libraries.txt` | да, при повторном `03` |
| `work/manual/static/native-so/` | `.so`, `summary.txt`, `readelf-*`, `jni-*`, `nm-*`, `oss-*` | да, при повторном `04` |
| `work/manual/static/scanners/` | Trueseeing JSON/лог, APKHunt-логи, FlowDroid XML | да, при повторном `05`/`06`/`07` |
| `work/manual/dynamic/emulator/` | `lab5-external.eml`, `screen-eml.png`, `screen-scanner.png` | да, при повторном `08` |
| `work/manual/dynamic/frida/` | `trace.log`, `modules.log`, `modules.js` | да, при повторном `09` |
| `results/` | архивный эталон для отчёта | нет, stage-скрипты сюда не пишут |
| `results/owapp/` | OWApp-прогон | да, `RunningScript.sh` перезапишет |
| `owapp/apk/` | APK, jar, APKHunt txt/html, SAST | да, APKHunt; каталог в git не входит |
| `figures/` | `fig01.png` … `fig10.png` | вручную, пока пусто |

### 8.4. Правила запуска и зависимости

- Запускать можно из любого каталога: `lib.sh` сам делает `source lab5/work/env.sh`. Для ручных команд и JADX `source` всё ещё нужен.
- `results/` — только чтение для stage-скриптов. Всё новое идёт в `work/manual/`.
- `01`–`05` по умолчанию перезаписывают свой каталог в `work/manual` (в них `FORCE=1`); `--force` оставлен для совместимости и ничего не защищает. Если нужен чистый прогон, удаляй только `work/manual`.
- `00_all.sh` не запускает APKHunt и FlowDroid. Для них — `06_apkhunt.sh` и `07_flowdroid.sh`.
- `05_scanners.sh` без флагов — только Trueseeing. `--all` — Trueseeing + APKHunt + FlowDroid, это долго и тяжело.
- `08_emulator.sh` без аргументов — `demo` с окном. Для отдельных шагов используй `up`, `install`, `eml`, `start`, `scanner`, `down`. Запуска без окна нет.
- `09_frida.sh` запускай после `08_emulator.sh`: нужен живой эмулятор и процесс `Yandex Mail`. `all` сам открывает `.eml` и сканер по таймеру.
- `10_check.sh` требует `jq`, `xmllint`, `rg`, APK, `sources/mfva/README.md`, `report.md` и `mbks_lab_5.docx`. Если `work/manual` пуст, он переключается на `results/`; отсутствие `figures/` — только предупреждение.
- Если в `work/manual/static/scanners` остался неполный `APKHunt_*.txt`, `10_check.sh` возьмёт самый свежий и упадёт на проверке `22m`. Удали неполный лог или дождись полного `06_apkhunt.sh`.
- `10_check.sh` возвращает код 1, если есть `FAIL`. Для показа достаточно `All checks passed.`
- `build_report_docx.mjs` не запускай, пока не решил, какую версию отчёта оставлять.

### 8.5. OWApp

- `lab5/owapp/DownloadScript.sh` — делает жёсткую ссылку APK в `owapp/apk/yandex-mail-8-81-2.apk`, печатает SHA-256.
- `lab5/owapp/RunningScript.sh` — режимы `--check`, `--trueseeing`, `--apkhunt`, `--sebastian`, `--all` (по умолчанию).
- `--check` показывает APK, Trueseeing, APKHunt и состояние Docker, ничего не сканируя.
- `--trueseeing` и `--apkhunt` пишут в `results/owapp/`; APKHunt дополнительно оставляет txt/html/SAST рядом с APK в `owapp/apk/`.
- `--sebastian` требует Docker; скрипт пробует `sudo systemctl start docker` и `sudo docker`. Без Docker режим пропускается.
- MobSF в `RunningScript.sh` не запускается: в OWApp он ставится локально и работает через `MobsfReport.py`.

Фактический прогон 2026-11-17: Trueseeing завершён (8072, 49.09 с, 37 групп), APKHunt прерван, SEBASTiAN не подтверждён. Подробности — в разделе 2.10.

### 8.6. Текущее состояние на 2026-11-17

- `10_check.sh`: **55 PASS, 0 FAIL**; только предупреждения про `figures/` (0 из 10) и `build_report_docx.mjs`.
- Свежий статический прогон в `work/manual`: androguard, манифест, smali, `.so`, Trueseeing.
- Свежий динамический прогон: `work/manual/dynamic/emulator` и `work/manual/dynamic/frida`; PID 6091, `openInputStream` и `camera360` есть, модулей 330.
- Trueseeing: `results` — 8068/37, `work/manual` — 8077/37, `results/owapp` — 8072/37. Для отчёта — 8068/37.
- OWApp APKHunt: частичный лог в `results/owapp/`, полного `Total time taken` нет; архивный полный прогон — `results/apkhunt/`.
- Рисунки не сняты: `figures/` пуст, в docx только 2 фото.
- `report.md` — короткая версия; `mbks_lab_5.docx` — полная. Перед пересборкой docx остановись и прочитай предупреждение в разделе 1.2.

Подробности по stage-скриптам и их флагам — в `lab5/scripts/manual/README.md`.
