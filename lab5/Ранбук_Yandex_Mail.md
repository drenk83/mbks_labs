# Ранбук: анализ Yandex Mail в ЛР5

Вариант 11. Чёрный ящик — Yandex Mail 8.81.2, пакет `ru.yandex.mail`.
Белый ящик — `mfva`, пакет `com.appknox.mfva`.

Файл описывает, как выполнялся анализ Yandex Mail, что и в каком порядке запускать руками, какие цифры должны получиться и чем текущая работа отличается от отчётов из `~/Documents/mbks/3`.

---

## 1. Что это за лабораторная

ЛР5, вариант 11, два приложения:

| Роль | Приложение | Пакет | Что делали |
|---|---|---|---|
| Белый ящик | `mfva` (в задании опечатка `mvfa`) | `com.appknox.mfva` | читали исходники, разбирали по 8 категориям MASVS |
| Чёрный ящик | Yandex Mail 8.81.2 | `ru.yandex.mail` | APK → JADX → манифест → эмулятор → Frida → статические анализаторы |

Задание требует: MASVS/MSTG, декомпиляцию, разбор манифеста, поиск Source/Sink, запуск в эмуляторе, трассу Frida, перечень native-методов, OSS-компоненты в `.so`, FlowDroid, OWApp, отчёт.

Где что лежит:

- `lab5/report.md` — короткая рабочая версия отчёта, 10 мест под рисунки.
- `lab5/mbks_lab_5.docx` — полный отчёт (около 35 тыс. символов, 2 скриншота телефона).
- `lab5/Журнал_действий.md` — что и как запускали, с командами и цифрами.
- `lab5/Лаб5_самоучитель_и_защита.md` и `guide.html` — разжёванный разбор для защиты.
- `lab5/scripts/` — `audit_apk.py`, `trace.js`, `jadx-mail.sh`, скрипты эмулятора.
- `lab5/results/` — готовые артефакты: манифест, native-методы, трасса, XML FlowDroid, JSON Trueseeing, лог APKHunt.
- `lab5/work/` — APK, JADX, Frida-server, AVD, venv’ы. В git не входит.

Важно: **полный отчёт в docx, а `report.md` — краткая версия**. Сборщик `build_report_docx.mjs` читает именно `report.md`. Если сейчас запустить его, он перезапишет полный docx короткой версией. Это надо учитывать перед пересборкой.

---

## 2. Как анализировали Yandex Mail — по шагам

### 2.1. Подготовка

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

Скрипт `lab5/scripts/audit_apk.py` читает APK и пишет:

- `manifest.txt` / `manifest.json`;
- `natives.txt` / `natives.json` — все native-методы;
- `native-sinks.txt` — те же методы в формате стока FlowDroid;
- `load-libraries.json` — места загрузки библиотек;
- `api-hits.txt` / `api-hits.json` — счётчики опасных вызовов.

Запуск (лучше в `/tmp`, чтобы не перезаписать `results/`):

```sh
lab5/work/venvs/analysis/bin/python lab5/scripts/audit_apk.py \
  "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk" \
  /tmp/lab5-audit-out
```

Ключевые цифры:

- классов 59 178;
- методов 260 516;
- native-методов 339;
- активности: 108 всего, 20 с входом снаружи;
- сервисы: 32 / 12;
- приёмники: 35 / 29;
- провайдеры: 20, экспортированы 3.

Именно эти цифры надо называть, а не «ноль экспортированных» из APKHunt.

### 2.4. Нативные библиотеки и OSS

В APK четыре библиотеки x86_64:

```text
libcamera360-arcadia.so          OpenCV, сканер документов
libjingle_peerconnection_so.so   WebRTC, BoringSSL, libyuv, libvpx, Opus
libYandexSpeechKitJni.4.15.7.so  SpeechKit 4.15.7
libeye.so                        EyeNative, камера эффектов
```

Проверка:

```sh
mkdir -p /tmp/lab5-native
unzip -o -j "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk" \
  'lib/x86_64/*.so' -d /tmp/lab5-native

file /tmp/lab5-native/*.so
grep -a -E -c 'libpng|png_read|png_create' /tmp/lab5-native/*.so
```

Ожидание: четыре ELF x86-64, у `libpng` — нули. Готовая сводка: `lab5/results/oss-summary.txt`.

### 2.5. Эмулятор и сценарий с `.eml`

Эмулятор: AVD `lab5_api34`, API 34, google_apis, x86_64.

```sh
lab5/scripts/emu-status.sh
lab5/scripts/emu-up.sh --window
adb devices
```

Установка APK:

```sh
adb install -r "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk"
adb shell monkey -p ru.yandex.mail -c android.intent.category.LAUNCHER 1
```

Дальше — «чужое письмо». Создаём минимальный `.eml` с маркером:

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
```

Кладём в приватный каталог почты (нужен root adb):

```sh
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

Запуск просмотра:

```sh
adb shell am start -a android.intent.action.VIEW \
  -d file:///data/data/ru.yandex.mail/files/lab5-external.eml \
  -t message/rfc822 \
  -n ru.yandex.mail/com.yandex.mail.eml.EmlActivity
```

Скриншот:

```sh
adb exec-out screencap -p > /tmp/lab5-eml.png
```

На экране должна быть тема `lab5 external eml` и маркер `LAB5-EML-MARKER`.

Сканер:

```sh
adb shell am start -n ru.yandex.mail/com.yandex.mail360.camera.doc.scanner.DocScannerCameraActivity
adb exec-out screencap -p > /tmp/lab5-scanner.png
```

Сканер не exported, поэтому из чужого приложения он не запустится. Запуск с root adb — это не атака, а способ показать загрузку библиотеки.

Остановка:

```sh
lab5/scripts/emu-down.sh
```

### 2.6. Frida: трасса чтения `.eml`

Сервер Frida:

```sh
adb push lab5/work/tools/frida/frida-server-17.4.0-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell '/data/local/tmp/frida-server >/data/local/tmp/frida.log 2>&1 &'
```

Процесс почты:

```sh
frida-ps -Uai | grep -i mail
```

В списке имя процесса — `Yandex Mail`, не `ru.yandex.mail`. Берём PID.

Сессия (важно: `sleep` держит stdin, иначе Frida сразу выходит):

```sh
PID=$(frida-ps -Uai | awk '/Yandex Mail/ {print $1; exit}')
sleep 120 | stdbuf -oL -eL frida -U -p "$PID" -l lab5/scripts/trace.js | tee /tmp/lab5-trace.log
```

Пока сессия жива, во втором терминале запускаем `am start` из раздела 2.5. В трассе должны появиться:

```text
activity.onCreate class=com.yandex.mail.eml.EmlActivity
  intent action=android.intent.action.VIEW type=message/rfc822
  data=file:///data/data/ru.yandex.mail/files/lab5-external.eml
openInputStream uri=file:///data/data/ru.yandex.mail/files/lab5-external.eml
activity.onCreate class=...DocScannerCameraActivity
  bundleNull=true
```

Второй attach — карта модулей:

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

Ожидание:

```text
libcamera360-arcadia.so | /data/app/.../base.apk!/lib/x86_64/libcamera360-arcadia.so
total 330
```

Готовые логи: `results/frida/trace.log` и `results/frida/modules-pid9066.log`.

### 2.7. FlowDroid

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

```sh
lab5/work/venvs/analysis/bin/trueseeing \
  -eqc 'as;gj! /tmp/lab5-trueseeing.json' \
  "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk"
```

Ожидание: `done, found 8068 issues (66.37 sec.)`. В JSON 37 групп:

- Info 26;
- Medium 6;
- Low 5;
- High нет.

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

- `lab5/owapp/DownloadScript.sh` — делает жёсткую ссылку APK, код 0.
- `lab5/owapp/RunningScript.sh` — не запускали: он снова вызывает Trueseeing/APKHunt и упирается в Docker.
- MobSF и SEBASTiAN не запускались: нужны Docker и sudo.

---

## 3. Ручной runbook: два маршрута

### Маршрут A. Быстрый, 15–20 минут, без эмулятора

Показывает, что работа сделана, и не требует тяжёлых прогонов.

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs
source lab5/work/env.sh

sha256sum "lab5/work/apk/Yandex Mail_8.81.2_APKPure.apk"

sed -n '1,6p'   lab5/results/manifest.txt
sed -n '74,77p' lab5/results/manifest.txt
sed -n '1,4p'   lab5/results/natives.txt
sed -n '1,12p'  lab5/results/api-hits.txt

grep -E 'EmlActivity|openInputStream|DocScanner|watched=' \
  lab5/results/frida/trace.log
grep camera360 lab5/results/frida/modules-pid9066.log

grep -o 'TerminationState="[^"]*"' \
  lab5/results/flowdroid/yandex-mail.xml
python3 - <<'PY'
import xml.etree.ElementTree as ET
r = ET.parse('lab5/results/flowdroid/yandex-mail.xml').getroot()
print(len(r.findall('.//Results/Result')), 'results')
print(len(r.findall('.//Results/Result/Sources/Source')), 'sources')
PY

python3 - <<'PY'
import json
from collections import Counter
d = json.load(open('lab5/results/trueseeing/yandex-mail.json'))
print(d['app']['package'], d['app']['version_name'], d['app']['issues'])
print(Counter(i['severity'] for i in d['issues']))
PY

grep -n "Total exported\|Total time taken" \
  lab5/results/apkhunt/APKHunt_yandex-mail-8-81-2_2026-10-31_18-48-53.txt
grep -c 'android:exported="true"' \
  lab5/results/apkhunt/yandex-mail-8-81-2_SAST/resources/AndroidManifest.xml
```

Плюс открыть глазами:

- `lab5/results/frida/screen-eml.png` — письмо с маркером;
- `lab5/results/frida/screen-scanner.png` — сканер.

Этого достаточно, чтобы «показать» работу. Но не достаточно, чтобы почувствовать, как её делали.

### Маршрут B. Полный, 2–4 часа

Порядок такой:

1. **JADX** — 15–20 минут.
   - `lab5/scripts/jadx-mail.sh`;
   - манифест: `EmlActivity`, `exported`, фильтры;
   - `EmlActivity`: `getData`, `openInputStream`, WebView;
   - `DocScannerCameraActivity`: `loadLibrary("camera360-arcadia")`.

2. **androguard** — 5–10 минут.
   - запуск в `/tmp/lab5-audit-out`;
   - сверить 339 native, 20/108 активностей.

3. **Нативные библиотеки** — 5 минут.
   - `unzip` в `/tmp/lab5-native`;
   - `file`, `strings`, `libpng` — 0.

4. **Эмулятор + `.eml` + Frida** — 40–60 минут.
   - `emu-up.sh --window`;
   - установка APK;
   - `.eml` в `/data/data/ru.yandex.mail/files/`;
   - `am start` → скриншот;
   - `trace.js` → `openInputStream`;
   - второй attach → `camera360`;
   - сканер → скриншот;
   - `emu-down.sh`.

5. **Trueseeing** — 1–2 минуты.
   - 8068 срабатываний, 37 групп.

6. **APKHunt** — 22–25 минут, опционально.
   - жёсткая ссылка, `-l`;
   - читать сводку, но не верить `exported=0`;
   - проверить 43 вхождения `android:exported="true"`.

7. **FlowDroid** — 5–15 минут, 8 ГБ, опционально.
   - лучше писать в `/tmp/lab5-flowdroid.xml`;
   - ожидать `DataFlowOutOfMemory` и 18 результатов;
   - не делать вывод «пути нет» по оборванному прогону.

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
| `EmlActivity` падает на WebView | включён широкий хук `loadLibrary` / всех `Activity` | использовать итоговый `trace.js`, там только `EmlActivity`, сканер и `openInputStream` |
| `am start -n ...LoginActivity` → `does not exist` | это alias | цель — `StartWizardActivity`; для письма нужен `EmlActivity` |
| APKHunt пишет exported 0 | ошибка сводки | смотреть `results/manifest.txt` и `grep -c` |
| `grep -c '<Result>'` даёт 1 | XML в одну строку | `grep -o` + `wc -l` или Python |
| FlowDroid ест 8 ГБ | так и было | не перезапускать без нужды, смотреть XML |
| `trueseeing version` → `requires a tty` | версия без терминала | на скан не влияет |
| `sources/yandex-mail` нет | дерево не в git | JADX разберёт APK заново; манифест есть в `results/apkhunt/..._SAST` |
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
| Автоматика | MobSF + Trueseeing (скриншоты) | Trueseeing 8068/37 групп + APKHunt 22 мин + FlowDroid + androguard |
| Доказательная база | скриншоты, без хеша и точных версий | SHA-256, versionCode, точные counts, артефакты в `results/` |
| Оценка рисков | XSS/RCE/SSRF как «возможные», без проверки | честно: `EmlActivity` читает и показывает, выполнения кода в этом классе нет |
| Слабые места | нет FlowDroid/APKHunt, нет внешнего `.eml`, часть компонентов указана неверно | FlowDroid оборван, JNI-вход не пойман, MobSF/SEBASTiAN не запускались, не все рисунки сняты |

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
- Есть честные ограничения: OOM, нет JNI-входа, MobSF/SEBASTiAN без Docker.

### 5.6. Где текущий отчёт ещё слаб

- FlowDroid оборван по памяти; 18 путей не включают письмо.
- 339 native-стоков не добавлялись в `SourcesAndSinks.txt`; достижимость native разбиралась вручную.
- Нет трассы входа в конкретную JNI-функцию; есть только факт загрузки библиотеки.
- MobSF и SEBASTiAN не запускались; OWApp `RunningScript.sh` не запускался.
- Разбор Yandex Mail сделан по шагам задания, а не по всем номерам MSTG-тестов.
- В `report.md` 10 рисунков ещё не вставлены; в docx только 2 фото.

---

## 6. Что делать сегодня

1. Прочитать `report.md` + `Журнал_действий.md` — 15 минут.
2. Прогнать **маршрут A** — 15 минут, убедиться, что все цифры на месте.
3. Открыть JADX и самому найти `EmlActivity` и сканер — 20 минут. Это главное, что нужно уметь показывать.
4. Снять рисунки 6–8 в JADX и 1–5, 9–10 по `Инструкция_скриншоты.md`.
5. Если нужен полный динамический опыт — поднять эмулятор, повторить `.eml` + Frida. Это 40–60 минут, но именно здесь появляется `openInputStream`.
6. Trueseeing можно перезапустить (1 минута). APKHunt — только если не жалко 22 минут. FlowDroid — только если есть свободные 8 ГБ и желание увидеть OOM своими глазами.

---

## 7. Короткая шпаргалка «что показать»

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

## 8. Готовые скрипты

Ручные этапы вынесены в `lab5/scripts/manual/`:

```text
lab5/scripts/manual/
  00_all.sh
  01_androguard.sh
  02_manifest.sh
  03_smali.sh
  04_native_so.sh
  05_scanners.sh
  06_apkhunt.sh
  07_flowdroid.sh
  08_emulator.sh
  08_emulator_down.sh
  09_frida.sh
  10_check.sh
  lib.sh
  simple-trace.js
  README.md
```

Самый простой запуск:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs/lab5/scripts/manual
./00_all.sh
```

Или по шагам:

```sh
./01_androguard.sh
./02_manifest.sh
./03_smali.sh
./04_native_so.sh
./05_scanners.sh
./10_check.sh

# OWApp
cd /home/drenk83/Projects/gitrepo/mbks_labs/lab5/owapp
./DownloadScript.sh
./RunningScript.sh
```

Подробности и ожидаемые числа — в `lab5/scripts/manual/README.md`.
