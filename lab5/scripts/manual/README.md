# Ручные этапы ЛР5

Простые скрипты для ручного анализа Yandex Mail. Каждый запускается без аргументов.
Это **не замена** `audit_apk.py`: скрипт остаётся автоматическим средством из задания, а эти этапы показывают, как получить и проверить те же данные стандартными CLI.

Все результаты пишутся в `lab5/work/manual/`, каталог `lab5/results/` не перезаписывается.

## Самое простое

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs/lab5/scripts/manual
./00_all.sh
```

`./00_all.sh` делает весь статический анализ и в конце запускает проверку.
Занимает около 1,5 минуты.

## По шагам

```sh
./01_androguard.sh      # audit_apk.py: manifest, native, API hits
./02_manifest.sh        # apktool + xmllint: exported-компоненты
./03_smali.sh           # apktool + rg: native, API, loadLibrary
./04_native_so.sh       # .so x86_64: readelf, strings, libpng
./05_scanners.sh        # Trueseeing, около 1 минуты
./10_check.sh           # сверка чисел с ожидаемыми
```

Долгие сканеры — отдельно:

```sh
./06_apkhunt.sh         # около 22 минут
./07_flowdroid.sh       # 8 ГБ памяти, может оборваться по OOM
```

OWApp — отдельно, своим штатным скриптом:

```sh
cd /home/drenk83/Projects/gitrepo/mbks_labs/lab5/owapp
./DownloadScript.sh
./RunningScript.sh
```

`RunningScript.sh` запускает Trueseeing и APKHunt, а SEBASTiAN — через Docker,
если Docker доступен. MobSF пропускается: в OWApp он ставится локально и
запускается через `MobsfReport.py`.

Динамика:

```sh
./08_emulator.sh        # эмулятор + APK + .eml + скриншоты
./09_frida.sh           # frida-server + трасса + карта модулей
./08_emulator_down.sh   # остановить эмулятор
```

`./08_emulator.sh` открывает окно эмулятора. `./09_frida.sh` запускай после `./08_emulator.sh`.
`./09_frida.sh` использует `simple-trace.js`: только `EmlActivity.onCreate`, `DocScannerCameraActivity.onCreate` и `openInputStream`. Большой `lab5/scripts/trace.js` остаётся отдельно для продвинутого разбора.

## Что получится

| Скрипт | Куда пишет | Ожидание |
|---|---|---|
| `./01_androguard.sh` | `work/manual/static/androguard` | native 339, classes 59178, methods 260516 |
| `./02_manifest.sh` | `work/manual/static/manifest` | 43 `exported=true`; activity 14, alias 7, service 5, receiver 14, provider 3 |
| `./03_smali.sh` | `work/manual/static/smali` | native 339, loadLibrary 8, openInputStream 40 |
| `./04_native_so.sh` | `work/manual/static/native-so` | 4 библиотеки x86_64, libpng 0 |
| `./05_scanners.sh` | `work/manual/static/scanners` | Trueseeing 37 групп |
| `./06_apkhunt.sh` | `work/manual/static/scanners` | 22m, exported=0 (ошибка сводки) |
| `./07_flowdroid.sh` | `work/manual/static/scanners` | 18 путей, `DataFlowOutOfMemory` |
| `./08_emulator.sh` | `work/manual/dynamic/emulator` | письмо с `LAB5-EML-MARKER`, сканер |
| `./09_frida.sh` | `work/manual/dynamic/frida` | `openInputStream`, `camera360` |
| `./10_check.sh` | только вывод | все проверки PASS |
| `owapp/RunningScript.sh` | `results/owapp` | Trueseeing, APKHunt, SEBASTiAN через Docker |

## Важные предупреждения

- `./06_apkhunt.sh` идёт 22+ минуты. `./07_flowdroid.sh` может съесть 8 ГБ и оборваться по памяти.
- `lab5/owapp/RunningScript.sh` для SEBASTiAN требует Docker. Если Docker не запущен, скрипт попробует `sudo systemctl start docker`; пароль sudo введёшь в терминале. MobSF в этом скрипте не запускается: в OWApp он ставится локально и работает через `MobsfReport.py`.
- APKHunt печатает `exported=0`, но в манифесте 43 вхождения `android:exported="true"`. Его сводке по exported не верить.
- `grep -c '<Result>'` на XML FlowDroid даст `1`: XML в одну строку. `./10_check.sh` считает через `xmllint`.
- `build_report_docx.mjs` читает короткий `report.md` и может перезаписать полный `mbks_lab_5.docx`. Не запускай его, пока не решил, какую версию оставлять.
- Если `frida --version` показывает 16.7.19, в `PATH` попал `venvs/analysis`; открой новый терминал и снова `source lab5/work/env.sh`.
- `./09_frida.sh` держит трассу 30 секунд и карту модулей 10 секунд, затем останавливает Frida по таймауту. Это нормально: события уже в `trace.log` и `modules.log`.
- Повторный запуск статических скриптов сам перезаписывает свой каталог в `work/manual`; `results/` не трогается.

## Ручной эквивалент без Python

```sh
apktool d -f -s --only-manifest -o work/manual/static/manifest/apktool "APK"
xmllint --xpath 'count(//*[local-name()="activity"][@*[local-name()="exported"]="true"])' \
  work/manual/static/manifest/apktool/AndroidManifest.xml

apktool d -f --no-res -o work/manual/static/smali/apktool "APK"
rg --glob '*.smali' '^\s*\.method .*\bnative\b' work/manual/static/smali/apktool | wc -l
rg --glob '*.smali' 'invoke.*System;->loadLibrary' work/manual/static/smali/apktool | wc -l
```
