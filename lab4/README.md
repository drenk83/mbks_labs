# Лабораторная работа № 4 — SAST, вариант 4

**Тема:** использование средств статического анализа кода для оценки безопасности приложений.

| Параметр | Значение |
|---|---|
| Вариант | 4 — C/C++, третье средство **joern** |
| Исследуемое ПО | **libsndfile 1.0.30** |
| Уязвимость | **CVE-2021-3246** (CWE-787, CVSS 8.8) |
| Исправление | libsndfile 1.1.0, коммит `deb669ee` |
| Студент | Чупров Е. А., гр. 5131001/30501 |
| Преподаватель | ассистент Жуковский Е. В. |
| Отчёт | [`report.md`](report.md) — Markdown для переноса в Google Docs |

## Кратко о результате

- Уязвимость воспроизведена на WAV-файле 2660 байт: ASan-сборка libsndfile 1.0.30 падает в `msadpcm_decode_block` (`src/ms_adpcm.c:279`) с `heap-buffer-overflow`.
- На libsndfile 1.1.0 тот же файл отклоняется сообщением `samplesperblock (10) should be >= 1582`.
- Написаны три правила, которые срабатывают на 1.0.30 и молчат на 1.1.0:
  - CodeQL: `cpp/lab4-msadpcm-block-size`;
  - semgrep: `lab4-msadpcm-block-size`;
  - joern: `rules/joern/msadpcm-block-size.sc`, запуск через `joern --script`.
- CodeQL: 5 штатных CWE-запросов дали 301 срабатывание (290 — CWE-190, 8 — CWE-129, 2 — CWE-457, 1 — CWE-468, 0 — CWE-120), своё правило — 1/0.
- semgrep: `p/c` — 0 находок (2 правила), `p/default` — 0 (336 правил), `p/security-audit` — 7 находок; своё правило — 1/0.
- joern 4.0.669: `joern-scan --language c` — 368 срабатываний (293 из них — эвристика Copy loop); своё правило — 1/0, место `ms_adpcm.c:131`. Штатный набор CVE-2021-3246 не находит.

## Состав каталога

```text
lab4/
├── report.md                  отчёт
├── README.md                  этот файл
├── scripts/
│   ├── 01-fetch.sh            клонирование v1.0.30 и 1.1.0
│   ├── 02-build.sh            обычная и ASan-сборка
│   ├── 03-poc.sh              генерация PoC и прогон
│   ├── 04-codeql.sh           база, пять CWE, своё правило
│   ├── 05-semgrep.sh          штатные наборы и своё правило
│   ├── 06-joern.sh            joern-scan и своё правило
│   ├── 07-screenshots.sh      сводки и PNG для отчёта
│   ├── run-all.sh             всё подряд
│   ├── codeql-build.sh        обёртка сборки для CodeQL
│   ├── make-shot.sh           рендер текста в PNG
│   └── summarize.py           сводки по результатам
├── rules/
│   ├── codeql/
│   │   ├── msadpcm-block-size.ql
│   │   └── qlpack.yml
│   ├── semgrep/
│   │   └── msadpcm-block-size.yaml
│   └── joern/
│       └── msadpcm-block-size.sc
├── poc/
│   ├── gen_msadpcm_poc.py
│   └── msadpcm_poc.wav        генерируется скриптом
├── results/                   SARIF, txt/json, сводки
├── screenshots/               PNG с выводом команд
└── work/                      исходники, сборки, базы, venv, JDK, joern (в git не входит)
```

Исходники libsndfile в git **не коммитятся**: они скачиваются скриптом `01-fetch.sh` в `work/`, который закрыт `.gitignore`. Туда же ставятся JDK и joern.

## Окружение

Работа выполнена нативно на Omarchy/Arch Linux, без WSL и Docker.

| Инструмент | Версия |
|---|---|
| clang | 23.1.3 (сборка libsndfile, `config.log`) |
| CodeQL | 2.27.3 (bundle с пакетом `codeql/cpp-queries`) |
| semgrep | 1.182.1 (venv на Python 3.13) |
| joern | 4.0.669 |
| JDK | Temurin 21.0.13+9 (нужен joern) |
| libsndfile | 1.0.30 (уязвимая), 1.1.0 (исправленная) |

Инструменты поставлены в пользовательский каталог `work/`, поэтому `sudo` не требуется:

```sh
# CodeQL: bundle распаковывается в work/tools/codeql
# semgrep: uv venv + uv pip install
uv venv --python 3.13 work/venvs/semgrep
uv pip install --python work/venvs/semgrep/bin/python semgrep==1.182.1

# JDK и joern лежат в work/tools/jdk-21 и work/tools/joern/joern-cli.
# Перед joern:
export JAVA_HOME="$PWD/work/tools/jdk-21"
export PATH="$JAVA_HOME/bin:$PATH"
```

Для сборки libsndfile нужны `autoconf`, `automake`, `libtool`, `pkg-config`, `clang`; они уже есть в системе. База запросов joern для версии 4.0.669 ставится командой `joern-scan --updatedb --dbversion 4.0.669` (58 запросов). Флаг `joern --version` версию не печатает: он открывает REPL.

## Воспроизведение

Полный прогон:

```sh
./scripts/run-all.sh
```

Или по шагам:

```sh
./scripts/01-fetch.sh
./scripts/02-build.sh
./scripts/03-poc.sh
./scripts/04-codeql.sh
./scripts/05-semgrep.sh
./scripts/06-joern.sh
./scripts/07-screenshots.sh
```

Замечания:

- `04-codeql.sh` при первом запуске скачивает bundle CodeQL (~560 МБ) в `work/tools/`.
- `05-semgrep.sh` обращается к реестру semgrep.dev; нужен интернет.
- `06-joern.sh` требует уже установленные JDK и joern в `work/tools/`. Штатный прогон по `src/` занимает около половины минуты и пишет `results/joern-builtin-1.0.30.txt`, `results/joern-custom-1.0.30.txt` и `results/joern-custom-1.1.0.txt`. Каталог `workspace` joern создаёт внутри `work/joern-runs/`.
- Скрипты используют `work/` и `results/`; пути абсолютные, запускать можно из любого каталога.

## Проверка PoC вручную

```sh
python3 poc/gen_msadpcm_poc.py
ASAN_OPTIONS=detect_leaks=0 \
  work/build/asan-1.0.30/programs/sndfile-info poc/msadpcm_poc.wav
# ожидается AddressSanitizer: heap-buffer-overflow в ms_adpcm.c:279

ASAN_OPTIONS=detect_leaks=0 \
  work/build/asan-1.1.0/programs/sndfile-info poc/msadpcm_poc.wav
# ожидается "*** Error samplesperblock (10) should be >= 1582."
```

## Правила

Все три правила нацелены на старую проверку в `wavlike_msadpcm_init`:

```c
if (blockalign < 7 * psf->sf.channels)
```

В 1.1.0 она заменена на проверки `samplesperblock` и `2 * blockalign`, поэтому правила на исправленной версии молчат.

- CodeQL: запрос ограничен функцией `wavlike_msadpcm_init`, ищет `if` с `blockalign` слева от `<`.
- semgrep: `pattern-inside` функции + шаблон условия.
- joern: обход CPG, оператор `if` в той же функции; первый ребёнок AST условия — `blockalign`, второй начинается с `7 *`.

## Отчёт

`report.md` написан в расчёте на перенос в Google Docs:

- заголовки Markdown станут заголовками документа;
- таблицы и блоки кода переносятся как есть;
- изображения лежат отдельно в `screenshots/`; при переносе их нужно вставить вручную (Markdown-ссылки на локальные файлы Google Docs не подтягивает).

Скриншоты в `screenshots/` — это отрендеренный вывод реальных команд (ImageMagick, моноширинный шрифт), а не постановочные картинки. При желании их можно заменить на снимки терминала.

## Ограничения и честные оговорки

- Штатный C-набор semgrep (`p/c`) содержит всего два правила и на libsndfile не дал находок; для содержательного анализа использован `p/security-audit`.
- Штатный запрос CodeQL CWE-190 дал 290 срабатываний с низкой точностью; большинство — битовые операции, требующие ручной триаги.
- Штатный запрос CWE-120 не увидел CVE-2021-3246: уязвимость является ошибкой согласования размеров, а не неограниченным копированием.
- Штатный `joern-scan` тоже не видит CVE-2021-3246. Из 368 срабатываний 293 — запрос Copy loop: он помечает цикл, который пишет в массив и увеличивает индекс, без проверки границы. Срабатывание форматной строки в `psf_hexdump` ложное: формат константный, но записан тернарным оператором.
- Часть срабатываний `use-after-free` в semgrep — ложные; это разобрано в отчёте.
