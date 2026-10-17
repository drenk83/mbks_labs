/* ============================================================================
 *  Вариант 3: список слушающих TCP-портов в файл - на языке C.
 *
 *  Приёмы базонезависимого кода (position independent code):
 *    * нет глобальных и статических данных - всё на стеке;
 *    * нет строковых литералов - строки собираются из иммедиатов в коде;
 *    * нет обращений к таблице импорта: адреса функций ищутся во время
 *      выполнения (PEB -> ядро -> таблица экспорта);
 *    * вызовы только через указатели (косвенно), поэтому нет абсолютных
 *      адресов в машинном коде;
 *    * нет CRT: компилируется без стандартной библиотеки и без /GS.
 *
 *  Сборка (только объектный файл, без линковки):
 *      cl /c /O2 /GS- /Gs- /Fa /Fosc.obj sc.c
 * ========================================================================== */

#pragma code_seg(".text$z")   /* вспомогательные функции - в конец */

typedef unsigned long  u32;
typedef unsigned short u16;
typedef unsigned char  u8;
typedef void*          HANDLE;
typedef int            BOOL;

typedef HANDLE (__stdcall *FN_CREATEFILE)(const char*, u32, u32, void*, u32, u32, HANDLE);
typedef BOOL   (__stdcall *FN_WRITEFILE)(HANDLE, const void*, u32, u32*, void*);
typedef u32    (__stdcall *FN_GETTCPTABLE)(void*, u32*, BOOL);
typedef void   (__stdcall *FN_EXITPROCESS)(u32);

#define INVALID_HANDLE_VALUE ((HANDLE)(long)-1)

/* -------------------------------------------------------------------------
 * Хеш имени функции: h = h*33 + байт (тот же, что в ассемблерном варианте)
 * ---------------------------------------------------------------------- */
static u32 hash_name(const char *s)
{
    u32 h = 0;                       /* FNV-1a с базисом 0 */
    while (*s) {
        h ^= (u32)(u8)(*s++);
        h *= 0x01000193u;
    }
    return h;
}

/* -------------------------------------------------------------------------
 * Поиск адреса функции в таблице экспорта модуля по хешу имени.
 *   e_lfanew = [base+0x3C];  export = base + [base+e_lfanew+0x78]
 *   NumberOfNames   +0x18;  AddressOfFunctions   +0x1C
 *   AddressOfNames  +0x20;  AddressOfNameOrdinals+0x24
 * ---------------------------------------------------------------------- */
static void *find_export(void *base, u32 want)
{
    u8  *b   = (u8*)base;
    u8  *pe  = b + *(u32*)(b + 0x3C);       /* PE-заголовок */
    u8  *exp = b + *(u32*)(pe + 0x78);      /* IMAGE_EXPORT_DIRECTORY */
    u32  n   = *(u32*)(exp + 0x18);         /* NumberOfNames */
    u32 *aof = (u32*)(b + *(u32*)(exp + 0x1C));   /* AddressOfFunctions */
    u32 *aon = (u32*)(b + *(u32*)(exp + 0x20));   /* AddressOfNames */
    u16 *aoo = (u16*)(b + *(u32*)(exp + 0x24));   /* AddressOfNameOrdinals */
    u32  i;

    for (i = 0; i < n; i++) {
        const char *nm = (const char*)(b + aon[i]);
        if (hash_name(nm) == want)
            return (void*)(b + aof[aoo[i]]);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * База kernel32.dll через PEB.
 * ---------------------------------------------------------------------- */
static void *kernel32_base(void)
{
    void *p;
    __asm {
        mov  eax, fs:[30h]        /* TEB -> PEB */
        mov  eax, [eax + 0Ch]     /* PEB_LDR_DATA */
        mov  eax, [eax + 0Ch]     /* InLoadOrderModuleList.Flink */
        mov  eax, [eax]           /* ntdll */
        mov  eax, [eax]           /* kernelbase */
        mov  eax, [eax]           /* kernel32 */
        mov  eax, [eax + 18h]     /* DllBase */
        mov  p, eax
    }
    return p;
}

/* -------------------------------------------------------------------------
 * Сборка строки из иммедиатов: каждый байт хранится со сдвигом +0x41,
 * поэтому в машинном коде нет нулевых байтов.
 * ---------------------------------------------------------------------- */
static void mkstr(char *dst, u32 w, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        dst[i] = (char)(u8)((w >> (8 * i)) - 0x41);
    }
}

/* -------------------------------------------------------------------------
 * Число -> десятичная строка.
 * ---------------------------------------------------------------------- */
static char *utoa(char *p, u32 v)
{
    char tmp[12];
    int  n = 0;
    do {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    } while (v);
    while (n)
        *p++ = tmp[--n];
    return p;
}

/* -------------------------------------------------------------------------
 * Полезная нагрузка. Вызывается как шеллкод: никаких параметров,
 * всё нужное находит сама.
 * ---------------------------------------------------------------------- */
#pragma code_seg(".text$a")   /* сам шеллкод - первым в .text */
__declspec(noreturn) void shellcode(void)
{
    void *k32;
    FN_CREATEFILE   CreateFileA;
    FN_WRITEFILE    WriteFile;
    FN_GETTCPTABLE  GetTcpTable;
    FN_EXITPROCESS  ExitProcess;
    void *iphlp;

    char  fname[16];
    char  dllname[16];
    char  out[256];
    char *o;
    u32   size;
    u32   rc;
    u32   n;
    u32   i;
    u8   *row;

    /* имена функций для поиска по хешу (значения посчитаны заранее) */
    k32 = kernel32_base();

    CreateFileA  = (FN_CREATEFILE)  find_export(k32, 0x5E7B0B49u); /* CreateFileA */
    WriteFile    = (FN_WRITEFILE)   find_export(k32, 0xE7E405A1u); /* WriteFile   */
    ExitProcess  = (FN_EXITPROCESS) find_export(k32, 0xFCA4F4CDu); /* ExitProcess */

    /* iphlpapi и GetTcpTable: берём через LoadLibraryA/GetProcAddress */
    {
        typedef void* (__stdcall *FN_LL)(const char*);
        typedef void* (__stdcall *FN_GPA)(void*, const char*);
        FN_LL  LoadLibraryA  = (FN_LL)  find_export(k32, 0x69D7B492u);
        FN_GPA GetProcAddress= (FN_GPA) find_export(k32, 0x075CF7ACu);

        /* "iphlpapi.dll" */
        mkstr(dllname, 0xADA9B1AAu, 4);      /* "iphlpapi.dll" */
        mkstr(dllname + 4, 0xAAB1A2B1u, 4);
        mkstr(dllname + 8, 0xADADA56Fu, 4);
        dllname[12] = 0;
        iphlp = LoadLibraryA(dllname);

        /* "GetTcpTable" собираем так же, без строкового литерала */
        mkstr(fname, 0x95B5A688u, 4);
        mkstr(fname + 4, 0xA295B1A4u, 4);
        mkstr(fname + 8, 0x41A6ADA3u, 4);
        GetTcpTable = (FN_GETTCPTABLE) GetProcAddress(iphlp, fname);
    }

    /* размер таблицы */
    size = 0;
    GetTcpTable(0, &size, 0);

    /* таблица на стеке: 20 байт на строку */
    {
        u8 table[1024];
        GetTcpTable(table, &size, 1);

        n = *(u32*)table;
        row = table + 4;
        o = out;

        for (i = 0; i < n; i++, row += 20) {
            if (*(u32*)row != 2) continue;         /* LISTEN */
            {
                u16 p = *(u16*)(row + 8);
                u32 port = ((u32)(p & 0xFF) << 8) | (u32)((p >> 8) & 0xFF);
                o = utoa(o, port);
                *o++ = '\r';
                *o++ = '\n';
            }
        }

        /* "ports.txt" */
        mkstr(fname, 0xB5B3B0B1u, 4);        /* "ports.txt" */
        mkstr(fname + 4, 0xB9B56FB4u, 4);
        mkstr(fname + 8, 0x414141B5u, 4);
        fname[9] = 0;

        {
            HANDLE h = CreateFileA(fname, 0x40000000u, 0, 0, 2, 0x80u, 0);
            if (h != INVALID_HANDLE_VALUE) {
                u32 written;
                WriteFile(h, out, (u32)(o - out), &written, 0);
            }
        }
    }

    rc = 0;
    ExitProcess(rc);
}
