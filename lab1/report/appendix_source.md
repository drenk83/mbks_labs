# Приложения: полные листинги исходного кода

Файл сформирован автоматически из рабочих исходников (копировать в docx как приложения).

## Приложение А. Программа фаззинга формата файла

Файл: `lab1/fuzzer/fuzzer.py` (1122 строки)

```python
from __future__ import annotations

import ctypes
import datetime
import os
import random
import shutil
import struct
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

LAB1 = Path(__file__).resolve().parent
LOG_DIR = LAB1 / "log"          # журналы прогонов
CRASH_DIR = LAB1 / "crash"      # найденные краши (.bin + .txt)
COV_DIR = LAB1 / "cov"          # сиды и служебное DynamoRIO (создаётся в режиме покрытия)

TARGET_NAME = "vuln2.exe"
DLL_NAME = "func.dll"
CONFIG_NAME = "config_2"
TARGET_PATH = LAB1 / TARGET_NAME
DLL_PATH = LAB1 / DLL_NAME
CONFIG_PATH = LAB1 / CONFIG_NAME

DRRUN = Path(r"C:\Tools\DynamoRIO\bin32\drrun.exe")
COVERED_MODULES = {TARGET_NAME.lower(), DLL_NAME.lower()}

MARKER = b"/start"              # маркер начала полезных данных в конфиге
HEADER_LEN = 48                 # размер шапки конфига
VARIANT_OFFSET = 0              # байт номера варианта — НЕ мутируется
TIMEOUT_NATIVE = 10.0           # сек
TIMEOUT_DRCOV = 30.0            # сек

# Граничные значения из ТЗ: (ширина в байтах, значение).
# Для каждой ширины есть 0x00, 0xFF.., половина диапазона и половина ±1:
#  1 байт : 00, 7E, 7F, 80, FF          (0xFF/2-1, 0xFF/2, 0xFF/2+1)
#  2 байта: 0000, 7FFE, 7FFF, 8000, 8001, FFFE, FFFF   (0xFFFF/2±1)
#  3 байта: 7FFFFF, 800000, FFFFFF
#  4 байта: 00000000, 0000FFFF, 7FFFFFFE, 7FFFFFFF, 80000000, FFFFFFFE, FFFFFFFF
BOUNDARY_SPEC = [
    (1, 0x00), (1, 0x7E), (1, 0x7F), (1, 0x80), (1, 0xFF),
    (2, 0x0000), (2, 0x7FFE), (2, 0x7FFF), (2, 0x8000), (2, 0x8001),
    (2, 0xFFFE), (2, 0xFFFF),
    (3, 0x7FFFFF), (3, 0x800000), (3, 0xFFFFFF),
    (4, 0x00000000), (4, 0x0000FFFF), (4, 0x7FFFFFFE), (4, 0x7FFFFFFF),
    (4, 0x80000000), (4, 0xFFFFFFFE), (4, 0xFFFFFFFF),
]
DWORD_VALUES = [v for w, v in BOUNDARY_SPEC if w == 4]
DELIMITERS = b",:=;"

# ---- доп. задание: параметры адаптации ------------------------------------
STRATEGIES = ["byte", "boundary", "append", "inject"]   # порядок обхода по кругу
SHRINK_LIMIT = 3        # столько прогонов подряд с падением покрытия -> смена
PLATEAU_LIMIT = 30      # столько прогонов без нового покрытия -> смена

SEQ_LOG = LOG_DIR / "seq.log"
COV_LOG = LOG_DIR / "cov.log"
ADAPT_LOG = LOG_DIR / "adapt.log"

MAX_CRASH_SAVES = 20            # предохранитель: сколько крашей сохранять за сессию
_SAVED_SIGNATURES: set[tuple] = set()   # подписи уже сохранённых крашей
_ORIG_CONFIG: bytes | None = None       # снимок config_2 на старте сессии


# ---------------------------------------------------------------------------
# Мелкие утилиты
# ---------------------------------------------------------------------------

# Метка времени для имён crash_*.bin.
def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


# Дописать строку в журнал.
def append_log(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text + "\n")


# Начать сессию в журнале: заголовок и подпись колонок.
def start_log(path: Path, title: str, columns: str) -> None:
    append_log(path, "")
    append_log(path, "# %s  %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), title))
    append_log(path, "# %s" % columns)


# Печать вывода цели без гигантской строки buffer:.
def print_target_out(out: str) -> None:
    if not out:
        return
    for line in out.splitlines():
        text = line.strip()
        if not text or text.startswith("===="):
            continue
        if text.startswith("buffer:"):
            print("buffer: %d символов" % max(0, len(text) - 8))
            continue
        print(text)


# True, если код возврата — исключение Windows 0xC000xxxx (не exit(-1) и не Ctrl+C).
def is_crash(code: int | None) -> bool:
    if code is None:
        return False
    unsigned = code & 0xFFFFFFFF
    if unsigned == 0xC000013A:      # Ctrl+C — не краш
        return False
    return 0xC0000000 <= unsigned <= 0xCFFFFFFF


# Код возврата в виде 0x........; None → timeout.
def code_str(code: int | None) -> str:
    if code is None:
        return "timeout"
    return "0x%08X" % (code & 0xFFFFFFFF)


# Позиция сразу за маркером /start (оттуда цель копирует данные).
def find_data_offset(data: bytes) -> int:
    pos = data.find(MARKER)
    return pos + len(MARKER) if pos >= 0 else HEADER_LEN


# Смещения выровненных полей в шапке (4, 8, 12, ... 44).
def header_field_offsets(data: bytes, width: int = 4) -> list[int]:
    limit = min(HEADER_LEN, len(data)) - width
    return [off for off in range(width, limit + 1, width)]


# Снимок config_2, снятый в начале сессии.
def orig_config() -> bytes:
    if _ORIG_CONFIG is None:
        raise RuntimeError("config_2 ещё не прочитан — сначала prepare_work")
    return _ORIG_CONFIG


# Создать log/ и crash/, если их нет.
def ensure_dirs() -> None:
    for path in (LOG_DIR, CRASH_DIR):
        path.mkdir(parents=True, exist_ok=True)


# Проверить файлы рядом со скриптом, снять снимок config_2, создать log/ и crash/.
def prepare_work() -> None:
    global _ORIG_CONFIG
    missing = [path.name for path in (TARGET_PATH, DLL_PATH, CONFIG_PATH) if not path.exists()]
    if missing:
        print("Нет файлов рядом с fuzzer.py: %s" % ", ".join(missing))
        print("Положите vuln2.exe, func.dll, config_2 в %s" % LAB1)
        sys.exit(1)
    ensure_dirs()
    _k32.SetErrorMode(0x0001 | 0x0002 | 0x8000)   # без диалогов WER
    if _ORIG_CONFIG is None:
        _ORIG_CONFIG = CONFIG_PATH.read_bytes()


# Вернуть на диск снимок config_2 с начала сессии.
def restore_config() -> None:
    CONFIG_PATH.write_bytes(orig_config())


# Записать мутант в config_2 рядом со скриптом.
def write_config(data: bytes) -> None:
    CONFIG_PATH.write_bytes(data)


# ---------------------------------------------------------------------------
# Мутации (все пункты ТЗ)
# ---------------------------------------------------------------------------

# Заменить один байт (не трогая номер варианта).
def mut_byte(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    if len(data) <= 1:
        return data, "файл слишком мал"
    off = rng.randrange(1, len(data))
    val = rng.choice([0x00, 0xFF, 0x7F, 0x80, rng.randrange(256)])
    out = bytearray(data)
    was = out[off]
    out[off] = val
    return bytes(out), "байт [0x%04X] %02X→%02X" % (off, was, val)


# Заменить 2–8 случайных байт.
def mut_multi(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    if len(data) <= 1:
        return data, "файл слишком мал"
    count = rng.randint(2, 8)
    out = bytearray(data)
    first = None
    for _ in range(count):
        off = rng.randrange(1, len(data))
        val = rng.choice([0x00, 0xFF, rng.randrange(256)])
        if first is None:
            first = (off, out[off], val)
        out[off] = val
    return bytes(out), "%d байт, первый [0x%04X] %02X→%02X" % (
        count, first[0], first[1], first[2])


# Подставить граничное значение (00, FF, FFFF, половины диапазона ±1, …).
def mut_boundary(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    width, value = rng.choice(BOUNDARY_SPEC)
    candidates = [off for off in range(1, len(data) - width + 1)]
    if not candidates:
        return data, "нет места под %d байт" % width
    off = rng.choice(candidates)
    out = bytearray(data)
    out[off:off + width] = value.to_bytes(width, "little")
    return bytes(out), "граничное [0x%04X] %d байт → %0*X" % (off, width, width * 2, value)


# Записать граничное DWORD в поле шапки (смещения 4, 8, …).
def mut_field(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    offsets = header_field_offsets(data, 4)
    if not offsets:
        return data, "шапка короче 8 байт"
    off = rng.choice(offsets)
    value = rng.choice(DWORD_VALUES)
    out = bytearray(data)
    out[off:off + 4] = value.to_bytes(4, "little")
    return bytes(out), "поле шапки [0x%04X] → %08X" % (off, value)


# Дописать байты в конец файла.
def mut_append(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    size = rng.choice([16, 64, 256, 1024, 5120])
    fill = rng.choice([b"b", b"A", b"z", b"\xff", b"\x00"])
    return data + fill * size, "допись +%d байт" % size


# Вставить байты внутрь файла (часто сразу за /start).
def mut_expand(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    if len(data) <= 1:
        return data, "файл слишком мал"
    if rng.random() < 0.5:
        off = find_data_offset(data)
    else:
        off = rng.randrange(1, len(data))
    size = rng.choice([64, 512, 1024, 5120])
    out = data[:off] + b"b" * size + data[off:]
    return out, "вставка %d байт [0x%04X]" % (size, off)


# Найти ,:=; и испортить поле рядом с разделителем.
def mut_delim(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    positions = [i for i, byte in enumerate(data) if byte in DELIMITERS]
    if not positions:
        return data, "разделители ,:=; не найдены"
    pos = rng.choice(positions)
    choice = rng.random()
    marker = chr(data[pos])
    if choice < 0.4:
        out = data[:pos] + data[pos:pos + 1] * rng.randint(2, 64) + data[pos:]
        return out, "разделитель [0x%04X] '%s' повторён" % (pos, marker)
    if choice < 0.7:
        off = pos + 1 if pos + 1 < len(data) else pos - 1
        out = bytearray(data)
        was = out[off]
        out[off] = rng.choice([0x00, 0xFF])
        return bytes(out), "рядом с '%s' [0x%04X] %02X→%02X" % (marker, off, was, out[off])
    out = bytearray(data)
    size = rng.choice([512, 1024, 5120])
    out[pos + 1:pos + 1] = b"b" * size
    return bytes(out), "после '%s' [0x%04X] вставка %d байт" % (marker, pos, size)


# Увеличить число в 4-байтном поле шапки (×2/×4/×10 и слагаемое).
def mut_grow(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    offsets = header_field_offsets(data, 4)
    if not offsets:
        return data, "шапка короче 8 байт"
    off = rng.choice(offsets)
    old = struct.unpack_from("<I", data, off)[0]
    factor = rng.choice([2, 4, 10])
    add = rng.choice([100, 1000, 0x1000])
    new = (old * factor + add) & 0xFFFFFFFF
    out = bytearray(data)
    out[off:off + 4] = new.to_bytes(4, "little")
    return bytes(out), "поле [0x%04X] %d→%d" % (off, old, new)


# Вставить длинные данные за /start и поставить dst_len=FFFFFFFF — типичный краш.
def mut_inject(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    off = find_data_offset(data)
    size = rng.choice([3000, 5120, 8192, 16384])
    out = bytearray(data[:off]) + bytearray(b"b" * size) + bytearray(data[off:])
    fields = [8]
    if rng.random() < 0.5 and 4 + 4 <= len(out):
        fields.append(4)
    for field in fields:
        if field + 4 <= len(out):
            out[field:field + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    extra = " и shell_len" if 4 in fields else ""
    return bytes(out), "вставка %d байт за /start, dst_len=FFFFFFFF%s" % (size, extra)


MANUAL_MUTATIONS = {
    "byte": mut_byte,
    "multi": mut_multi,
    "boundary": mut_boundary,
    "field": mut_field,
    "grow": mut_grow,
    "append": mut_append,
    "expand": mut_expand,
    "delim": mut_delim,
    "inject": mut_inject,
}


# ---------------------------------------------------------------------------
# Запуск цели
# ---------------------------------------------------------------------------

# Запуск vuln2.exe из папки скрипта (цель читает config_2 из cwd).
def run_native(capture: bool = False) -> tuple[int | None, str, float, bool]:
    stdout = subprocess.PIPE if capture else subprocess.DEVNULL
    started = time.time()
    try:
        proc = subprocess.run([str(TARGET_PATH)], cwd=str(LAB1),
                              stdout=stdout, stderr=subprocess.STDOUT,
                              timeout=TIMEOUT_NATIVE)
        out = proc.stdout.decode("cp866", "replace") if (capture and proc.stdout) else ""
        return proc.returncode, out, time.time() - started, False
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("cp866", "replace") if (capture and exc.stdout) else ""
        return None, out, time.time() - started, True
    except OSError as exc:
        return None, "ошибка запуска: %s" % exc, time.time() - started, True


# --- мини-отладчик (ctypes): код исключения, регистры, стек -----------------

DEBUG_ONLY_THIS_PROCESS = 0x00000002
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_DEBUG_EVENT = 1
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_PROCESS_DEBUG_EVENT = 5
THREAD_GET_CONTEXT = 0x0008
THREAD_QUERY_INFORMATION = 0x0040
WOW64_CONTEXT_ALL = 0x00010007      # CONTROL | INTEGER | SEGMENTS, ветка i386

# DEBUG_EVENT разбирается вручную: отладчик 64-битный, смещения фиксированы.
OFF_EVENT_CODE, OFF_EVENT_PID, OFF_EVENT_TID = 0, 4, 8
OFF_UNION = 16                       # union выровнен на 8
OFF_EXC_CODE = OFF_UNION + 0
OFF_EXC_ADDRESS = OFF_UNION + 16
OFF_FIRST_CHANCE = OFF_UNION + 152   # sizeof(EXCEPTION_RECORD) == 152
OFF_EXIT_CODE = OFF_UNION + 0
OFF_IMAGE_BASE = OFF_UNION + 24      # CREATE_PROCESS_DEBUG_INFO.lpBaseOfImage


# Параметры CreateProcessW.
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
    ]


# Дескрипторы созданного процесса.
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]


# 32-битный контекст потока WOW64 (размер 716 байт).
class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint32), ("Dr1", ctypes.c_uint32),
        ("Dr2", ctypes.c_uint32), ("Dr3", ctypes.c_uint32),
        ("Dr6", ctypes.c_uint32), ("Dr7", ctypes.c_uint32),
        ("FloatSave", ctypes.c_byte * 112),
        ("SegGs", ctypes.c_uint32), ("SegFs", ctypes.c_uint32),
        ("SegEs", ctypes.c_uint32), ("SegDs", ctypes.c_uint32),
        ("Edi", ctypes.c_uint32), ("Esi", ctypes.c_uint32),
        ("Ebx", ctypes.c_uint32), ("Edx", ctypes.c_uint32),
        ("Ecx", ctypes.c_uint32), ("Eax", ctypes.c_uint32),
        ("Ebp", ctypes.c_uint32), ("Eip", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint32), ("EFlags", ctypes.c_uint32),
        ("Esp", ctypes.c_uint32), ("SegSs", ctypes.c_uint32),
        ("ExtendedRegisters", ctypes.c_byte * 512),
    ]


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
    wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]
_k32.CreateProcessW.restype = wintypes.BOOL
_k32.WaitForDebugEvent.argtypes = [ctypes.c_void_p, wintypes.DWORD]
_k32.WaitForDebugEvent.restype = wintypes.BOOL
_k32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
_k32.ContinueDebugEvent.restype = wintypes.BOOL
_k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.OpenThread.restype = wintypes.HANDLE
_k32.Wow64GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
_k32.Wow64GetThreadContext.restype = wintypes.BOOL
_k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
_k32.ReadProcessMemory.restype = wintypes.BOOL
_k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
_k32.TerminateProcess.restype = wintypes.BOOL
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CloseHandle.restype = wintypes.BOOL
_k32.SetErrorMode.argtypes = [wintypes.UINT]
_k32.SetErrorMode.restype = wintypes.UINT


# Снять 32-битные регистры потока WOW64.
def _grab_context(tid: int) -> WOW64_CONTEXT | None:
    handle = _k32.OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, False, tid)
    if not handle:
        return None
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = WOW64_CONTEXT_ALL
    ok = _k32.Wow64GetThreadContext(handle, ctypes.byref(ctx))
    _k32.CloseHandle(handle)
    return ctx if ok else None


# Прочитать size байт памяти процесса (стек).
def _read_stack(hprocess, address: int, size: int = 128) -> bytes:
    buf = (ctypes.c_ubyte * size)()          # именно c_ubyte: c_byte даёт знаковые значения
    read = ctypes.c_size_t(0)
    if _k32.ReadProcessMemory(hprocess, ctypes.c_void_p(address), buf, size,
                              ctypes.byref(read)):
        return bytes(buf[:read.value])
    return b""


# Слить очередь отладчика. Иначе следующий сеанс получает чужой EXIT_PROCESS.
def _drain_debug_events(timeout: float = 1.0) -> None:
    event = ctypes.create_string_buffer(512)
    deadline = time.time() + timeout
    idle = 0
    while time.time() < deadline:
        if not _k32.WaitForDebugEvent(ctypes.byref(event), 30):
            idle += 1
            if idle >= 3:
                break
            continue
        idle = 0
        pid = struct.unpack_from("<I", event, OFF_EVENT_PID)[0]
        tid = struct.unpack_from("<I", event, OFF_EVENT_TID)[0]
        _k32.ContinueDebugEvent(pid, tid, DBG_CONTINUE)


# Запускает цель под отладчиком и снимает регистры/стек на исключении.
def debug_capture(timeout: float = 15.0) -> dict:
    result: dict = {"exception": None, "first_chance": None, "regs": None,
                    "stack": b"", "image_base": None, "exit_code": None,
                    "saved_eip_addr": None, "saved_eip_value": None,
                    "timeout": False, "error": None}
    _k32.SetErrorMode(0x0001 | 0x0002 | 0x8000)   # без диалогов WER
    _drain_debug_events(0.3)                      # хвост прошлого сеанса, если был
    startup = STARTUPINFOW()
    startup.cb = ctypes.sizeof(STARTUPINFOW)
    info = PROCESS_INFORMATION()
    cmdline = ctypes.create_unicode_buffer('"%s"' % TARGET_PATH)
    # CREATE_NO_WINDOW нельзя: без консоли цель проходит тот же конфиг
    # без ACCESS_VIOLATION и выходит 0 — тогда в логе краша нет регистров.
    # Окно не всплывает: дочерний процесс наследует консоль Python.
    started = _k32.CreateProcessW(None, cmdline, None, None, False,
                                  DEBUG_ONLY_THIS_PROCESS,
                                  None, str(LAB1), ctypes.byref(startup),
                                  ctypes.byref(info))
    if not started:
        result["error"] = "CreateProcessW: ошибка %d" % ctypes.get_last_error()
        return result
    deadline = time.time() + timeout
    event = ctypes.create_string_buffer(512)
    try:
        while True:
            remaining = int(max(0.0, deadline - time.time()) * 1000)
            if remaining <= 0:
                result["timeout"] = True
                _k32.TerminateProcess(info.hProcess, 1)
                break
            if not _k32.WaitForDebugEvent(ctypes.byref(event), min(remaining, 500)):
                continue
            code = struct.unpack_from("<I", event, OFF_EVENT_CODE)[0]
            pid = struct.unpack_from("<I", event, OFF_EVENT_PID)[0]
            tid = struct.unpack_from("<I", event, OFF_EVENT_TID)[0]
            if pid != info.dwProcessId:
                # хвост предыдущего сеанса — обязателен Continue, иначе очередь клинит
                _k32.ContinueDebugEvent(pid, tid, DBG_CONTINUE)
                continue
            cont = DBG_CONTINUE
            stop = False
            if code == EXCEPTION_DEBUG_EVENT:
                exc = struct.unpack_from("<I", event, OFF_EXC_CODE)[0]
                first = struct.unpack_from("<I", event, OFF_FIRST_CHANCE)[0]
                if is_crash(exc):
                    # первое шанс-событие запоминаем, второе (fatal) перезаписывает
                    if result["exception"] is None or first == 0:
                        result["exception"] = exc
                        result["first_chance"] = first
                        ctx = _grab_context(tid)
                        if ctx is not None:
                            result["regs"] = ctx
                            result["stack"] = _read_stack(info.hProcess, ctx.Esp, 128)
                            # сохранённый адрес возврата лежит по [EBP+4]
                            saved = _read_stack(info.hProcess, ctx.Ebp + 4, 4)
                            if len(saved) == 4:
                                result["saved_eip_addr"] = ctx.Ebp + 4
                                result["saved_eip_value"] = struct.unpack("<I", saved)[0]
                    if first == 0:
                        _k32.TerminateProcess(info.hProcess, 0)
                        stop = True
                    else:
                        cont = DBG_EXCEPTION_NOT_HANDLED
                else:
                    cont = DBG_EXCEPTION_NOT_HANDLED
            elif code == CREATE_PROCESS_DEBUG_EVENT:
                result["image_base"] = struct.unpack_from("<Q", event, OFF_IMAGE_BASE)[0]
            elif code == EXIT_PROCESS_DEBUG_EVENT:
                result["exit_code"] = struct.unpack_from("<I", event, OFF_EXIT_CODE)[0]
                stop = True
            _k32.ContinueDebugEvent(pid, tid, cont)
            if stop:
                break
    finally:
        _k32.TerminateProcess(info.hProcess, 0)
        _drain_debug_events()
        _k32.CloseHandle(info.hThread)
        _k32.CloseHandle(info.hProcess)
    return result


# ---------------------------------------------------------------------------
# Сохранение краша
# ---------------------------------------------------------------------------

# Краткий список отличий мутанта от оригинала.
def describe_changes(orig: bytes, mutant: bytes, limit: int = 8) -> list[str]:
    lines: list[str] = []
    shown = 0
    changed = 0
    delta = len(mutant) - len(orig)
    insert_at: int | None = None
    delete_at: int | None = None
    if delta > 0:
        for off in range(len(orig) + 1):
            if orig[off:] == mutant[off + delta:]:
                insert_at = off
                break
    elif delta < 0:
        for off in range(len(mutant) + 1):
            if mutant[off:] == orig[off - delta:]:
                delete_at = off
                break
    prefix = min(len(orig), len(mutant))
    if insert_at is not None:
        prefix = insert_at
    elif delete_at is not None:
        prefix = delete_at
    for i in range(prefix):
        if orig[i] != mutant[i]:
            changed += 1
            if shown < limit:
                lines.append("  [0x%04X] %02X → %02X" % (i, orig[i], mutant[i]))
                shown += 1
    if changed > shown:
        lines.append("  … ещё %d байт" % (changed - shown))
    if insert_at is not None:
        if insert_at == len(orig):
            lines.append("  допись %d байт" % delta)
        else:
            lines.append("  вставка %d байт по смещению 0x%X" % (delta, insert_at))
    elif delete_at is not None:
        lines.append("  удалено %d байт с 0x%X" % (-delta, delete_at))
    elif delta > 0:
        lines.append("  файл длиннее на %d байт" % delta)
    elif delta < 0:
        lines.append("  файл короче на %d байт" % (-delta))
    return lines


# Сохраняет краш-конфиг и лог с кодом ошибки, регистрами, стеком и заменами.
# Одинаковые краши (по signature) сохраняются один раз — иначе режим покрытия
# плодит сотни файлов на одну и ту же ошибку.
def save_crash(data: bytes, orig: bytes, note: str, exit_code: int | None,
               elapsed: float, debugger: bool = True,
               signature: tuple | None = None) -> tuple[Path | None, Path | None]:
    if signature is None:
        signature = (exit_code, len(data))
    if signature in _SAVED_SIGNATURES or len(_SAVED_SIGNATURES) >= MAX_CRASH_SAVES:
        return None, None
    _SAVED_SIGNATURES.add(signature)
    CRASH_DIR.mkdir(parents=True, exist_ok=True)
    stamp = now_stamp()
    bin_path = CRASH_DIR / ("crash_%s.bin" % stamp)
    txt_path = CRASH_DIR / ("crash_%s.txt" % stamp)
    suffix = 1
    while bin_path.exists() or txt_path.exists():
        bin_path = CRASH_DIR / ("crash_%s_%d.bin" % (stamp, suffix))
        txt_path = CRASH_DIR / ("crash_%s_%d.txt" % (stamp, suffix))
        suffix += 1
    bin_path.write_bytes(data)

    lines = [
        "крах %s" % code_str(exit_code),
        "мутация: %s" % note,
        "размер: %d → %d байт" % (len(orig), len(data)),
        "время: %.3f с" % elapsed,
        "",
    ]
    if debugger:
        info = None
        for _attempt in range(3):
            info = debug_capture()
            if info.get("error") or info.get("exception") is not None:
                break
        if info.get("error"):
            lines.append("отладчик: %s" % info["error"])
        elif info.get("exception") is not None:
            ctx = info.get("regs")
            base = info.get("image_base")
            lines.append("исключение под отладчиком: %s" % code_str(info["exception"]))
            if base:
                lines.append("база модуля: 0x%08X" % base)
            if ctx is not None:
                rel = ""
                if base:
                    rel = "  (= база+0x%X)" % ((ctx.Eip - (base & 0xFFFFFFFF)) & 0xFFFFFFFF)
                lines += [
                    "EIP=0x%08X%s" % (ctx.Eip, rel),
                    "EAX=0x%08X  EBX=0x%08X  ECX=0x%08X  EDX=0x%08X" % (
                        ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx),
                    "ESI=0x%08X  EDI=0x%08X  EBP=0x%08X  ESP=0x%08X" % (
                        ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp),
                ]
                if info.get("saved_eip_value") is not None:
                    lines.append("saved EIP [EBP+4]=0x%08X" % info["saved_eip_value"])
                stack = info.get("stack") or b""
                if stack:
                    lines.append("стек:")
                    for row in range(0, min(len(stack), 64), 16):
                        chunk = stack[row:row + 16]
                        lines.append("  +%02X  %s" % (row, " ".join("%02X" % b for b in chunk)))
        else:
            lines.append("под отладчиком не упало (exit %s)" % code_str(info.get("exit_code")))
    lines.append("")
    lines.append("правки к оригиналу:")
    lines += describe_changes(orig, data) or ["  (нет отличий в префиксе)"]
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return bin_path, txt_path


# ---------------------------------------------------------------------------
# Покрытие: DynamoRIO drcov
# ---------------------------------------------------------------------------

# Разбор лога drcov: множество (имя модуля, смещение BB) для цели и func.dll.
def parse_drcov(path: Path) -> set[tuple[str, int]]:
    raw = path.read_bytes()
    table_at = raw.find(b"BB Table:")
    if table_at < 0:
        return set()
    modules: dict[int, tuple[int, str]] = {}
    for line in raw[:table_at].decode("utf-8", "replace").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 10 and parts[0].isdigit():
            modules[int(parts[0])] = (int(parts[2], 16), parts[9])
    count = int(raw[table_at:].split(b"\n")[0].split(b":")[1].split()[0])
    body = raw.index(b"\n", table_at) + 1
    blocks: set[tuple[str, int]] = set()
    for index in range(count):
        start, _size, mod_id = struct.unpack_from("<IHH", raw, body + index * 8)
        mod = modules.get(mod_id)
        if not mod:
            continue
        name = os.path.basename(mod[1]).lower()
        if name in COVERED_MODULES:
            # start — смещение от базы модуля (проверено на drcov 11.3)
            blocks.add((name, start))
    return blocks


# Прогон цели под drrun -t drcov: покрытие + код возврата.
def run_cov(keep_log: bool = False) -> tuple[set[tuple[str, int]], int | None, str, float, Path | None]:
    COV_DIR.mkdir(parents=True, exist_ok=True)
    (COV_DIR / "dynamorio_config").mkdir(parents=True, exist_ok=True)
    logdir = COV_DIR / "drcov_logs"
    if logdir.exists():
        shutil.rmtree(logdir, ignore_errors=True)
    logdir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["DYNAMORIO_CONFIGDIR"] = str(COV_DIR / "dynamorio_config")
    cmd = [str(DRRUN), "-t", "drcov", "-logdir", str(logdir), "--", str(TARGET_PATH)]
    started = time.time()
    code: int | None = None
    out = ""
    try:
        proc = subprocess.run(cmd, cwd=str(LAB1), env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=TIMEOUT_DRCOV)
        code = proc.returncode
        out = proc.stdout.decode("cp866", "replace")
    except subprocess.TimeoutExpired:
        code = None
    except OSError as exc:
        out = "ошибка запуска drrun: %s" % exc
    logs = sorted(logdir.glob("drcov*.log"))
    blocks: set[tuple[str, int]] = set()
    log_path = None
    if logs:
        log_path = logs[-1]
        blocks = parse_drcov(log_path)
    if not keep_log:
        shutil.rmtree(logdir, ignore_errors=True)
    return blocks, code, out, time.time() - started, log_path


# ---------------------------------------------------------------------------
# Планировщик стратегий (доп. задание)
# ---------------------------------------------------------------------------

# Смена алгоритма мутирования по результатам покрытия.
# Сигналы:
# * gain    — появились новые базовые блоки (покрытие выросло);
# * shrink  — покрытие прогона меньше покрытия родителя
# (BB_run < BB_parent) — «покрытие стало меньше»;
# * plateau — PLATEAU_LIMIT прогонов подряд без нового покрытия.
# Реакция: следующая стратегия по кругу STRATEGIES.
class Scheduler:
    def __init__(self, fixed: str | None = None):
        self.fixed = fixed          # None | имя стратегии | "cycle" (без обратной связи)
        self.index = 0
        self.shrink = 0
        self.since_gain = 0
        self.switches = 0

    @property
    def current(self) -> str:
        if self.fixed in (None, "cycle"):
            return STRATEGIES[self.index]
        return self.fixed

    # Возвращает (было, стало, причина) при смене стратегии, иначе None.
    def update(self, bb_run: int, bb_parent: int, gain: bool) -> tuple[str, str, str] | None:
        if self.fixed == "cycle":
            # контрольный режим: стратегии меняются по кругу БЕЗ учёта покрытия
            self.since_gain += 1
            if self.since_gain < PLATEAU_LIMIT:
                return None
            previous = STRATEGIES[self.index]
            self.index = (self.index + 1) % len(STRATEGIES)
            self.since_gain = 0
            self.switches += 1
            return previous, STRATEGIES[self.index], "cycle"
        if gain:
            self.since_gain = 0
            self.shrink = 0
            return None
        self.since_gain += 1
        self.shrink = self.shrink + 1 if bb_run < bb_parent else 0
        reason = None
        if self.shrink >= SHRINK_LIMIT:
            reason = "shrink"
        elif self.since_gain >= PLATEAU_LIMIT:
            reason = "plateau"
        if reason is None or self.fixed:
            return None
        previous = STRATEGIES[self.index]
        self.index = (self.index + 1) % len(STRATEGIES)
        self.shrink = 0
        self.since_gain = 0
        self.switches += 1
        return previous, STRATEGIES[self.index], reason


# Применить одну из четырёх стратегий покрытия.
def apply_strategy(name: str, data: bytes, rng: random.Random) -> tuple[bytes, str]:
    func = {"byte": mut_byte, "boundary": mut_boundary,
            "append": mut_append, "inject": mut_inject}[name]
    return func(data, rng)


# ---------------------------------------------------------------------------
# Общий обработчик одного прогона
# ---------------------------------------------------------------------------

# Счётчики прогонов/крашей и скорость для прогресса в консоли.
class Stats:
    def __init__(self):
        self.runs = 0
        self.crashes = 0
        self.timeouts = 0
        self.started = time.time()

    def rate(self) -> float:
        return self.runs / max(1e-6, time.time() - self.started)


# Записать мутант, запустить цель, при крахе сохранить вход и лог.
def execute(data: bytes, orig: bytes, note: str, stats: Stats,
            log_path: Path | None = None, tag: str = "",
            capture: bool = False) -> tuple[str, int | None, str]:
    write_config(data)
    code, out, elapsed, timed_out = run_native(capture=capture)
    stats.runs += 1
    if timed_out:
        status = "timeout"
        stats.timeouts += 1
    elif is_crash(code):
        status = "crash"
        stats.crashes += 1
    elif (code & 0xFFFFFFFF) == 0xFFFFFFFF:
        status = "exit(-1)"
    else:
        status = "ok"
    if log_path is not None:
        append_log(log_path, "%d  %s  %s  %s  %d  %s" % (
            stats.runs, tag, status, code_str(code), len(data), note))
    if status == "crash":
        bin_path, _txt = save_crash(data, orig, note, code, elapsed,
                                    signature=(code & 0xFFFFFFFF, note))
        if bin_path is not None:
            print("  крах %s  %s  → %s" % (code_str(code), note, bin_path.name))
        else:
            print("  крах %s  %s  (повтор, файл не пишем)" % (code_str(code), note))
    return status, code, out


# ---------------------------------------------------------------------------
# Режимы
# ---------------------------------------------------------------------------

# Перебрать все смещения файла × все граничные значения.
def mode_seq1(max_runs: int | None = None, rng: random.Random | None = None) -> None:
    _SAVED_SIGNATURES.clear()
    orig = orig_config()
    total = sum(1 for off in range(1, len(orig))
                for width, _ in BOUNDARY_SPEC if off + width <= len(orig))
    print("Последовательная замена: %d смещений, до %d прогонов" % (len(orig) - 1, total))
    start_log(SEQ_LOG, "последовательная замена",
              "прогон  проход  статус  код  размер  мутация")
    stats = Stats()
    for off in range(1, len(orig)):
        for width, value in BOUNDARY_SPEC:
            if off + width > len(orig):
                continue
            if max_runs and stats.runs >= max_runs:
                print("Стоп: лимит %d прогонов. Крашей: %d" % (max_runs, stats.crashes))
                restore_config()
                return
            data = bytearray(orig)
            data[off:off + width] = value.to_bytes(width, "little")
            note = "[0x%04X] %d байт → %0*X" % (off, width, width * 2, value)
            execute(bytes(data), orig, note, stats, SEQ_LOG, "A")
            if stats.runs % 500 == 0:
                print("  %d/%d  крашей %d  %.0f/с" % (
                    stats.runs, total, stats.crashes, stats.rate()))
    print("Готово: %d прогонов, крашей %d" % (stats.runs, stats.crashes))
    restore_config()


# Вставить данные за /start и перебрать граничные значения полей шапки.
def mode_seq2(max_runs: int | None = None, rng: random.Random | None = None) -> None:
    _SAVED_SIGNATURES.clear()
    orig = orig_config()
    data_off = find_data_offset(orig)
    lengths = [5120, 2500]
    print("Удлинённый файл: вставка за /start (смещение %d), перебор полей шапки" % data_off)
    start_log(SEQ_LOG, "удлинённый файл",
              "прогон  проход  статус  код  размер  мутация")
    stats = Stats()
    for size in lengths:
        base = orig[:data_off] + b"b" * size + orig[data_off:]
        fields = [8, 4] + [off for off in header_field_offsets(base, 4) if off not in (8, 4)]
        for field in fields:
            for value in [0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE,
                          0x0000FFFF, 0x00000000]:
                if max_runs and stats.runs >= max_runs:
                    print("Стоп: лимит %d прогонов. Крашей: %d" % (max_runs, stats.crashes))
                    restore_config()
                    return
                data = bytearray(base)
                data[field:field + 4] = value.to_bytes(4, "little")
                note = "вставка %d байт за /start, поле [0x%04X]=%08X" % (size, field, value)
                execute(bytes(data), orig, note, stats, SEQ_LOG, "B")
                if stats.crashes:
                    print("Крах на прогоне %d, config_2 восстановлен" % stats.runs)
                    restore_config()
                    return
    print("Готово: %d прогонов, крашей %d" % (stats.runs, stats.crashes))
    restore_config()


REASON_RU = {
    "plateau": "нет новых блоков",
    "shrink": "маршрут короче родителя",
    "cycle": "по кругу",
}


# Фаззинг с измерением покрытия; при необходимости меняет стратегию.
def mode_cov(max_runs: int = 300, fixed: str | None = None,
             rng: random.Random | None = None, seed: int = 7) -> None:
    _SAVED_SIGNATURES.clear()
    rng = rng or random.Random(seed)
    orig = orig_config()
    stats = Stats()

    write_config(orig)
    base_blocks, base_code, _out, base_time, _log = run_cov()
    if not base_blocks:
        print("Покрытие не получено. Проверьте DynamoRIO: %s" % DRRUN)
        restore_config()
        return
    bb_global = set(base_blocks)
    print("Покрытие оригинала: %d блоков (%.2f с)" % (len(bb_global), base_time))
    if is_crash(base_code):
        print("Внимание: оригинальный конфиг уже даёт крах %s" % code_str(base_code))

    parents: list[dict] = [{"name": "оригинал", "data": orig, "bb": len(base_blocks)}]
    scheduler = Scheduler(fixed=fixed)
    if fixed == "cycle":
        mode = "4 стратегии по кругу, без обратной связи"
    elif fixed:
        mode = "только стратегия %s" % fixed
    else:
        mode = "смена стратегии по покрытию"
    print("Режим: %s. Прогонов: %d" % (mode, max_runs))

    start_log(COV_LOG, mode,
              "прогон  стратегия  статус  код  блоков/родитель/всего  мутация")
    start_log(ADAPT_LOG, mode + ", база %d блоков" % len(bb_global),
              "прогон  было → стало  почему  блоков/родитель/всего")

    for run in range(1, max_runs + 1):
        parent = rng.choice(parents)
        strategy = scheduler.current
        data, note = apply_strategy(strategy, parent["data"], rng)
        if data == parent["data"]:
            append_log(COV_LOG, "%d  %s  noop  —  —  %s" % (run, strategy, note))
            continue
        write_config(data)
        blocks, code, _out, elapsed, _log = run_cov()
        bb_run = len(blocks)
        gain_blocks = blocks - bb_global
        gain = bool(gain_blocks)
        if gain:
            bb_global |= blocks
            seed_path = COV_DIR / ("seed_%04d_%d.bin" % (run, bb_run))
            seed_path.write_bytes(data)
            parents.append({"name": seed_path.name, "data": data, "bb": bb_run})
        if is_crash(code):
            status = "crash"
        elif code is None:
            status = "timeout"
        else:
            status = "ok"
        if status == "crash":
            stats.crashes += 1
            bin_path, _txt = save_crash(
                data, orig, "прогон %d, %s, %s" % (run, strategy, note),
                code, elapsed, signature=(code & 0xFFFFFFFF, strategy))
            if bin_path is not None:
                print("  крах %s  прогон %d (%s)  → %s" % (
                    code_str(code), run, strategy, bin_path.name))
        append_log(COV_LOG, "%d  %s  %s  %s  %d/%d/%d  %s" % (
            run, strategy, status, code_str(code),
            bb_run, parent["bb"], len(bb_global), note))
        if gain:
            print("  прогон %d: +%d новых блоков (всего %d), стратегия %s" % (
                run, len(gain_blocks), len(bb_global), strategy))
        switch = scheduler.update(bb_run, parent["bb"], gain)
        if switch:
            prev, new, reason = switch
            why = REASON_RU.get(reason, reason)
            append_log(ADAPT_LOG, "%d  %s → %s  %s  %d/%d/%d" % (
                run, prev, new, why, bb_run, parent["bb"], len(bb_global)))
            print("  прогон %d: стратегия %s → %s (%s)" % (run, prev, new, why))
        if run % 25 == 0:
            print("  %d/%d  блоков %d  сидов %d  смен %d  %.1f/с" % (
                run, max_runs, len(bb_global), len(parents) - 1,
                scheduler.switches, run / max(1e-6, time.time() - stats.started)))
    print("Готово: %d прогонов, блоков %d → %d, сидов %d, смен %d, крашей %d" % (
        max_runs, len(base_blocks), len(bb_global),
        len(parents) - 1, scheduler.switches, stats.crashes))
    restore_config()


# Ручной режим: одна мутация указанного типа по текущему config_2.
def mode_manual(kind: str, rng: random.Random | None = None) -> None:
    rng = rng or random.Random()
    orig = orig_config()
    base = CONFIG_PATH.read_bytes()
    data, note = MANUAL_MUTATIONS[kind](base, rng)
    print("Мутация: %s" % note)
    stats = Stats()
    status, code, out = execute(data, orig, note, stats, SEQ_LOG, kind, capture=True)
    print_target_out(out)
    print("Результат: %s, код %s" % (status, code_str(code)))


# Поиск разделителей полей ,:=; в текущем конфиге (требование ТЗ).
def mode_lookup_delims() -> None:
    data = CONFIG_PATH.read_bytes()
    found = [(i, chr(b)) for i, b in enumerate(data) if b in DELIMITERS]
    print("Файл %d байт, разделителей ,:=;: %d" % (len(data), len(found)))
    for offset, symbol in found[:50]:
        print("  [0x%04X] '%s'" % (offset, symbol))
    if not found:
        print("  в этом конфиге их нет")


# Один запуск текущего config_2 с выводом цели и регистрами при падении.
def mode_run_once() -> None:
    prepare_work()
    orig = orig_config()
    data = CONFIG_PATH.read_bytes()
    print("Запуск %s (%d байт)" % (CONFIG_PATH.name, len(data)))
    code, out, elapsed, timed_out = run_native(capture=True)
    print_target_out(out)
    print("Код %s, %.3f с%s" % (code_str(code), elapsed, ", таймаут" if timed_out else ""))
    if is_crash(code):
        stats = Stats()
        execute(data, orig, "текущий config_2", stats, None, "run")
    else:
        print("Краха нет")


# ---------------------------------------------------------------------------
# Меню
# ---------------------------------------------------------------------------

MENU = """
================= ФАЗЗЕР lab1 (вариант 2) =================
 1  Последовательная замена байт
 2  Удлинённый файл
 3  Фаззинг с покрытием
 4  Замена одного байта
 5  Замена нескольких байт
 6  Допись в конец файла
 7  Разделители полей
 8  Вставка внутрь файла
 9  Увеличение поля шапки
10  Запуск цели
 0  Выход
===========================================================
"""


# Спросить целое; пустой ввод — default.
def ask_int(prompt: str, default: int) -> int:
    try:
        raw = input(prompt).strip()
        return int(raw) if raw else default
    except (ValueError, EOFError):
        return default


# Интерактивное меню режимов фаззера.
def menu_loop() -> None:
    prepare_work()
    rng = random.Random()
    while True:
        print(MENU)
        try:
            choice = input("выберите пункт> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nвыход")
            return
        try:
            if choice == "1":
                mode_seq1(ask_int("лимит прогонов (0 = без лимита): ", 0) or None)
            elif choice == "2":
                mode_seq2()
            elif choice == "3":
                mode_cov(ask_int("сколько прогонов (по умолчанию 300): ", 300))
            elif choice == "4":
                mode_manual("byte", rng)
            elif choice == "5":
                mode_manual("multi", rng)
            elif choice == "6":
                mode_manual("append", rng)
            elif choice == "7":
                mode_lookup_delims()
                mode_manual("delim", rng)
            elif choice == "8":
                mode_manual("expand", rng)
            elif choice == "9":
                mode_manual("grow", rng)
            elif choice == "10":
                mode_run_once()
            elif choice == "0":
                print("выход")
                return
            else:
                print("неизвестный пункт")
        except KeyboardInterrupt:
            print("\n[!] прервано пользователем")
            restore_config()


# Точка входа: UTF-8 в консоли и меню.
def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    menu_loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Приложение Б. IDAPython-скрипт: функции ввода и небезопасные функции (имя + адрес вызова)

Файл: `lab1/ida/find_calls.py` (245 строк)

```python
"""IDAPython 3 / IDA 7.7: вызовы функций ввода и небезопасных копирований.

Запуск: ida.exe → lab1/ida/vuln2.exe → File → Script file (рабочая копия цели).
Имена сверяются с белым списком (не подстрока mem/str).
"""

from __future__ import print_function

import os

import idaapi
import idautils
import idc

try:
    import ida_nalt
except ImportError:
    ida_nalt = None

# Точные имена из ТЗ плюс обычные CRT-варианты. Не «if 'mem' in name».
INPUT_FUNCS = {
    "fread",
    "fread_s",
    "fscanf",
    "fscanf_s",
    "sscanf",
    "sscanf_s",
    "scanf",
    "scanf_s",
    "read",
    "_read",
    "fgets",
    "gets",
    "gets_s",
    "fopen",
    "fopen_s",
    "wfopen",
    "_wfopen",
}

UNSAFE_FUNCS = {
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "strncpy",
    "strncat",
    "memcpy",
    "memmove",
    "memcpy_s",
    "memmove_s",
    "wcscpy",
    "lstrcpyA",
    "lstrcpyW",
    "wsprintfA",
    "wsprintfW",
}

CALL_XREF = {
    idaapi.fl_CN,
    idaapi.fl_CF,
    idaapi.fl_JN,
    idaapi.fl_JF,
}

# Мнемоники, которыми вызывают заглушку импорта. Проверка по мнемонике надёжнее
# фильтра по типу xref: у MinGW-заглушек `jmp ds:__imp_*` IDA отдаёт тип, который
# в старом варианте скрипта отбрасывался, и вызовы не находились.
CALL_MNEMS = {"call", "jmp", "ljmp", "lcall", "jmpq"}


def _log(line, sink):
    """Печать в Output window IDA и в список для файла."""
    text = line if line.endswith("\n") else line + "\n"
    idaapi.msg(text)
    sink.append(line.rstrip("\n"))


def _script_dir():
    """Каталог скрипта; cwd у IDA — папка ida.exe, на него нельзя опираться."""
    here = globals().get("__file__")
    if here:
        return os.path.dirname(os.path.abspath(here))
    return os.path.dirname(idaapi.get_input_file_path() or "")


def _normalize_names(raw):
    """Варианты имени: __imp_fread, _fread, fread@12 → fread."""
    if not raw:
        return set()
    names = {raw}
    n = raw
    if n.startswith("__imp_"):
        n = n[6:]
        names.add(n)
    if "@" in n:
        n = n.split("@", 1)[0]
        names.add(n)
    if n.startswith("_") and len(n) > 1:
        names.add(n[1:])
    return names


def _classify(raw):
    """'input' / 'unsafe' / None по белому списку."""
    variants = _normalize_names(raw)
    if variants & INPUT_FUNCS:
        return "input"
    if variants & UNSAFE_FUNCS:
        return "unsafe"
    return None


def _pretty_name(raw):
    """Каноническое имя из белого списка, иначе исходное."""
    variants = _normalize_names(raw)
    for group in (INPUT_FUNCS, UNSAFE_FUNCS):
        hit = variants & group
        if hit:
            return sorted(hit)[0]
    return raw


def _iter_imports():
    """Пары (ea IAT, имя) из таблицы импортов, не из Names window."""
    if ida_nalt is not None:
        qty = ida_nalt.get_import_module_qty()
        enum_names = ida_nalt.enum_import_names
    else:
        qty = idaapi.get_import_module_qty()
        enum_names = idaapi.enum_import_names

    found = []

    def callback(ea, name, _ord):
        if name:
            found.append((ea, name))
        return True

    for i in range(qty):
        enum_names(i, callback)
    return found


def _is_thunk_at(ea):
    """Заглушка импорта: `jmp ds:__imp_*` (в MinGW-сборке — отдельная, не функция)."""
    mnem = (idc.print_insn_mnem(ea) or "").lower()
    if mnem not in ("jmp", "ljmp", "jmpq"):
        return False
    func = idaapi.get_func(ea)
    if func is None:
        # IDA не считает такую заглушку функцией — это и есть переход на импорт
        return True
    if func.flags & idaapi.FUNC_THUNK:
        return True
    return ea == func.start_ea


def _code_xrefs_to(ea):
    """Адреса call/jmp, ссылающихся на ea (по мнемонике, а не по типу xref)."""
    addrs = []
    for xref in idautils.XrefsTo(ea, 0):
        mnem = (idc.print_insn_mnem(xref.frm) or "").lower()
        if mnem in CALL_MNEMS:
            addrs.append(xref.frm)
        elif getattr(xref, "iscode", False) and xref.type in CALL_XREF:
            addrs.append(xref.frm)
    return sorted(set(addrs))


def _collect_calls(import_ea):
    """Прямые вызовы импорта и вызовы через thunk."""
    calls = set()
    for frm in _code_xrefs_to(import_ea):
        if _is_thunk_at(frm):
            thunk = idaapi.get_func(frm)
            target = thunk.start_ea if thunk else frm
            for caller in _code_xrefs_to(target):
                calls.add(caller)
        else:
            calls.add(frm)
    return sorted(calls)


def _func_owner(ea):
    """Имя и старт функции, из которой сделан call."""
    func = idaapi.get_func(ea)
    if func is None:
        return "-", 0
    name = idc.get_func_name(func.start_ea) or "sub_%X" % func.start_ea
    return name, func.start_ea


def main():
    idaapi.auto_wait()
    lines = []
    imports = _iter_imports()

    hits = []
    for ea, name in imports:
        kind = _classify(name)
        if kind:
            hits.append((kind, _pretty_name(name), ea, name))

    hits.sort(key=lambda t: (0 if t[0] == "input" else 1, t[1], t[2]))

    n_calls = 0
    seen_pretty = set()
    for kind, pretty, ea, raw in hits:
        seen_pretty.add(pretty)
        calls = _collect_calls(ea)
        _log("[%s]  %s  (import 0x%08X, raw %s)" % (kind, pretty, ea, raw), lines)
        if not calls:
            _log("  (нет code-xref call/jmp)", lines)
            continue
        for call_ea in calls:
            owner, owner_ea = _func_owner(call_ea)
            n_calls += 1
            _log(
                "  call 0x%08X  in %s (0x%08X)" % (call_ea, owner, owner_ea),
                lines,
            )

    _log("", lines)
    _log("imports matched: %d" % len(hits), lines)
    _log("call sites: %d" % n_calls, lines)
    for must in ("fread", "memcpy"):
        if must not in seen_pretty:
            _log("НЕ НАЙДЕНО: %s" % must, lines)

    out_path = os.path.join(_script_dir(), "calls.txt")
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        _log("written: %s" % out_path, lines)
    except OSError as exc:
        _log("не удалось записать %s: %s" % (out_path, exc), lines)

    # в batch-режиме (idat64 -A -S) IDA сама не завершается — закрываем явно;
    # в GUI переменная не выставлена и окно остаётся открытым
    if os.environ.get("MBKS_IDA_BATCH") == "1":
        idc.qexit(0)


main()
```

## Приложение В. Вспомогательный IDAPython-скрипт: дизассемблер участка с уязвимостью

Файл: `lab1/ida/dump_vuln.py` (215 строк)

```python
"""IDAPython 3 / IDA 7.7: дизассемблер и псевдокод участка с уязвимостью.

Ищет функцию, которая печатает `buffer: ` (там же копирование данных из конфига),
и выгружает в `vuln_disasm.txt`:
  * дизассемблер этой функции с комментариями по вызовам memcpy/strncpy;
  * псевдокод Hex-Rays (если декомпилятор доступен);
  * список вызовов небезопасных функций с адресами.

Запуск (batch):
  MBKS_IDA_BATCH=1 idat64.exe -A -L<лог> -S<путь>\\lab1\\ida\\dump_vuln.py <путь>\\lab1\\ida\\vuln2.exe
"""

from __future__ import print_function

import os

import idaapi
import idautils
import idc

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None

try:
    import ida_nalt
except ImportError:
    ida_nalt = None

# Строки-маркеры, по которым находим уязвимую функцию
PATTERNS = [b"buffer: ", b"read config", b"Variant: ", b"/start"]
UNSAFE = {"memcpy", "memmove", "strcpy", "strncpy", "sprintf", "strcat", "strncat"}


def _log(line, sink):
    text = line if line.endswith("\n") else line + "\n"
    idaapi.msg(text)
    sink.append(line.rstrip("\n"))


def _script_dir():
    here = globals().get("__file__")
    if here:
        return os.path.dirname(os.path.abspath(here))
    return os.path.dirname(idaapi.get_input_file_path() or "")


def _iter_strings():
    """(адрес, значение) всех строк; перебор без опоры на окно Strings."""
    for item in idautils.Strings():
        try:
            yield int(item.ea), str(item)
        except Exception:
            continue


def _find_pattern_strings():
    hits = []
    for ea, value in _iter_strings():
        raw = value.encode("utf-8", "replace")
        for pattern in PATTERNS:
            if pattern in raw or pattern.decode() in value:
                hits.append((ea, value))
                break
    return hits


def _code_xrefs_to(ea):
    addrs = []
    for xref in idautils.XrefsTo(ea, 0):
        mnem = (idc.print_insn_mnem(xref.frm) or "").lower()
        if mnem in ("call", "jmp", "ljmp", "lcall", "jmpq"):
            addrs.append(xref.frm)
        elif getattr(xref, "iscode", False):
            addrs.append(xref.frm)
        else:
            addrs.append(xref.frm)      # ссылка на строку из кода
    return sorted(set(addrs))


def _data_string_xrefs(ea):
    """Адреса команд, ссылающихся на строку (push offset aBuffer)."""
    addrs = []
    for xref in idautils.DataRefsTo(ea):
        addrs.append(xref)
    if not addrs:
        addrs = _code_xrefs_to(ea)
    return sorted(set(addrs))


def _dump_function(func, lines):
    _log("", lines)
    _log("=== функция %s (0x%08X .. 0x%08X) ===" % (
        idc.get_func_name(func.start_ea) or "?", func.start_ea, func.end_ea), lines)
    unsafe_calls = []
    ea = func.start_ea
    while ea < func.end_ea and ea != idaapi.BADADDR:
        mnem = (idc.print_insn_mnem(ea) or "").lower()
        disasm = idc.generate_disasm_line(ea, 0) or ""
        comment = ""
        if mnem in ("call", "jmp"):
            target = idc.get_operand_value(ea, 0)
            name = idc.get_func_name(target) or idc.get_name(target) or ""
            short = name.split("_")[-1] if name else ""
            if short in UNSAFE or name in UNSAFE:
                unsafe_calls.append((ea, name))
                comment = "   ; <== небезопасный вызов %s" % name
        _log("0x%08X  %-42s%s" % (ea, disasm.strip(), comment), lines)
        ea = idc.next_head(ea, func.end_ea)
    _log("", lines)
    _log("небезопасные вызовы в функции: %d" % len(unsafe_calls), lines)
    for call_ea, name in unsafe_calls:
        _log("  call 0x%08X -> %s" % (call_ea, name), lines)
    return unsafe_calls


def _decompile(func, lines):
    if ida_hexrays is None:
        _log("декомпилятор Hex-Rays недоступен", lines)
        return
    try:
        if not ida_hexrays.init_hexrays_plugin():
            _log("Hex-Rays не инициализирован", lines)
            return
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc is None:
            _log("декомпиляция не удалась", lines)
            return
        _log("", lines)
        _log("=== псевдокод C (Hex-Rays) ===", lines)
        for line in str(cfunc).splitlines():
            _log(line, lines)
    except Exception as exc:                      # noqa: BLE001 — важно не падать в batch
        _log("ошибка декомпиляции: %s" % exc, lines)


def _callees(func, lines, depth=2, seen=None):
    """Выгружает функции, которые вызывает найденная функция (на depth уровней).

    Нужно, чтобы в дамп попала реализация копирования (например, внутренняя
    функция snprintf), а не только сама уязвимая функция.
    """
    seen = seen if seen is not None else set()
    if depth <= 0:
        return
    targets = []
    ea = func.start_ea
    while ea < func.end_ea and ea != idaapi.BADADDR:
        if (idc.print_insn_mnem(ea) or "").lower() in ("call", "jmp"):
            target = idc.get_operand_value(ea, 0)
            callee = idaapi.get_func(target)
            if callee is not None and callee.start_ea not in seen \
                    and callee.start_ea != func.start_ea:
                targets.append(callee)
        ea = idc.next_head(ea, func.end_ea)
    for callee in targets:
        if callee.start_ea in seen:
            continue
        seen.add(callee.start_ea)
        _dump_function(callee, lines)
        _callees(callee, lines, depth - 1, seen)


def main():
    idaapi.auto_wait()
    lines = []
    _log("файл: %s" % (ida_nalt.get_input_file_path() if ida_nalt else "?"), lines)

    strings = _find_pattern_strings()
    _log("найдено строк-маркеров: %d" % len(strings), lines)
    for ea, value in strings:
        _log("  %#x  %r" % (ea, value[:40]), lines)

    functions = []
    for ea, _value in strings:
        for ref in _data_string_xrefs(ea):
            func = idaapi.get_func(ref)
            if func is not None and func.start_ea not in [f.start_ea for f in functions]:
                functions.append(func)

    _log("", lines)
    _log("функций-кандидатов: %d" % len(functions), lines)
    seen = set()
    best = None
    for func in functions:
        if func.start_ea in seen:
            continue
        seen.add(func.start_ea)
        calls = _dump_function(func, lines)
        if calls and best is None:
            best = func
    if best is not None:
        _decompile(best, lines)

    # Функции, вызываемые из найденных: именно там оказывается реализация
    # копирования (внутренняя snprintf), которая импортом не является.
    _log("", lines)
    _log("=== функции, вызываемые из найденных (реализация копирования) ===", lines)
    for func in functions:
        _callees(func, lines, depth=2, seen=seen)

    out_path = os.path.join(_script_dir(), "vuln_disasm.txt")
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        _log("written: %s" % out_path, lines)
    except OSError as exc:
        _log("не удалось записать %s: %s" % (out_path, exc), lines)

    if os.environ.get("MBKS_IDA_BATCH") == "1":
        idc.qexit(0)


main()
```
