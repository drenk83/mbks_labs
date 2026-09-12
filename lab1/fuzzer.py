#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Лабораторная работа №1 (МБКС, вариант 2) — мутационный фаззер формата файла.

Один файл. Что внутри:
  * мутации из ТЗ: замена 1 байта, замена нескольких байт, граничные значения,
    допись в конец, расширение/вставка внутрь, работа с разделителями ",:=;";
  * авторежим последовательной замены байт (SEQ-1) и проход по удлинённому файлу (SEQ-2);
  * измерение покрытия средством динамической бинарной инструментации DynamoRIO (drcov);
  * режим с обратной связью по покрытию: входы, давшие новые базовые блоки,
    сохраняются и становятся родителями для дальнейших мутаций (COV);
  * доп. задание: смена алгоритма мутирования по результатам покрытия (adapt);
  * обнаружение ошибки, код ошибки, регистры и стек на момент падения;
  * логирование ошибок вместе с произведёнными заменами.

Запуск:  py -3.12 lab1/fuzzer.py          (откроется меню)
          py -3.12 lab1/fuzzer.py --cov --max-runs 300   (без меню)
"""

from __future__ import annotations

import argparse
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

# ---------------------------------------------------------------------------
# Пути и константы
# ---------------------------------------------------------------------------

LAB1 = Path(__file__).resolve().parent
VULNS = LAB1 / "vulns"          # исходные цели — только чтение
WORK = LAB1 / "work"            # рабочие копии + текущий config_2
CRASHES = LAB1 / "crashes"      # найденные краши (.bin + .txt)
CORPUS = LAB1 / "corpus"        # входы, давшие новое покрытие
LOGS = LAB1 / "logs"            # журналы прогонов

TARGET_NAME = "vuln2.exe"
DLL_NAME = "func.dll"
CONFIG_NAME = "config_2"
ORIG_CONFIG = VULNS / CONFIG_NAME

DRRUN = Path(r"C:\Tools\DynamoRIO\bin32\drrun.exe")
COVERED_MODULES = {TARGET_NAME.lower(), DLL_NAME.lower()}

MARKER = b"/start"              # маркер начала полезных данных в конфиге
HEADER_LEN = 48                 # размер шапки конфига
VARIANT_OFFSET = 0              # байт номера варианта — НЕ мутируется
TIMEOUT_NATIVE = 10.0           # сек
TIMEOUT_DRCOV = 30.0            # сек

# Граничные значения из ТЗ: (ширина в байтах, значение)
BOUNDARY_SPEC = [
    (1, 0x00), (1, 0x01), (1, 0x7F), (1, 0x80), (1, 0xFF),
    (2, 0x0000), (2, 0x7FFF), (2, 0x8000), (2, 0x8001), (2, 0xFFFE), (2, 0xFFFF),
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

SEQ_LOG = LOGS / "seq.log"
COV_LOG = LOGS / "cov.log"
ADAPT_LOG = LOGS / "adapt.log"

MAX_CRASH_SAVES = 20            # предохранитель: сколько крашей сохранять за сессию
_SAVED_SIGNATURES: set[tuple] = set()   # подписи уже сохранённых крашей


# ---------------------------------------------------------------------------
# Мелкие утилиты
# ---------------------------------------------------------------------------

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def append_log(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text + "\n")


def is_crash(code: int | None) -> bool:
    """Крах — это исключение Windows 0xC000xxxx.

    Штатный выход цели с кодом -1 (несовпадение варианта) даёт 0xFFFFFFFF
    и крахом НЕ считается.
    """
    if code is None:
        return False
    unsigned = code & 0xFFFFFFFF
    if unsigned == 0xC000013A:      # Ctrl+C — не краш
        return False
    return 0xC0000000 <= unsigned <= 0xCFFFFFFF


def code_str(code: int | None) -> str:
    if code is None:
        return "timeout"
    return "0x%08X" % (code & 0xFFFFFFFF)


def find_data_offset(data: bytes) -> int:
    """Позиция сразу за маркером /start (оттуда цель копирует данные)."""
    pos = data.find(MARKER)
    return pos + len(MARKER) if pos >= 0 else HEADER_LEN


def header_field_offsets(data: bytes, width: int = 4) -> list[int]:
    """Смещения выровненных полей в шапке (4, 8, 12, ... 44)."""
    limit = min(HEADER_LEN, len(data)) - width
    return [off for off in range(width, limit + 1, width)]


def ensure_dirs() -> None:
    for path in (WORK, CRASHES, CORPUS, LOGS):
        path.mkdir(parents=True, exist_ok=True)
    (WORK / "dynamorio_config").mkdir(parents=True, exist_ok=True)


def prepare_work() -> None:
    """Рабочие копии цели рядом с текущим config_2 (цель читает конфиг из cwd)."""
    ensure_dirs()
    # без диалогов Windows Error Reporting при падениях цели
    _k32.SetErrorMode(0x0001 | 0x0002 | 0x8000)
    for name in (TARGET_NAME, DLL_NAME):
        src, dst = VULNS / name, WORK / name
        if not dst.exists() or dst.stat().st_size != src.stat().st_size:
            shutil.copy2(src, dst)
    if not (WORK / CONFIG_NAME).exists():
        shutil.copy2(ORIG_CONFIG, WORK / CONFIG_NAME)


def restore_config() -> None:
    shutil.copy2(ORIG_CONFIG, WORK / CONFIG_NAME)


def write_config(data: bytes) -> None:
    (WORK / CONFIG_NAME).write_bytes(data)


# ---------------------------------------------------------------------------
# Мутации (все пункты ТЗ)
# ---------------------------------------------------------------------------

def mut_byte(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Однобайтовая замена."""
    if len(data) <= 1:
        return data, "noop: файл слишком мал"
    off = rng.randrange(1, len(data))
    val = rng.choice([0x00, 0xFF, 0x7F, 0x80, rng.randrange(256)])
    out = bytearray(data)
    was = out[off]
    out[off] = val
    return bytes(out), "byte: [%#06x] %02X -> %02X" % (off, was, val)


def mut_multi(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Замена нескольких байт."""
    if len(data) <= 1:
        return data, "noop: файл слишком мал"
    count = rng.randint(2, 8)
    out = bytearray(data)
    first = None
    for _ in range(count):
        off = rng.randrange(1, len(data))
        val = rng.choice([0x00, 0xFF, rng.randrange(256)])
        if first is None:
            first = (off, out[off], val)
        out[off] = val
    return bytes(out), "multi: %d байт, напр. [%#06x] %02X -> %02X" % (
        count, first[0], first[1], first[2])


def mut_boundary(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Замена на граничное значение (0x00, 0xFF, 0xFFFF, 0xFFFFFFFF, половины ±1...)."""
    width, value = rng.choice(BOUNDARY_SPEC)
    candidates = [off for off in range(1, len(data) - width + 1)]
    if not candidates:
        return data, "noop: нет места под %d байт" % width
    off = rng.choice(candidates)
    out = bytearray(data)
    was = bytes(out[off:off + width])
    out[off:off + width] = value.to_bytes(width, "little")
    return bytes(out), "boundary: [%#06x] %s -> %0*X (%d б)" % (
        off, was.hex().upper(), width * 2, value, width)


def mut_field(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Граничное значение в 4-байтное поле шапки (там лежат длины)."""
    offsets = header_field_offsets(data, 4)
    if not offsets:
        return data, "noop: шапка короче 8 байт"
    off = rng.choice(offsets)
    value = rng.choice(DWORD_VALUES)
    out = bytearray(data)
    was = bytes(out[off:off + 4])
    out[off:off + 4] = value.to_bytes(4, "little")
    return bytes(out), "field: [%#06x] %s -> %08X" % (off, was.hex().upper(), value)


def mut_append(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Допись в конец файла."""
    size = rng.choice([16, 64, 256, 1024, 5120])
    fill = rng.choice([b"b", b"A", b"z", b"\xff", b"\x00"])
    return data + fill * size, "append: +%d байт %02X" % (size, fill[0])


def mut_expand(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Расширение: вставка внутрь файла (файл становится длиннее)."""
    if len(data) <= 1:
        return data, "noop: файл слишком мал"
    if rng.random() < 0.5:
        off = find_data_offset(data)          # за маркером /start
    else:
        off = rng.randrange(1, len(data))
    size = rng.choice([64, 512, 1024, 5120])
    out = data[:off] + b"b" * size + data[off:]
    return out, "expand: вставка %d байт в [%#06x]" % (size, off)


def mut_delim(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Поиск разделителей полей ",:=;" и мутация вокруг них."""
    positions = [i for i, byte in enumerate(data) if byte in DELIMITERS]
    if not positions:
        return data, "delim: разделители ,:=; не найдены"
    pos = rng.choice(positions)
    choice = rng.random()
    marker = chr(data[pos])
    if choice < 0.4:                      # дублируем разделитель
        out = data[:pos] + data[pos:pos + 1] * rng.randint(2, 64) + data[pos:]
        return out, "delim: [%#06x] '%s' размножен" % (pos, marker)
    if choice < 0.7:                      # меняем соседний байт на граничный
        off = pos + 1 if pos + 1 < len(data) else pos - 1
        out = bytearray(data)
        was = out[off]
        out[off] = rng.choice([0x00, 0xFF])
        return bytes(out), "delim: [%#06x] рядом с '%s' %02X -> %02X" % (
            off, marker, was, out[off])
    out = bytearray(data)                 # вставляем длинное значение после разделителя
    size = rng.choice([512, 1024, 5120])
    out[pos + 1:pos + 1] = b"b" * size
    return bytes(out), "delim: [%#06x] после '%s' вставлено %d байт" % (pos, marker, size)


def mut_inject(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """Ключевая мутация: длинные данные сразу за /start + завышенная длина в шапке."""
    off = find_data_offset(data)
    size = rng.choice([3000, 5120, 8192, 16384])
    out = bytearray(data[:off]) + bytearray(b"b" * size) + bytearray(data[off:])
    fields = [8]                                    # рабочее смещение поля длины
    if rng.random() < 0.5 and 4 + 4 <= len(out):
        fields.append(4)
    for field in fields:
        if field + 4 <= len(out):
            out[field:field + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out), "inject: +%d байт за маркером [%#06x], поля %s = FFFFFFFF" % (
        size, off, "/".join(str(f) for f in fields))


MANUAL_MUTATIONS = {
    "byte": mut_byte,
    "multi": mut_multi,
    "boundary": mut_boundary,
    "field": mut_field,
    "append": mut_append,
    "expand": mut_expand,
    "delim": mut_delim,
    "inject": mut_inject,
}


# ---------------------------------------------------------------------------
# Запуск цели
# ---------------------------------------------------------------------------

def run_native(capture: bool = False) -> tuple[int | None, str, float, bool]:
    """Обычный запуск work/vuln2.exe с рабочим каталогом work."""
    stdout = subprocess.PIPE if capture else subprocess.DEVNULL
    started = time.time()
    try:
        proc = subprocess.run([str(WORK / TARGET_NAME)], cwd=str(WORK),
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
CREATE_NO_WINDOW = 0x08000000
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


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    """32-битный контекст потока WOW64 (размер 716 байт)."""
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


def _grab_context(tid: int) -> WOW64_CONTEXT | None:
    handle = _k32.OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, False, tid)
    if not handle:
        return None
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = WOW64_CONTEXT_ALL
    ok = _k32.Wow64GetThreadContext(handle, ctypes.byref(ctx))
    _k32.CloseHandle(handle)
    return ctx if ok else None


def _read_stack(hprocess, address: int, size: int = 128) -> bytes:
    buf = (ctypes.c_ubyte * size)()          # именно c_ubyte: c_byte даёт знаковые значения
    read = ctypes.c_size_t(0)
    if _k32.ReadProcessMemory(hprocess, ctypes.c_void_p(address), buf, size,
                              ctypes.byref(read)):
        return bytes(buf[:read.value])
    return b""


def debug_capture(timeout: float = 15.0) -> dict:
    """Запускает цель под отладчиком и снимает регистры/стек на исключении."""
    result: dict = {"exception": None, "first_chance": None, "regs": None,
                    "stack": b"", "image_base": None, "exit_code": None,
                    "saved_eip_addr": None, "saved_eip_value": None,
                    "timeout": False, "error": None}
    _k32.SetErrorMode(0x0001 | 0x0002 | 0x8000)   # без диалогов WER
    startup = STARTUPINFOW()
    startup.cb = ctypes.sizeof(STARTUPINFOW)
    info = PROCESS_INFORMATION()
    cmdline = ctypes.create_unicode_buffer('"%s"' % (WORK / TARGET_NAME))
    started = _k32.CreateProcessW(None, cmdline, None, None, False,
                                  DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW,
                                  None, str(WORK), ctypes.byref(startup),
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
        _k32.CloseHandle(info.hThread)
        _k32.CloseHandle(info.hProcess)
    return result


# ---------------------------------------------------------------------------
# Сохранение краша
# ---------------------------------------------------------------------------

def describe_changes(orig: bytes, mutant: bytes, limit: int = 40) -> list[str]:
    lines = []
    shown = 0
    changed = 0
    for i in range(min(len(orig), len(mutant))):
        if orig[i] != mutant[i]:
            changed += 1
            if shown < limit:
                lines.append("  +%04X  %02X -> %02X" % (i, orig[i], mutant[i]))
                shown += 1
    if changed > shown:
        lines.append("  ... и ещё %d изменённых байт" % (changed - shown))
    if len(mutant) > len(orig):
        lines.append("appended: %d байт %s..." % (len(mutant) - len(orig),
                                                  mutant[len(orig):len(orig) + 32].hex()))
    elif len(mutant) < len(orig):
        lines.append("truncated: -%d байт" % (len(orig) - len(mutant)))
    return lines


def save_crash(data: bytes, orig: bytes, note: str, exit_code: int | None,
               elapsed: float, debugger: bool = True,
               signature: tuple | None = None) -> tuple[Path | None, Path | None]:
    """Сохраняет краш-конфиг и лог с кодом ошибки, регистрами, стеком и заменами.

    Одинаковые краши (по signature) сохраняются один раз — иначе режим покрытия
    плодит сотни файлов на одну и ту же ошибку.
    """
    if signature is None:
        signature = (exit_code, len(data))
    if signature in _SAVED_SIGNATURES or len(_SAVED_SIGNATURES) >= MAX_CRASH_SAVES:
        return None, None
    _SAVED_SIGNATURES.add(signature)
    CRASHES.mkdir(parents=True, exist_ok=True)
    stamp = now_stamp()
    bin_path = CRASHES / ("crash_%s.bin" % stamp)
    txt_path = CRASHES / ("crash_%s.txt" % stamp)
    suffix = 1
    while bin_path.exists() or txt_path.exists():
        bin_path = CRASHES / ("crash_%s_%d.bin" % (stamp, suffix))
        txt_path = CRASHES / ("crash_%s_%d.txt" % (stamp, suffix))
        suffix += 1
    bin_path.write_bytes(data)

    lines = ["status: crash",
             "exit_code: %s (%s)" % (exit_code, code_str(exit_code)),
             "exception: %s" % code_str(exit_code),
             "elapsed_sec: %.3f" % elapsed,
             "note: %s" % note,
             "orig_size: %d" % len(orig),
             "mutant_size: %d" % len(data)]
    debugger_note = "не запускался"
    if debugger:
        info = debug_capture()
        if info.get("error"):
            debugger_note = info["error"]
        elif info.get("exception") is not None:
            ctx = info.get("regs")
            debugger_note = "confirmed=True first_chance=%s" % info.get("first_chance")
            lines.append("exception_under_debugger: %s" % code_str(info["exception"]))
            lines.append("image_base: %s" % (("0x%08X" % info["image_base"])
                                             if info.get("image_base") else "?"))
            if ctx is not None:
                lines += [
                    "EAX=0x%08X" % ctx.Eax, "EBX=0x%08X" % ctx.Ebx,
                    "ECX=0x%08X" % ctx.Ecx, "EDX=0x%08X" % ctx.Edx,
                    "ESI=0x%08X" % ctx.Esi, "EDI=0x%08X" % ctx.Edi,
                    "EBP=0x%08X" % ctx.Ebp, "ESP=0x%08X" % ctx.Esp,
                    "EIP=0x%08X" % ctx.Eip, "EFLAGS=0x%08X" % ctx.EFlags,
                ]
                # адрес сохранённого адреса возврата = EBP+4
                lines.append("saved_eip_addr=0x%08X" % (info.get("saved_eip_addr")
                                                        or ctx.Ebp + 4))
                if info.get("saved_eip_value") is not None:
                    lines.append("saved_eip_value=0x%08X" % info["saved_eip_value"])
                stack = info.get("stack") or b""
                if stack:
                    lines.append("stack:")
                    for row in range(0, min(len(stack), 128), 16):
                        chunk = stack[row:row + 16]
                        lines.append("  +%02X  %s" % (row, " ".join("%02X" % b for b in chunk)))
        else:
            debugger_note = "под отладчиком не воспроизвелось (timeout=%s exit=%s)" % (
                info.get("timeout"), code_str(info.get("exit_code")))
    lines.append("extra: %s" % debugger_note)
    lines.append("replacements:")
    lines += describe_changes(orig, data)
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return bin_path, txt_path


# ---------------------------------------------------------------------------
# Покрытие: DynamoRIO drcov
# ---------------------------------------------------------------------------

def parse_drcov(path: Path) -> set[tuple[str, int]]:
    """Разбор лога drcov: множество (имя модуля, смещение BB) для цели и func.dll."""
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


def run_cov(keep_log: bool = False) -> tuple[set[tuple[str, int]], int | None, str, float, Path | None]:
    """Прогон цели под drrun -t drcov: покрытие + код возврата."""
    logdir = WORK / "drcov_logs"
    if logdir.exists():
        shutil.rmtree(logdir, ignore_errors=True)
    logdir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["DYNAMORIO_CONFIGDIR"] = str(WORK / "dynamorio_config")
    cmd = [str(DRRUN), "-t", "drcov", "-logdir", str(logdir), "--", str(WORK / TARGET_NAME)]
    started = time.time()
    code: int | None = None
    out = ""
    try:
        proc = subprocess.run(cmd, cwd=str(WORK), env=env, stdout=subprocess.PIPE,
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

class Scheduler:
    """Смена алгоритма мутирования по результатам покрытия.

    Сигналы:
      * gain    — появились новые базовые блоки (покрытие выросло);
      * shrink  — покрытие прогона меньше покрытия родителя
                  (BB_run < BB_parent) — «покрытие стало меньше»;
      * plateau — PLATEAU_LIMIT прогонов подряд без нового покрытия.
    Реакция: следующая стратегия по кругу STRATEGIES.
    """

    def __init__(self, fixed: str | None = None):
        self.fixed = fixed
        self.index = 0
        self.shrink = 0
        self.since_gain = 0
        self.switches = 0

    @property
    def current(self) -> str:
        return self.fixed or STRATEGIES[self.index]

    def update(self, bb_run: int, bb_parent: int, gain: bool) -> tuple[str, str, str] | None:
        """Возвращает (было, стало, причина) при смене стратегии, иначе None."""
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


def apply_strategy(name: str, data: bytes, rng: random.Random) -> tuple[bytes, str]:
    func = {"byte": mut_byte, "boundary": mut_boundary,
            "append": mut_append, "inject": mut_inject}[name]
    return func(data, rng)


# ---------------------------------------------------------------------------
# Общий обработчик одного прогона
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.runs = 0
        self.crashes = 0
        self.timeouts = 0
        self.started = time.time()

    def rate(self) -> float:
        elapsed = max(1e-6, time.time() - self.started)
        return self.runs / elapsed


def execute(data: bytes, orig: bytes, note: str, stats: Stats,
            log_path: Path | None = None, tag: str = "",
            capture: bool = False) -> tuple[str, int | None, str]:
    """Записать конфиг, запустить цель, обработать результат и записать лог."""
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
        append_log(log_path, "%d\t%s\t%s\t%s\t%s\t%d" % (
            stats.runs, tag, status, code_str(code), note, len(data)))
    if status == "crash":
        bin_path, _txt = save_crash(data, orig, note, code, elapsed,
                                    signature=(code & 0xFFFFFFFF, note))
        if bin_path is not None:
            print("\n[crash] %s  %s  -> %s" % (code_str(code), note, bin_path.name))
        else:
            print("\n[crash] %s  %s  (дубликат — файл не создаётся)" % (code_str(code), note))
    return status, code, out


# ---------------------------------------------------------------------------
# Режимы
# ---------------------------------------------------------------------------

def mode_seq1(max_runs: int | None = None, rng: random.Random | None = None) -> None:
    """Авторежим: последовательная замена байт граничными значениями (ТЗ)."""
    _SAVED_SIGNATURES.clear()
    rng = rng or random.Random(1)
    orig = ORIG_CONFIG.read_bytes()
    total = sum(1 for off in range(1, len(orig))
                for width, _ in BOUNDARY_SPEC if off + width <= len(orig))
    print("[seq-1] последовательная замена: %d смещений, до %d прогонов" % (len(orig) - 1, total))
    stats = Stats()
    for off in range(1, len(orig)):
        for width, value in BOUNDARY_SPEC:
            if off + width > len(orig):
                continue
            if max_runs and stats.runs >= max_runs:
                print("[seq-1] достигнут лимит %d прогонов" % max_runs)
                restore_config()
                return
            data = bytearray(orig)
            data[off:off + width] = value.to_bytes(width, "little")
            note = "seq1: [%#06x] %0*X (%d б)" % (off, width * 2, value, width)
            execute(bytes(data), orig, note, stats, SEQ_LOG, "A")
            if stats.runs % 500 == 0:
                print("  [seq-1] прогонов %d/%d, крашей %d, %.1f зап/с"
                      % (stats.runs, total, stats.crashes, stats.rate()))
    print("[seq-1] готово: прогонов %d, крашей %d" % (stats.runs, stats.crashes))
    restore_config()


def mode_seq2(max_runs: int | None = None, rng: random.Random | None = None) -> None:
    """Удлинённый файл (вставка за /start) × граничные значения в полях шапки."""
    _SAVED_SIGNATURES.clear()
    rng = rng or random.Random(2)
    orig = ORIG_CONFIG.read_bytes()
    data_off = find_data_offset(orig)
    lengths = [5120, 2500]
    print("[seq-2] данные вставляются за маркером /start (offset %d), поля шапки — граничные"
          % data_off)
    stats = Stats()
    for size in lengths:
        base = orig[:data_off] + b"b" * size + orig[data_off:]
        fields = [8, 4] + [off for off in header_field_offsets(base, 4) if off not in (8, 4)]
        for field in fields:
            for value in [0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE,
                          0x0000FFFF, 0x00000000]:
                if max_runs and stats.runs >= max_runs:
                    print("[seq-2] достигнут лимит %d прогонов" % max_runs)
                    restore_config()
                    return
                data = bytearray(base)
                data[field:field + 4] = value.to_bytes(4, "little")
                note = "seq2: вставка %d б за /start, поле [%#06x] = %08X" % (
                    size, field, value)
                execute(bytes(data), orig, note, stats, SEQ_LOG, "B")
                if stats.crashes:
                    print("[seq-2] краш найден на прогоне %d" % stats.runs)
                    restore_config()
                    return
    print("[seq-2] готово: прогонов %d, крашей %d" % (stats.runs, stats.crashes))
    restore_config()


def mode_cov(max_runs: int = 300, fixed: str | None = None,
             rng: random.Random | None = None) -> None:
    """Режим с обратной связью по покрытию + адаптация алгоритма (доп. задание)."""
    _SAVED_SIGNATURES.clear()
    rng = rng or random.Random(7)
    orig = ORIG_CONFIG.read_bytes()
    stats = Stats()

    write_config(orig)
    base_blocks, base_code, _out, base_time, _log = run_cov()
    if not base_blocks:
        print("[cov] покрытие не получено — проверьте DynamoRIO (%s)" % DRRUN)
        restore_config()
        return
    bb_global = set(base_blocks)
    print("[cov] базовое покрытие оригинала: %d BB (%.2f с)" % (len(bb_global), base_time))
    if is_crash(base_code):
        print("[cov] внимание: оригинальный конфиг даёт краш %s" % code_str(base_code))

    parents: list[dict] = [{"name": "orig", "data": orig, "bb": len(base_blocks)}]
    scheduler = Scheduler(fixed=fixed)
    mode = "фиксированная стратегия %s" % fixed if fixed else "адаптация по покрытию"
    print("[cov] режим: %s; лимит %d прогонов" % (mode, max_runs))

    header = "run\tfrom\tto\treason\tbb_run\tbb_parent\tbb_global"
    append_log(ADAPT_LOG, "# %s | режим: %s | BB оригинала: %d" % (
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), mode, len(bb_global)))
    append_log(ADAPT_LOG, header)

    for run in range(1, max_runs + 1):
        parent = rng.choice(parents)
        strategy = scheduler.current
        data, note = apply_strategy(strategy, parent["data"], rng)
        if data == parent["data"]:
            append_log(COV_LOG, "%d\t%s\tnoop\t%s\t%s\t%d" % (
                run, strategy, code_str(None), note, len(data)))
            continue
        write_config(data)
        blocks, code, _out, elapsed, _log = run_cov()
        bb_run = len(blocks)
        gain_blocks = blocks - bb_global
        gain = bool(gain_blocks)
        if gain:
            bb_global |= blocks
            seed_path = CORPUS / ("seed_%04d_%d.bin" % (run, bb_run))
            seed_path.write_bytes(data)
            parents.append({"name": seed_path.name, "data": data, "bb": bb_run})
        status = "crash" if is_crash(code) else "ok"
        if status == "crash":
            stats.crashes += 1
            bin_path, _txt = save_crash(
                data, orig, "cov run=%d strategy=%s %s" % (run, strategy, note),
                code, elapsed, signature=(code & 0xFFFFFFFF, strategy))
            if bin_path is not None:
                print("\n[crash] %s strategy=%s -> %s" % (code_str(code), strategy, bin_path.name))
        append_log(COV_LOG, "%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d" % (
            run, strategy, status, code_str(code), note, bb_run, parent["bb"], len(bb_global)))
        if gain:
            print("  [cov] #%d GAIN +%d BB  всего=%d  стратегия=%s  родитель=%s  seeds=%d"
                  % (run, len(gain_blocks), len(bb_global), strategy,
                     parent["name"], len(parents) - 1))
        switch = scheduler.update(bb_run, parent["bb"], gain)
        if switch:
            prev, new, reason = switch
            append_log(ADAPT_LOG, "%d\t%s\t%s\t%s\t%d\t%d\t%d" % (
                run, prev, new, reason, bb_run, parent["bb"], len(bb_global)))
            print("  [adapt] run %d: %s -> %s (%s) BB %d/%d/%d"
                  % (run, prev, new, reason, bb_run, parent["bb"], len(bb_global)))
        if run % 25 == 0:
            rate = run / max(1e-6, time.time() - stats.started)
            print("  [cov] прогонов %d/%d, покрытие %d BB, сидов %d, смен %d, %.1f зап/с"
                  % (run, max_runs, len(bb_global), len(parents) - 1,
                     scheduler.switches, rate))
    print("[cov] готово: прогонов %d, покрытие %d BB (старт %d), сидов %d, смен стратегии %d, крашей %d"
          % (max_runs, len(bb_global), len(base_blocks), len(parents) - 1,
             scheduler.switches, stats.crashes))
    restore_config()


def mode_manual(kind: str, rng: random.Random | None = None) -> None:
    """Ручной режим: одна мутация указанного типа по текущему work/config_2."""
    rng = rng or random.Random()
    orig = ORIG_CONFIG.read_bytes()
    base = (WORK / CONFIG_NAME).read_bytes() if (WORK / CONFIG_NAME).exists() else orig
    data, note = MANUAL_MUTATIONS[kind](base, rng)
    print("[manual:%s] %s" % (kind, note))
    stats = Stats()
    status, code, out = execute(data, orig, "%s: %s" % (kind, note), stats,
                                SEQ_LOG, kind, capture=True)
    if out:
        print(out.strip())
    print("[manual:%s] статус=%s код=%s" % (kind, status, code_str(code)))


def mode_lookup_delims() -> None:
    """Поиск разделителей полей ,:=; в текущем конфиге (требование ТЗ)."""
    data = (WORK / CONFIG_NAME).read_bytes()
    found = [(i, chr(b)) for i, b in enumerate(data) if b in DELIMITERS]
    print("[delim] файл %d байт, найдено разделителей: %d" % (len(data), len(found)))
    for offset, symbol in found[:50]:
        print("  [%#06x] '%s'" % (offset, symbol))
    if not found:
        print("  в этом конфиге разделителей ,:=; нет — стратегия delim фиксирует 'нет изменений'")


def mode_run_once() -> None:
    """Один запуск текущего work/config_2 с выводом цели и регистрами при падении."""
    prepare_work()
    orig = ORIG_CONFIG.read_bytes()
    data = (WORK / CONFIG_NAME).read_bytes()
    print("[run] %s, %d байт" % (WORK / CONFIG_NAME, len(data)))
    code, out, elapsed, timed_out = run_native(capture=True)
    if out:
        print(out.strip())
    print("[run] код возврата %s, %.3f с%s" % (code_str(code), elapsed,
                                               ", таймаут" if timed_out else ""))
    if is_crash(code):
        stats = Stats()
        execute(data, orig, "run: текущий config_2", stats, None, "run")
    else:
        print("[run] краха нет")


def show_stats() -> None:
    """Статистика: журналы, краши, корпус."""
    def count_lines(path: Path) -> int:
        return sum(1 for _ in path.open(encoding="utf-8")) if path.exists() else 0

    print("--- статистика ---")
    print("seq.log:   %d строк" % count_lines(SEQ_LOG))
    print("cov.log:   %d строк" % count_lines(COV_LOG))
    print("adapt.log: %d строк" % count_lines(ADAPT_LOG))
    crashes = sorted(CRASHES.glob("crash_*.bin"))
    print("крашей:    %d" % len(crashes))
    for path in crashes[-5:]:
        print("   %s  %d байт" % (path.name, path.stat().st_size))
    seeds = sorted(CORPUS.glob("*.bin"))
    print("сидов:     %d" % len(seeds))
    for path in seeds[-5:]:
        print("   %s  %d байт" % (path.name, path.stat().st_size))
    if ADAPT_LOG.exists():
        switches = [line for line in ADAPT_LOG.read_text(encoding="utf-8").splitlines()
                    if line and not line.startswith("#") and not line.startswith("run\t")]
        print("смен стратегии в adapt.log: %d" % len(switches))
        for line in switches[-5:]:
            print("   %s" % line)


# ---------------------------------------------------------------------------
# Меню и командная строка
# ---------------------------------------------------------------------------

MENU = """
================= ФАЗЗЕР lab1 (вариант 2) =================
 1  SEQ-1: последовательная замена байт граничными значениями (ТЗ, авторежим)
 2  SEQ-2: удлинённый файл (вставка за /start) x поля шапки   <- находит краш
 3  COV:   покрытие DynamoRIO + смена стратегий по покрытию   <- доп. задание
 4  COV-контроль: то же, но стратегия зафиксирована (для сравнения)
 5  замена одного байта (вручную)
 6  замена нескольких байт (вручную)
 7  дописать в конец / расширить файл (вручную)
 8  найти разделители ,:=; и мутировать вокруг них
 9  один запуск work/config_2 (вывод цели, регистры и стек при падении)
10  статистика: журналы, краши, корпус
 0  выход
===========================================================
"""


def ask_int(prompt: str, default: int) -> int:
    try:
        raw = input(prompt).strip()
        return int(raw) if raw else default
    except (ValueError, EOFError):
        return default


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
                fixed = {1: "boundary", 2: "byte", 3: "inject", 4: "append"}.get(
                    ask_int("фиксированная стратегия: 1=boundary, 2=byte, 3=inject, 4=append: ", 1),
                    "boundary")
                mode_cov(ask_int("сколько прогонов (по умолчанию 300): ", 300), fixed=fixed)
            elif choice == "5":
                mode_manual("byte", rng)
            elif choice == "6":
                mode_manual("multi", rng)
            elif choice == "7":
                mode_manual("expand", rng)
            elif choice == "8":
                mode_lookup_delims()
                mode_manual("delim", rng)
            elif choice == "9":
                mode_run_once()
            elif choice == "10":
                show_stats()
            elif choice == "0":
                print("выход")
                return
            else:
                print("неизвестный пункт")
        except KeyboardInterrupt:
            print("\n[!] прервано пользователем")
            restore_config()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Фаззер формата файла (lab1, вариант 2)")
    parser.add_argument("--seq1", action="store_true", help="авторежим последовательной замены")
    parser.add_argument("--seq2", action="store_true", help="проход по удлинённому файлу")
    parser.add_argument("--cov", action="store_true", help="режим покрытия с адаптацией")
    parser.add_argument("--cov-fixed", metavar="STRATEGY", help="режим покрытия без адаптации")
    parser.add_argument("--max-runs", type=int, default=None, help="лимит прогонов")
    parser.add_argument("--mutate", choices=sorted(MANUAL_MUTATIONS), help="одна ручная мутация")
    parser.add_argument("--run", action="store_true", help="один запуск текущего config_2")
    parser.add_argument("--stats", action="store_true", help="показать статистику")
    args = parser.parse_args()
    prepare_work()
    rng = random.Random()

    if args.seq1:
        mode_seq1(args.max_runs)
    elif args.seq2:
        mode_seq2(args.max_runs)
    elif args.cov:
        mode_cov(args.max_runs or 300)
    elif args.cov_fixed:
        mode_cov(args.max_runs or 300, fixed=args.cov_fixed)
    elif args.mutate:
        mode_manual(args.mutate, rng)
    elif args.run:
        mode_run_once()
    elif args.stats:
        show_stats()
    else:
        menu_loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
