"""IDAPython 3 / IDA 7.7: вызовы функций ввода и небезопасных копирований.

Запуск: ida.exe → lab1/work/vuln2.exe → File → Script file.
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
