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
