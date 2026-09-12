#!/usr/bin/env python3
"""Фаззер формата файла config_2 для vuln2.exe (лаба 1, вариант 2).

Один файл, только стандартная библиотека. Формат конфига в код не зашит: мутации
портят байты «как есть». Единственная эвристика (нужна, чтобы находить переполнение) —
длинный вход: данные вставляются сразу после маркера, найденного в файле.

Режимы:
  python fuzzer.py run                один запуск work/config_2
  python fuzzer.py mutate <тип>       одна мутация и запуск
  python fuzzer.py auto --seq         перебор граничных значений + длинный вход
  python fuzzer.py auto --cov         покрытие через DynamoRIO drcov (доп. задание)
"""

from __future__ import annotations

import argparse
import ctypes
import random
import shutil
import struct
import subprocess
import sys
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
VULNS = HERE.parent / "vulns"
WORK = HERE.parent / "work"
CRASHES = HERE.parent / "crashes"
DRRUN = Path(r"C:\Tools\DynamoRIO\bin32\drrun.exe")
TARGET = "vuln2.exe"
CONFIG = "config_2"
ORIG_EXE = VULNS / TARGET
ORIG_DLL = VULNS / "func.dll"
ORIG_CONFIG = VULNS / CONFIG

DELIMS = b",:=;"
MARKER = b"/start"          # маркер начала данных (эвристика, не имя поля)
LONG_FILLER = 5120          # сколько байт дописывать для «длинного» входа
BOUNDARY = [
    (0x00).to_bytes(1, "little"),
    (0xFF).to_bytes(1, "little"),
    (0xFFFF).to_bytes(2, "little"),
    (0xFFFFFF).to_bytes(3, "little"),
    (0xFFFFFFFF).to_bytes(4, "little"),
    (0xFFFF // 2).to_bytes(2, "little"),
    (0xFFFF // 2 + 1).to_bytes(2, "little"),
    (0xFFFF // 2 - 1).to_bytes(2, "little"),
    (0xFFFFFFFF // 2).to_bytes(4, "little"),
    (0xFFFFFFFF // 2 + 1).to_bytes(4, "little"),
    (0xFFFFFFFF // 2 - 1).to_bytes(4, "little"),
    (0x7FFFFFFF).to_bytes(4, "little"),
]
MUTATIONS = ["byte", "multi", "boundary", "append", "expand", "delim", "long"]


# ---------------------------------------------------------------- мутации

def put(data: bytes, off: int, patch: bytes) -> bytes:
    """Записать patch по смещению (что не влезает — отбрасывается)."""
    if off < 0 or off >= len(data) or not patch:
        return data
    n = min(len(patch), len(data) - off)
    b = bytearray(data)
    b[off:off + n] = patch[:n]
    return bytes(b)


def mut_byte(data: bytes, rng: random.Random) -> bytes:
    """Замена одного байта."""
    i = rng.randrange(len(data))
    return put(data, i, bytes([rng.randrange(256)]))


def mut_multi(data: bytes, rng: random.Random, n: int = 4) -> bytes:
    """Замена нескольких байт."""
    b = bytearray(data)
    for i in rng.sample(range(len(b)), min(n, len(b))):
        b[i] = rng.randrange(256)
    return bytes(b)


def mut_boundary(data: bytes, rng: random.Random) -> bytes:
    """Подстановка граничного значения из ТЗ."""
    return put(data, rng.randrange(len(data)), rng.choice(BOUNDARY))


def mut_append(data: bytes, rng: random.Random, n: int = 64) -> bytes:
    """Допись в конец файла."""
    return data + bytes([0x62]) * n


def mut_expand(data: bytes, rng: random.Random, n: int = 64) -> bytes:
    """Вставка внутрь файла (файл становится длиннее)."""
    pos = rng.randrange(len(data) + 1)
    return data[:pos] + bytes([0x62]) * n + data[pos:]


def mut_delim(data: bytes, rng: random.Random) -> bytes:
    """Порча или удлинение поля рядом с разделителем ,:=;"""
    pos = [i for i, ch in enumerate(data) if ch in DELIMS]
    if not pos:
        return data
    i = rng.choice(pos)
    return put(data, i, bytes([rng.randrange(256)]))


def mut_long(data: bytes, rng: random.Random) -> bytes:
    """Длинный вход: данные сразу за маркером + завышенное поле длины.

    Это найденное условие переполнения: копирование идёт от маркера, поэтому
    данные обязаны лежать сразу за ним, а поле длины в шапке должно быть завышено.
    """
    out = data
    at = data.find(MARKER)
    if at < 0:
        at = 0
    at += len(MARKER)
    out = out[:at] + bytes([0x62]) * LONG_FILLER + out[at:]
    off = rng.randrange(0, max(1, len(data) - 4)) & ~3
    return put(out, off, (0xFFFFFFFF).to_bytes(4, "little"))


def mutate(data: bytes, kind: str, rng: random.Random) -> bytes:
    if kind == "byte":
        return mut_byte(data, rng)
    if kind == "multi":
        return mut_multi(data, rng)
    if kind == "boundary":
        return mut_boundary(data, rng)
    if kind == "append":
        return mut_append(data, rng)
    if kind == "expand":
        return mut_expand(data, rng)
    if kind == "delim":
        return mut_delim(data, rng)
    if kind == "long":
        return mut_long(data, rng)
    raise SystemExit(f"неизвестная мутация: {kind}")


# ---------------------------------------------------------------- запуск цели

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_NO_WINDOW = 0x08000000
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_DEBUG_EVENT = 1
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_PROCESS_DEBUG_EVENT = 5
WOW64_BREAKPOINT = 0x4000001F
FATAL = {0xC0000005, 0xC00000FD, 0xC000001D, 0xC0000096, 0xC0000374, 0xC0000409}


class WOW64_CONTEXT(ctypes.Structure):
    """32-битный контекст потока (нужен Wow64GetThreadContext из 64-битного Python)."""
    _fields_ = [
        ("ContextFlags", wintypes.DWORD), ("Dr0", wintypes.DWORD), ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD), ("Dr3", wintypes.DWORD), ("Dr6", wintypes.DWORD),
        ("Dr7", wintypes.DWORD), ("FloatSave", ctypes.c_byte * 112),
        ("SegGs", wintypes.DWORD), ("SegFs", wintypes.DWORD), ("SegEs", wintypes.DWORD),
        ("SegDs", wintypes.DWORD), ("Edi", wintypes.DWORD), ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD), ("Edx", wintypes.DWORD), ("Ecx", wintypes.DWORD),
        ("Eax", wintypes.DWORD), ("Ebp", wintypes.DWORD), ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD), ("EFlags", wintypes.DWORD), ("Esp", wintypes.DWORD),
        ("SegSs", wintypes.DWORD), ("ExtendedRegisters", ctypes.c_byte * 512),
    ]


class RESULT:
    """Результат одного прогона: код возврата, исключение, регистры, стек."""

    def __init__(self) -> None:
        self.exit_code: int | None = None
        self.exception: int = 0
        self.regs: dict = {}
        self.stack: bytes = b""

    @property
    def crashed(self) -> bool:
        code = self.exception or (self.exit_code or 0)
        return (code & 0xF0000000) == 0xC0000000


def _regs(pid: int, tid: int) -> tuple[dict, bytes]:
    h = kernel32.OpenThread(0x0008 | 0x0040, False, tid)
    if not h:
        return {}, b""
    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = 0x00010007  # WOW64_CONTEXT_FULL
        if not kernel32.Wow64GetThreadContext(h, ctypes.byref(ctx)):
            return {}, b""
        regs = {n: getattr(ctx, n) for n in
                ("Eax", "Ebx", "Ecx", "Edx", "Esi", "Edi", "Ebp", "Esp", "Eip", "EFlags")}
        h_proc = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        stack = b""
        if h_proc:
            buf = (ctypes.c_ubyte * 128)()
            got = ctypes.c_size_t(0)
            if kernel32.ReadProcessMemory(h_proc, ctypes.c_void_p(ctx.Esp), buf, 128,
                                          ctypes.byref(got)):
                stack = bytes(buf[:got.value])
            kernel32.CloseHandle(h_proc)
        return regs, stack
    finally:
        kernel32.CloseHandle(h)


def run_debug() -> RESULT:
    """Запуск цели под отладчиком: регистры и стек при исключении."""
    res = RESULT()
    exe = WORK / TARGET
    si = ctypes.c_void_p(ctypes.c_ubyte * 68)  # STARTUPINFO (размер не критичен для 32-бит)
    pi = (ctypes.c_void_p * 4)()
    cmd = ctypes.create_unicode_buffer(f'"{exe}"')
    ok = kernel32.CreateProcessW(str(exe), cmd, None, None, False,
                                 DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW,
                                 None, str(WORK), None, ctypes.byref(pi))
    if not ok:
        res.exit_code = -1
        return res
    h_proc, h_thread, pid = pi[0], pi[1], pi[2]
    try:
        while True:
            ev = (ctypes.c_ubyte * 200)()
            if not kernel32.WaitForDebugEvent(ctypes.byref(ev), 8000):
                res.exit_code = -1
                break
            code = ctypes.c_uint32.from_buffer(ev, 0).value
            ev_pid = ctypes.c_uint32.from_buffer(ev, 4).value
            ev_tid = ctypes.c_uint32.from_buffer(ev, 8).value
            if code == EXCEPTION_DEBUG_EVENT:
                # EXCEPTION_RECORD: код по смещению 12, first chance по 12+80
                exc = ctypes.c_uint32.from_buffer(ev, 12).value
                first = ctypes.c_uint32.from_buffer(ev, 12 + 80).value
                if exc in (0x80000003, WOW64_BREAKPOINT, 0x80000004, 0x4000001E,
                           0x40010006, 0x4001000A):
                    cont = DBG_CONTINUE
                elif (not first) or exc in FATAL:
                    res.exception = exc
                    res.regs, res.stack = _regs(pid, ev_tid)
                    kernel32.TerminateProcess(h_proc, exc)
                    cont = DBG_CONTINUE
                else:
                    cont = DBG_EXCEPTION_NOT_HANDLED
            elif code == EXIT_PROCESS_DEBUG_EVENT:
                res.exit_code = ctypes.c_uint32.from_buffer(ev, 12).value
                kernel32.ContinueDebugEvent(ev_pid, ev_tid, DBG_CONTINUE)
                break
            else:
                cont = DBG_CONTINUE
            kernel32.ContinueDebugEvent(ev_pid, ev_tid, cont)
            if res.exception:
                break
    finally:
        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(h_proc)
    if res.exit_code is None:
        res.exit_code = -1
    return res


def run_plain() -> int:
    """Быстрый запуск без отладчика (для перебора в авторежиме)."""
    p = subprocess.run([str(WORK / TARGET)], cwd=str(WORK),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p.returncode


# ---------------------------------------------------------------- покрытие (DynamoRIO)

def run_drcov() -> set:
    """Прогон под drrun -t drcov; возвращает множество (модуль, адрес базового блока)."""
    for old in WORK.glob("drcov*.log"):
        old.unlink(missing_ok=True)
    env = dict(**__import__("os").environ)
    cfg_dir = WORK / "dynamorio_config"
    cfg_dir.mkdir(exist_ok=True)
    env["DYNAMORIO_CONFIGDIR"] = str(cfg_dir)
    subprocess.run([str(DRRUN), "-t", "drcov", "-logdir", str(WORK), "--", str(WORK / TARGET)],
                   cwd=str(WORK), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    logs = sorted(WORK.glob("drcov*.log"))
    if not logs:
        return set()
    raw = logs[-1].read_bytes()
    for p in logs:
        p.unlink(missing_ok=True)
    idx = raw.find(b"BB Table:")
    if idx < 0:
        return set()
    head = raw[:idx].decode("latin-1", "replace")
    mods = {}
    for line in head.splitlines():
        line = line.strip()
        if line[:1].isdigit() and "," in line:
            mod_id = int(line.split(",", 1)[0])
            mods[mod_id] = line.rsplit(",", 1)[-1].strip().replace("/", "\\").rsplit("\\", 1)[-1].lower()
    keep = {i for i, n in mods.items() if n in (TARGET, "func.dll")}
    payload = raw[raw.find(b"\n", idx) + 1:]
    if payload.startswith(b"\n"):
        payload = payload[1:]
    blocks = set()
    for i in range(len(payload) // 8):
        start, _size, mod_id = struct.unpack_from("<IHH", payload, i * 8)
        if mod_id in keep:
            blocks.add((mods[mod_id], start))
    return blocks


# ---------------------------------------------------------------- сохранение результата

def prepare() -> bytes:
    """Копии цели в work/ и байты оригинального конфига."""
    WORK.mkdir(exist_ok=True)
    CRASHES.mkdir(exist_ok=True)
    shutil.copy2(ORIG_EXE, WORK / TARGET)
    shutil.copy2(ORIG_DLL, WORK / "func.dll")
    orig = ORIG_CONFIG.read_bytes()
    (WORK / CONFIG).write_bytes(orig)
    return orig


def diff_text(orig: bytes, mutant: bytes) -> str:
    """Список произведённых замен — ТЗ требует логировать их вместе с ошибкой."""
    lines = [f"orig_size: {len(orig)}", f"mutant_size: {len(mutant)}"]
    if len(mutant) > len(orig):
        lines.append(f"appended: {len(mutant) - len(orig)} bytes  {mutant[len(orig):len(orig)+32].hex()}")
    if len(mutant) < len(orig):
        lines.append(f"truncated: {len(orig) - len(mutant)} bytes")
    changed = [(i, orig[i], mutant[i]) for i in range(min(len(orig), len(mutant))) if orig[i] != mutant[i]]
    lines.append(f"changed_bytes: {len(changed)}")
    lines += [f"  +{i:04X}  {a:02X} -> {b:02X}" for i, a, b in changed[:200]]
    if len(changed) > 200:
        lines.append(f"  ... и ещё {len(changed) - 200}")
    return "\n".join(lines) + "\n"


def save_crash(data: bytes, res: RESULT, orig: bytes, note: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    bin_path = CRASHES / f"crash_{stamp}.bin"
    txt_path = CRASHES / f"crash_{stamp}.txt"
    bin_path.write_bytes(data)
    body = [f"note: {note}", f"exception: 0x{res.exception:08X}",
            f"exit_code: {res.exit_code} (0x{(res.exit_code or 0) & 0xFFFFFFFF:08X})"]
    for n in ("Eax", "Ebx", "Ecx", "Edx", "Esi", "Edi", "Ebp", "Esp", "Eip", "EFlags"):
        if n in res.regs:
            body.append(f"{n.upper()}=0x{res.regs[n]:08X}")
    if res.stack:
        body.append("stack:")
        for k in range(0, len(res.stack), 16):
            chunk = res.stack[k:k + 16]
            body.append(f"  +{k:02X}  " + " ".join(f"{b:02X}" for b in chunk))
    body.append(diff_text(orig, data))
    txt_path.write_text("\n".join(body) + "\n", encoding="utf-8")
    print(f"[КРАШ] {bin_path.name}  exception=0x{res.exception:08X}  "
          f"EIP=0x{res.regs.get('Eip', 0):08X}  (лог: {txt_path.name})")
    return bin_path


def write_log(name: str, header: str, row: str) -> None:
    path = HERE / name
    if not path.exists():
        path.write_text(header + "\n", encoding="utf-8")
    with path.open("a", encoding="utf-8") as fh:
        fh.write(row + "\n")


# ---------------------------------------------------------------- режимы

def cmd_run(orig: bytes) -> int:
    """Пункт «один запуск»: прогнать текущий work/config_2 и показать регистры."""
    data = (WORK / CONFIG).read_bytes()
    print(f"[run] work/config_2: {len(data)} байт")
    res = run_debug()
    print(f"[run] статус {'КРАШ' if res.crashed else 'ок'}  exit={res.exit_code}")
    if res.crashed:
        save_crash(data, res, orig, "run work/config_2")
        return 0
    return 1


def cmd_mutate(orig: bytes, kind: str) -> int:
    """Одна мутация заданного типа и запуск."""
    rng = random.Random()
    mutant = mutate(orig, kind, rng)
    (WORK / CONFIG).write_bytes(mutant)
    print(f"[mutate] {kind}: {len(orig)} -> {len(mutant)} байт")
    res = run_debug()
    print(f"[mutate] статус {'КРАШ' if res.crashed else 'ок'}  exit={res.exit_code}")
    if res.crashed:
        save_crash(mutant, res, orig, f"mutate {kind}")
        return 0
    (WORK / CONFIG).write_bytes(orig)
    return 1


def cmd_seq(orig: bytes, max_runs: int | None) -> int:
    """Перебор граничных значений по всем смещениям + фаза «длинного входа»."""
    plan1 = [(off, patch) for off in range(len(orig)) for patch in BOUNDARY]
    print(f"[seq] фаза 1: {len(orig)} смещений × {len(BOUNDARY)} значений = {len(plan1)} прогонов")
    n = 0
    for off, patch in plan1:
        n += 1
        if max_runs and n > max_runs:
            print("[seq] достигнут лимит")
            return 1
        mutant = put(orig, off, patch)
        (WORK / CONFIG).write_bytes(mutant)
        if n % 200 == 0:
            print(f"[seq] {n}/{len(plan1)}  смещение={off} значение={patch.hex()}")
        rc = run_plain()
        write_log("seq.log", "run\toffset\tpatch\texit", f"{n}\t{off}\t{patch.hex()}\t{rc}")
        if (rc & 0xF0000000) == 0xC0000000:
            res = run_debug()          # повтор под отладчиком ради регистров
            save_crash(mutant, res, orig, f"seq offset={off} patch={patch.hex()}")
            return 0

    print("[seq] фаза 2: длинный вход (данные за маркером + завышенная длина)")
    at = orig.find(MARKER)
    at = (at + len(MARKER)) if at >= 0 else 0
    long_data = orig[:at] + bytes([0x62]) * LONG_FILLER + orig[at:]
    for off in range(0, len(orig) - 4, 4):
        n += 1
        mutant = put(long_data, off, (0xFFFFFFFF).to_bytes(4, "little"))
        (WORK / CONFIG).write_bytes(mutant)
        if n % 50 == 0:
            print(f"[seq] фаза 2: смещение={off} ({n} прогонов всего)")
        rc = run_plain()
        write_log("seq.log", "run\toffset\tpatch\texit", f"{n}\t{off}\tffffffff\t{rc}")
        if (rc & 0xF0000000) == 0xC0000000:
            res = run_debug()
            save_crash(mutant, res, orig, f"seq long offset={off} patch=ffffffff")
            return 0
    print("[seq] краш не найден")
    return 1


def cmd_cov(orig: bytes, max_runs: int, rng: random.Random) -> int:
    """Покрытие drcov + очередь входов, давших новые базовые блоки (доп. задание)."""
    print("[cov] калибровка оригинала…")
    (WORK / CONFIG).write_bytes(orig)
    base = run_drcov()
    if not base:
        print("[cov] покрытие не снято: проверьте drrun и каталог конфигурации DynamoRIO")
        return 2
    print(f"[cov] базовых блоков: {len(base)}")
    total = set(base)
    queue = [(orig, set(base))]

    strategy = MUTATIONS[0]
    weights = {m: 1.0 for m in MUTATIONS}
    plateau = 0
    energy = 1
    for run in range(1, max_runs + 1):
        parent, parent_blocks = rng.choice(queue)
        mutant = mutate(parent, strategy, rng)
        if mutant == parent:
            continue
        (WORK / CONFIG).write_bytes(mutant)
        blocks = run_drcov()
        new = blocks - total
        bb_run, bb_parent = len(blocks), len(parent_blocks)
        if new:
            total |= new
            queue.append((mutant, blocks))
            weights[strategy] = min(16.0, weights[strategy] * 2)
            plateau = 0
            reason = "gain"
        elif bb_run < bb_parent:
            weights[strategy] = max(0.25, weights[strategy] * 0.5)
            plateau += 1
            reason = "shrink"
        else:
            plateau += 1
            reason = "plateau"
        if plateau >= 20:                    # смена алгоритма по результатам покрытия
            old, strategy = strategy, min(MUTATIONS, key=lambda m: (weights[m], m == strategy))
            plateau = 0
            energy = min(3, energy + 1)
            write_log("adapt.log", "run\tfrom\tto\treason\tbb_run\tbb_parent\tbb_global",
                      f"{run}\t{old}\t{strategy}\t{reason}\t{bb_run}\t{bb_parent}\t{len(total)}")
            print(f"[adapt] прогон {run}: {old} -> {strategy} ({reason}) "
                  f"BB {bb_run}/{bb_parent}/{len(total)}")
        write_log("cov.log", "run\tstrategy\tbb_run\tbb_parent\tbb_global\tsignal\tsize",
                  f"{run}\t{strategy}\t{bb_run}\t{bb_parent}\t{len(total)}\t{reason}\t{len(mutant)}")
        if run % 50 == 0:
            print(f"[cov] {run}/{max_runs}: блоков={len(total)} очередь={len(queue)} "
                  f"стратегия={strategy}")
    print(f"[cov] готово: блоков {len(total)} (было {len(base)}), очередь {len(queue)}")
    return 1


# ---------------------------------------------------------------- точка входа

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Фаззер config_2 / vuln2.exe")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("run")
    mut = sub.add_parser("mutate")
    mut.add_argument("kind", choices=MUTATIONS)
    auto = sub.add_parser("auto")
    group = auto.add_mutually_exclusive_group(required=True)
    group.add_argument("--seq", action="store_true")
    group.add_argument("--cov", action="store_true")
    auto.add_argument("--max-runs", type=int, default=None)
    args = parser.parse_args(argv)

    orig = prepare()
    if args.cmd == "run":
        return cmd_run(orig)
    if args.cmd == "mutate":
        return cmd_mutate(orig, args.kind)
    if args.cmd == "auto" and args.seq:
        return cmd_seq(orig, args.max_runs)
    if args.cmd == "auto" and args.cov:
        return cmd_cov(orig, args.max_runs or 200, random.Random())
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
