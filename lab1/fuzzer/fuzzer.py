#!/usr/bin/env python3
"""Слепой мутационный фаззер config_2 / vuln2.exe (вариант 2)."""

from __future__ import annotations

import argparse
import hashlib
import random
import shutil
import sys
from datetime import datetime
from pathlib import Path

from adapt import STRATEGIES, Scheduler
from config import load_config
from debugger import format_crash_log, run_under_debugger
from mutations import BOUNDARY_VALUES, mutate, seq_plan
from runner import RunResult, run_drcov, write_config


def sha256(path: Path) -> str:
    """Контрольная сумма, чтобы не перезаписать оригинал в vulns/."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare_work(cfg: dict) -> bytes:
    """Копии exe/dll в work/, вернуть байты оригинального config_2."""
    work = cfg["work_dir"]
    work.mkdir(parents=True, exist_ok=True)
    cfg["crashes_dir"].mkdir(parents=True, exist_ok=True)
    shutil.copy2(cfg["orig_exe"], work / "vuln2.exe")
    shutil.copy2(cfg["orig_dll"], work / "func.dll")
    orig = cfg["orig_config"].read_bytes()
    write_config(work, orig)
    return orig


def assert_orig_untouched(cfg: dict, digest: str) -> None:
    """Стоп, если vulns/config_2 изменился за сессию."""
    now = sha256(cfg["orig_config"])
    if now != digest:
        raise SystemExit(f"оригинал vulns/config_2 изменился: {digest} -> {now}")


def save_crash(cfg: dict, data: bytes, result: RunResult) -> Path:
    """Пара bin+txt в lab1/crashes/; существующие файлы не затирает (штамп времени)."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    crashes = cfg["crashes_dir"]
    bin_path = crashes / f"crash_{stamp}.bin"
    txt_path = crashes / f"crash_{stamp}.txt"
    bin_path.write_bytes(data)
    txt_path.write_text(format_crash_log(result), encoding="utf-8")
    print(f"[crash] сохранён {bin_path.name}  exception=0x{(result.exception_code or 0):08X}")
    if result.regs:
        print(
            f"        EAX={result.regs['EAX']:08X} EIP={result.regs['EIP']:08X} "
            f"ESP={result.regs['ESP']:08X} EBP={result.regs['EBP']:08X}"
        )
    return bin_path


def replay_crash(cfg: dict, data: bytes) -> RunResult:
    """Повтор упавшего входа под отладчиком после прогона с drcov."""
    write_config(cfg["work_dir"], data)
    return run_under_debugger(cfg["work_dir"], cfg["timeout_sec"])


def run_debug(cfg: dict, data: bytes) -> RunResult:
    """Записать мутант и запустить цель как debuggee."""
    write_config(cfg["work_dir"], data)
    return run_under_debugger(cfg["work_dir"], cfg["timeout_sec"])


def run_cov(cfg: dict, data: bytes) -> RunResult:
    """Записать мутант и снять покрытие drcov."""
    write_config(cfg["work_dir"], data)
    return run_drcov(cfg["drrun"], cfg["work_dir"], cfg["timeout_sec"])


def cmd_seq(cfg: dict, orig: bytes) -> int:
    """Авторежим ТЗ: каждое смещение × граничные значения. 0 = нашли краш."""
    total = len(orig) * len(BOUNDARY_VALUES)
    print(f"[seq] {len(orig)} смещений × {len(BOUNDARY_VALUES)} значений = {total} прогонов")
    n = 0
    for offset, patch, mutant in seq_plan(orig):
        n += 1
        result = run_debug(cfg, mutant)
        if n == 1 or n % 100 == 0:
            print(f"[seq] {n}/{total} off={offset} patch={patch.hex()} status={result.status}")
        if result.status == "crash":
            save_crash(cfg, mutant, result)
            return 0
        if result.status == "timeout":
            print(f"[seq] timeout off={offset}")
            continue
    print("[seq] проход закончен, краша нет")
    return 1


def cmd_cov(cfg: dict, orig: bytes, max_runs: int | None) -> int:
    """Очередь сидов по новым BB и смена стратегии (доп. задание)."""
    limit = max_runs if max_runs is not None else cfg["max_runs"]
    rng = random.Random()
    sched = Scheduler(cfg["adapt_log"], cfg["shrink_streak"], cfg["plateau_runs"])
    print("[cov] калибровка оригинала под drcov…")
    base = run_cov(cfg, orig)
    if base.status == "crash":
        dumped = replay_crash(cfg, orig)
        save_crash(cfg, orig, dumped if dumped.regs else base)
        return 0
    if base.status != "ok" or not base.coverage:
        print(f"[cov] не удалось снять покрытие оригинала: {base.status} {base.extra}")
        return 2
    global_cov = set(base.coverage)
    queue: list[tuple[bytes, set]] = [(orig, set(base.coverage))]
    print(f"[cov] BB оригинала: {len(global_cov)}  max_runs={limit}")

    for i in range(1, limit + 1):
        parent_data, parent_cov = rng.choice(queue)
        mutant = mutate(parent_data, sched.current, sched.energy, rng)
        if mutant == parent_data:
            sched.on_run("plateau", len(parent_cov), len(parent_cov), len(global_cov))
            continue
        result = run_cov(cfg, mutant)
        if result.status == "timeout":
            print(f"[cov] #{i} timeout strategy={sched.current}")
            continue
        if result.status == "crash":
            dumped = replay_crash(cfg, mutant)
            save_crash(cfg, mutant, dumped if dumped.status == "crash" else result)
            return 0
        run_cov_set = result.coverage or set()
        bb_run = len(run_cov_set)
        bb_parent = len(parent_cov)
        new = run_cov_set - global_cov
        if new:
            global_cov |= new
            queue.append((mutant, run_cov_set))
            signal = "gain"
            print(
                f"[cov] #{i} GAIN +{len(new)} BB  total={len(global_cov)}  "
                f"strategy={sched.current} seeds={len(queue)}"
            )
        elif bb_run < bb_parent:
            signal = "shrink"
            if i % 25 == 0:
                print(f"[cov] #{i} shrink {bb_run}<{bb_parent} strategy={sched.current}")
        else:
            signal = "plateau"
            if i % 50 == 0:
                print(
                    f"[cov] #{i} plateau total={len(global_cov)} "
                    f"strategy={sched.current} energy={sched.energy}"
                )
        action = sched.on_run(signal, bb_run, bb_parent, len(global_cov))
        if action.startswith("switch") and sched.all_tried() and sched.plateau_streak == 0:
            # после обхода всех стратегий и очередного плато — можно остановиться,
            # но только если plateau_limit уже сработал на всех. Не рвём сразу.
            pass
    print(f"[cov] лимит {limit}, краша нет, BB={len(global_cov)}, сидов={len(queue)}")
    print(f"[cov] лог адаптации: {cfg['adapt_log']}")
    return 1


def cmd_manual(cfg: dict, orig: bytes, strategy: str) -> int:
    """Одна мутация указанного типа по оригиналу и запуск под отладчиком."""
    rng = random.Random()
    mutant = mutate(orig, strategy, energy=1, rng=rng)
    print(f"[manual] strategy={strategy} size {len(orig)} -> {len(mutant)}")
    result = run_debug(cfg, mutant)
    print(f"[manual] status={result.status} exit={result.exit_code}")
    if result.status == "crash":
        save_crash(cfg, mutant, result)
        return 0
    write_config(cfg["work_dir"], orig)
    return 0 if result.status == "ok" else 1


def cmd_once(cfg: dict, orig: bytes) -> int:
    """Пункт 7: прогнать уже лежащий work/config_2, при краше напечатать регистры."""
    data = (cfg["work_dir"] / "config_2").read_bytes()
    print(f"[run] size={len(data)} (work/config_2)")
    result = run_debug(cfg, data)
    print(f"[run] status={result.status} exit={result.exit_code}")
    if result.status == "crash":
        save_crash(cfg, data, result)
        print(format_crash_log(result))
        return 0
    print("падение не зафиксировано")
    write_config(cfg["work_dir"], orig)
    return 0


def menu(cfg: dict, orig: bytes) -> int:
    """Интерактивное меню, если запустили без аргументов."""
    actions = {
        "1": lambda: cmd_seq(cfg, orig),
        "2": lambda: cmd_cov(cfg, orig, None),
        "3": lambda: cmd_manual(cfg, orig, "byte"),
        "3a": lambda: cmd_manual(cfg, orig, "multi"),
        "4": lambda: cmd_manual(cfg, orig, "append"),
        "5": lambda: cmd_manual(cfg, orig, "expand"),
        "6": lambda: cmd_manual(cfg, orig, "delim"),
        "7": lambda: cmd_once(cfg, orig),
    }
    print("1  авто: последовательная замена байт")
    print("2  авто: покрытие + адаптация стратегий")
    print("3  замена 1 байта     3a  нескольких байт")
    print("4  допись")
    print("5  расширение / вставка")
    print("6  разделители ,:=;")
    print("7  один запуск work/config_2 (регистры, если упало)")
    print("0  выход")
    choice = input("> ").strip()
    if choice in ("0", ""):
        return 0
    if choice == "3":
        extra = input("1 байт или несколько? [1/n] ").strip().lower()
        if extra in ("n", "несколько", "multi"):
            return cmd_manual(cfg, orig, "multi")
        return cmd_manual(cfg, orig, "byte")
    fn = actions.get(choice)
    if not fn:
        print("нет такого пункта")
        return 1
    return fn()


def parse_args(argv: list[str]) -> argparse.Namespace:
    """CLI: auto --seq|--cov, mutate <strategy>, run."""
    p = argparse.ArgumentParser(description="Фаззер vuln2.exe / config_2")
    sub = p.add_subparsers(dest="cmd")
    auto = sub.add_parser("auto")
    g = auto.add_mutually_exclusive_group(required=True)
    g.add_argument("--seq", action="store_true")
    g.add_argument("--cov", action="store_true")
    auto.add_argument("--max-runs", type=int, default=None)
    sub.add_parser("run")
    mut = sub.add_parser("mutate")
    mut.add_argument("strategy", choices=STRATEGIES)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Точка входа: подготовка work/, команда, проверка что оригинал цел."""
    cfg = load_config()
    orig_digest = sha256(cfg["orig_config"])
    orig = prepare_work(cfg)
    try:
        if not argv:
            return menu(cfg, orig)
        args = parse_args(argv)
        if args.cmd == "auto" and args.seq:
            return cmd_seq(cfg, orig)
        if args.cmd == "auto" and args.cov:
            return cmd_cov(cfg, orig, args.max_runs)
        if args.cmd == "run":
            return cmd_once(cfg, orig)
        if args.cmd == "mutate":
            return cmd_manual(cfg, orig, args.strategy)
        return menu(cfg, orig)
    finally:
        assert_orig_untouched(cfg, orig_digest)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\nостановлено")
        sys.exit(130)
