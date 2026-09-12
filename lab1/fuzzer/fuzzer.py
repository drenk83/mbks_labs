#!/usr/bin/env python3
"""Слепой мутационный фаззер config_2 / vuln2.exe (лаба 1, вариант 2).

Режимы:
  auto --seq   детерминированные проходы: замена байт граничными значениями,
               удлинение файла, граничные значения в полях на удлинённом файле;
  auto --cov   очередь сидов по покрытию (DynamoRIO drcov) + адаптация стратегий
               (доп. задание: смена алгоритма мутаций по результатам покрытия);
  mutate <s>   одна мутация выбранного типа и запуск;
  run          один запуск текущего work/config_2.

Формат конфига в код не зашит: ни /start, ни имена полей, ни их смещения.
"""

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
from mutations import (
    BOUNDARY_VALUES,
    WORD_DWORD_VALUES,
    mutate,
    seq_pass_a,
    seq_pass_b,
    seq_pass_c,
    seq_pass_d,
)
from runner import RunResult, run_drcov, write_config

# Проходы режима --seq: A — граничные значения на месте, B — удлинение,
# C — граничные значения в полях на удлинённом файле, D — обрезка.
SEQ_PASSES = {
    "A": "граничные значения на месте (все смещения)",
    "B": "удлинение файла блоками",
    "C": "граничные значения в 4-байтных полях на удлинённом файле",
    "D": "обрезка файла",
}


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


def describe_replacements(orig: bytes, mutant: bytes, note: str = "") -> str:
    """Список замен относительно оригинала — для краш-лога по ТЗ."""
    lines = []
    if note:
        lines.append(f"note: {note}")
    lines.append(f"orig_size: {len(orig)}")
    lines.append(f"mutant_size: {len(mutant)}")
    n = min(len(orig), len(mutant))
    changed: list[str] = []
    for i in range(n):
        if orig[i] != mutant[i]:
            changed.append(f"  +{i:04X}  {orig[i]:02X} -> {mutant[i]:02X}")
    lines.append(f"changed_bytes: {len(changed)}")
    if len(mutant) > len(orig):
        tail = mutant[len(orig) :]
        preview = tail[:32].hex()
        extra = "..." if len(tail) > 32 else ""
        lines.append(f"appended: {len(tail)} bytes  {preview}{extra}")
    if len(mutant) < len(orig):
        lines.append(f"truncated: {len(orig) - len(mutant)} bytes")
    lines.append("replacements:")
    lines.extend(changed[:120])
    if len(changed) > 120:
        lines.append(f"  ... and {len(changed) - 120} more")
    return "\n".join(lines) + "\n"


class RunLog:
    """Журнал прогонов: ТЗ требует логировать ошибки вместе с произведёнными заменами."""

    HEADER = ("run\tpass\toffset\tpatch\tstatus\texit\texception\tsize\tbb_run\t"
              "bb_parent\tbb_global\tstrategy\tsignal\n")

    def __init__(self, path: Path, enabled: bool = True):
        self.path = Path(path)
        self.enabled = enabled
        if self.enabled:
            self.path.write_text(self.HEADER, encoding="utf-8")

    def write(self, **kw) -> None:
        if not self.enabled:
            return
        fields = [
            kw.get("run", ""),
            kw.get("pass_name", ""),
            kw.get("offset", ""),
            kw.get("patch", ""),
            kw.get("status", ""),
            kw.get("exit_code", ""),
            kw.get("exception", ""),
            kw.get("size", ""),
            kw.get("bb_run", ""),
            kw.get("bb_parent", ""),
            kw.get("bb_global", ""),
            kw.get("strategy", ""),
            kw.get("signal", ""),
        ]
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write("\t".join(str(f) for f in fields) + "\n")


def save_crash(cfg: dict, data: bytes, result: RunResult, orig: bytes | None = None,
               note: str = "") -> Path:
    """Пара bin+txt в lab1/crashes/: вход, замены, код исключения, регистры, стек."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    crashes = cfg["crashes_dir"]
    bin_path = crashes / f"crash_{stamp}.bin"
    txt_path = crashes / f"crash_{stamp}.txt"
    bin_path.write_bytes(data)
    body = format_crash_log(result)
    if orig is not None:
        body += describe_replacements(orig, data, note)
    elif note:
        body += f"note: {note}\n"
    txt_path.write_text(body, encoding="utf-8")
    print(f"[crash] сохранён {bin_path.name}  exception=0x{(result.exception_code or 0):08X}")
    if result.regs:
        print(
            f"        EAX={result.regs['EAX']:08X} EIP={result.regs['EIP']:08X} "
            f"ESP={result.regs['ESP']:08X} EBP={result.regs['EBP']:08X}"
        )
    return bin_path


def save_corpus(cfg: dict, data: bytes, run_id: int, new_bb: int) -> Path:
    """Сиды, давшие новое покрытие — «сохранение изменённых байт» из ТЗ."""
    folder = Path(__file__).resolve().parent / "corpus"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"seed_{run_id:05d}_plus{new_bb}bb.bin"
    path.write_bytes(data)
    return path


def write_mutant(cfg: dict, data: bytes) -> None:
    write_config(cfg["work_dir"], data)


def run_debug(cfg: dict, data: bytes) -> RunResult:
    """Записать мутант и запустить цель как debuggee (регистры при падении)."""
    write_mutant(cfg, data)
    return run_under_debugger(cfg["work_dir"], cfg["timeout_sec"])


def run_cov(cfg: dict, data: bytes) -> RunResult:
    """Записать мутант и снять покрытие drcov."""
    write_mutant(cfg, data)
    return run_drcov(cfg["drrun"], cfg["work_dir"], cfg["timeout_sec"])


def replay_crash(cfg: dict, data: bytes) -> RunResult:
    """Повтор упавшего входа под отладчиком после прогона с drcov."""
    return run_debug(cfg, data)


def count_seq_runs(orig: bytes, passes: str) -> int:
    """Сколько прогонов даст выбранный набор проходов (для прогресса)."""
    total = 0
    if "A" in passes:
        total += len(orig) * len(BOUNDARY_VALUES)
    if "B" in passes:
        total += 6
    if "C" in passes:
        total += 4 * (len(orig) // 4) * len(WORD_DWORD_VALUES)
    if "D" in passes:
        total += 4
    return total


def _seq_iter(orig: bytes, passes: str):
    """Итератор прогонов выбранных проходов."""
    if "A" in passes:
        yield from seq_pass_a(orig)
    if "B" in passes:
        yield from seq_pass_b(orig)
    if "C" in passes:
        yield from seq_pass_c(orig)
    if "D" in passes:
        yield from seq_pass_d(orig)


def cmd_seq(cfg: dict, orig: bytes, passes: str, max_runs: int | None) -> int:
    """Детерминированный авторежим: проходы A/B/C/D. 0 = нашли краш."""
    total = count_seq_runs(orig, passes)
    if max_runs:
        total = min(total, max_runs)
    print(f"[seq] проходы {passes}: до {total} прогонов "
          f"(A={len(orig)}×{len(BOUNDARY_VALUES)}, C=4×{len(orig)//4}×{len(WORD_DWORD_VALUES)})")
    log = RunLog(cfg["fuzzer_dir"] / "seq.log", cfg.get("log", True))
    n = 0
    per_pass: dict[str, int] = {}
    for pass_name, offset, patch, mutant in _seq_iter(orig, passes):
        if max_runs and n >= max_runs:
            print(f"[seq] достигнут лимит {max_runs}")
            break
        n += 1
        per_pass[pass_name] = per_pass.get(pass_name, 0) + 1
        if n == 1 or n % 200 == 0:
            print(f"[seq] {n}/{total} проход {pass_name} off={offset} "
                  f"patch={patch.hex()} size={len(mutant)}")
        result = run_debug(cfg, mutant)
        log.write(run=n, pass_name=pass_name, offset=offset, patch=patch.hex(),
                  status=result.status, exit_code=result.exit_code,
                  exception=f"0x{(result.exception_code or 0):08X}", size=len(mutant))
        if result.status == "crash":
            save_crash(cfg, mutant, result, orig,
                       note=f"seq pass={pass_name} offset={offset} patch={patch.hex()}")
            return 0
        if result.status == "timeout":
            print(f"[seq] timeout проход {pass_name} off={offset}")
    print(f"[seq] проходы закончены, краша нет. По проходам: {per_pass}")
    return 1


def cmd_cov(cfg: dict, orig: bytes, max_runs: int | None, deep: bool = False) -> int:
    """Очередь сидов по новым BB и смена стратегии (доп. задание)."""
    limit = max_runs if max_runs is not None else cfg["max_runs"]
    rng = random.Random()
    sched = Scheduler(cfg["adapt_log"], cfg["shrink_streak"], cfg["plateau_runs"], rng)
    log = RunLog(cfg["fuzzer_dir"] / "cov.log", cfg.get("log", True))
    print("[cov] калибровка оригинала под drcov…")
    base = run_cov(cfg, orig)
    if not base.coverage:
        print(f"[cov] покрытие не снято: status={base.status} exit={base.exit_code} "
              f"extra={base.extra}")
        print("[cov] похоже, клиент drcov не зарегистрировался (каталог конфигурации "
              "DynamoRIO недоступен) — это не краш цели")
        return 2
    if base.status == "crash":
        dumped = replay_crash(cfg, orig)
        save_crash(cfg, orig, dumped if dumped.regs else base, orig, note="crash on original")
        return 0

    global_cov: set = set(base.coverage)
    queue: list[tuple[bytes, set]] = [(orig, set(base.coverage))]
    longest = orig
    no_gain = 0
    field_cursor = 0
    print(f"[cov] BB оригинала: {len(global_cov)}  max_runs={limit}  energy={sched.energy}")

    for i in range(1, limit + 1):
        # Родитель выбирается из трёх источников:
        #   1) сиды, давшие новое покрытие (обратная связь по ТЗ);
        #   2) самый длинный вход — переполнение буфера ищется среди длинных данных;
        #   3) исходный конфиг — на нём «перебор полей» реально меняет поведение
        #      (у длинных входов данных хватает и переполнения не возникает).
        roll = rng.random()
        if queue and roll < 0.45:
            parent_data, parent_cov = rng.choice(queue)
        elif len(longest) > len(orig) and roll < 0.75:
            parent_data, parent_cov = longest, set(global_cov)
        else:
            parent_data, parent_cov = orig, set(base.coverage)

        mutant = mutate(parent_data, sched.current, sched.energy, rng, field_cursor)
        field_cursor += 1
        if mutant == parent_data:
            sched.on_run("noop", len(parent_cov), len(parent_cov), len(global_cov))
            log.write(run=i, status="noop", strategy=sched.current, signal="noop",
                      size=len(mutant))
            continue
        if len(mutant) > len(longest):
            longest = mutant

        result = run_cov(cfg, mutant)
        if result.status == "error":
            print(f"[cov] прогон инструментирования не удался: {result.extra}")
            print("[cov] это сбой drrun, а не падение цели — останавливаюсь")
            log.write(run=i, status="error", strategy=sched.current, size=len(mutant))
            return 2
        if result.status == "timeout":
            print(f"[cov] #{i} timeout strategy={sched.current} size={len(mutant)}")
            log.write(run=i, status="timeout", strategy=sched.current, size=len(mutant))
            continue
        if result.status == "crash":
            dumped = replay_crash(cfg, mutant)
            confirmed = dumped.status == "crash"
            save_crash(
                cfg,
                mutant,
                dumped if confirmed else result,
                orig,
                note=(f"cov run={i} strategy={sched.current} size={len(mutant)} "
                      f"confirmed_under_debugger={confirmed}"),
            )
            log.write(run=i, status="crash", strategy=sched.current, size=len(mutant),
                      exception=f"0x{(result.exception_code or 0):08X}")
            return 0

        run_cov_set = result.coverage or set()
        bb_run = len(run_cov_set)
        bb_parent = len(parent_cov)
        new = run_cov_set - global_cov
        if new:
            global_cov |= new
            queue.append((mutant, run_cov_set))
            save_corpus(cfg, mutant, i, len(new))
            signal = "gain"
            no_gain = 0
            print(f"[cov] #{i} GAIN +{len(new)} BB  total={len(global_cov)}  "
                  f"strategy={sched.current} size={len(mutant)} seeds={len(queue)}")
        elif bb_run < bb_parent:
            signal = "shrink"
            if i % 25 == 0:
                print(f"[cov] #{i} shrink {bb_run}<{bb_parent} strategy={sched.current}")
        else:
            signal = "plateau"
            no_gain += 1
            if i % 50 == 0:
                print(f"[cov] #{i} plateau total={len(global_cov)} strategy={sched.current} "
                      f"energy={sched.energy} longest={len(longest)} seeds={len(queue)}")
        sched.on_run(signal, bb_run, bb_parent, len(global_cov))
        log.write(run=i, status=result.status, size=len(mutant), bb_run=bb_run,
                  bb_parent=bb_parent, bb_global=len(global_cov),
                  strategy=sched.current, signal=signal)
        if (deep and sched.all_tried() and sched.switches >= len(STRATEGIES)
                and no_gain >= 3 * sched.plateau_limit):
            print(f"[cov] все стратегии испробованы, роста покрытия нет ({no_gain} прогонов)")
            break

    print(f"[cov] лимит {limit}, краша нет, BB={len(global_cov)}, сидов={len(queue)}, "
          f"самый длинный вход={len(longest)}")
    print(f"[cov] лог адаптации: {cfg['adapt_log']}  лог прогонов: {log.path}")
    return 1


def cmd_manual(cfg: dict, orig: bytes, strategy: str) -> int:
    """Одна мутация указанного типа по оригиналу и запуск под отладчиком."""
    rng = random.Random()
    mutant = mutate(orig, strategy, energy=3, rng=rng)
    print(f"[manual] strategy={strategy} size {len(orig)} -> {len(mutant)}")
    result = run_debug(cfg, mutant)
    print(f"[manual] status={result.status} exit={result.exit_code}")
    if result.status == "crash":
        save_crash(cfg, mutant, result, orig, note=f"manual strategy={strategy}")
        return 0
    write_mutant(cfg, orig)
    return 0 if result.status == "ok" else 1


def cmd_once(cfg: dict, orig: bytes) -> int:
    """Пункт 7: прогнать уже лежащий work/config_2, при краше напечатать регистры."""
    data = (cfg["work_dir"] / "config_2").read_bytes()
    print(f"[run] size={len(data)} (work/config_2)")
    result = run_debug(cfg, data)
    print(f"[run] status={result.status} exit={result.exit_code}")
    if result.status == "crash":
        save_crash(cfg, data, result, orig, note="run work/config_2")
        print(format_crash_log(result))
        return 0
    print("падение не зафиксировано")
    write_mutant(cfg, orig)
    return 0


def menu(cfg: dict, orig: bytes) -> int:
    """Интерактивное меню, если запустили без аргументов."""
    actions = {
        "1": lambda: cmd_seq(cfg, orig, "ABCD", None),
        "2": lambda: cmd_cov(cfg, orig, None),
        "3": lambda: cmd_manual(cfg, orig, "byte"),
        "3a": lambda: cmd_manual(cfg, orig, "multi"),
        "4": lambda: cmd_manual(cfg, orig, "append"),
        "5": lambda: cmd_manual(cfg, orig, "expand"),
        "6": lambda: cmd_manual(cfg, orig, "delim"),
        "7": lambda: cmd_once(cfg, orig),
    }
    print("1  авто: детерминированные проходы (граничные значения + удлинение)")
    print("2  авто: покрытие + адаптация стратегий")
    print("3  замена 1 байта     3a  нескольких байт")
    print("4  допись             5   вставка (удлинение)")
    print("6  разделители ,:=;   7   один запуск work/config_2")
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
    p = argparse.ArgumentParser(description="Фаззер vuln2.exe / config_2 (вариант 2)")
    sub = p.add_subparsers(dest="cmd")
    auto = sub.add_parser("auto")
    g = auto.add_mutually_exclusive_group(required=True)
    g.add_argument("--seq", action="store_true",
                   help="детерминированные проходы (граничные значения + удлинение)")
    g.add_argument("--cov", action="store_true",
                   help="очередь по покрытию drcov + адаптация стратегий")
    auto.add_argument("--max-runs", type=int, default=None)
    auto.add_argument("--passes", default="ABC",
                      help="проходы для --seq: A (граничные значения на месте), "
                           "B (удлинение), C (граничные значения в полях на длинном файле), "
                           "D (обрезка)")
    auto.add_argument("--deep", action="store_true",
                      help="для --cov: остановиться, когда все стратегии испробованы")
    auto.add_argument("--no-log", action="store_true", help="не писать seq.log/cov.log")
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
        cfg["log"] = not getattr(args, "no_log", False)
        if args.cmd == "auto" and args.seq:
            return cmd_seq(cfg, orig, args.passes.upper(), args.max_runs)
        if args.cmd == "auto" and args.cov:
            return cmd_cov(cfg, orig, args.max_runs, args.deep)
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
