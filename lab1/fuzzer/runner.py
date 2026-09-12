"""Запуск vuln2.exe: напрямую, под drrun -t drcov, с таймаутом и без окна WER."""

import ctypes
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from coverage import find_and_parse, unlink_drcov_logs

CREATE_NO_WINDOW = 0x08000000
SEM_FAILCRITICALERRORS = 0x0001
SEM_NOGPFAULTERRORBOX = 0x0002
SEM_NOOPENFILEERRORBOX = 0x8000

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.SetErrorMode.argtypes = [ctypes.c_uint]
_kernel32.SetErrorMode.restype = ctypes.c_uint


def _silence_wer() -> None:
    """Глушит диалог Windows Error Reporting у текущего процесса (наследуется детьми)."""
    _kernel32.SetErrorMode(
        SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
    )


def _kill_tree(pid: int) -> None:
    """taskkill /T: drrun при timeout иначе оставляет живой vuln2.exe."""
    if not pid:
        return
    subprocess.run(
        ["taskkill", "/F", "/T", "/PID", str(pid)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=CREATE_NO_WINDOW,
    )


@dataclass
class RunResult:
    """Итог одного запуска цели: ok / crash / timeout плюс покрытие и регистры."""
    status: str
    exit_code: int | None = None
    exception_code: int | None = None
    regs: dict | None = None
    stack: bytes | None = None
    coverage: set | None = None
    elapsed: float = 0.0
    extra: str = ""
    logs: list = field(default_factory=list)


def _is_exception_exit(code: int | None) -> bool:
    """True только для NTSTATUS 0xCxxxxxxx (AV и т.п.). exit(-1)=0xFFFFFFFF — не краш."""
    if code is None:
        return False
    return (code & 0xF0000000) == 0xC0000000


def write_config(work_dir: Path, data: bytes) -> None:
    """Пишет мутант строго как config_2 — exe путь в argv не принимает."""
    (work_dir / "config_2").write_bytes(data)


def _popen_wait(cmd: list, cwd: Path, timeout_sec: float, capture_stderr: bool = False,
                env: dict | None = None) -> RunResult:
    """Popen + communicate; по истечении timeout убивает всё дерево PID."""
    t0 = time.perf_counter()
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
        creationflags=CREATE_NO_WINDOW,
        env=env,
    )
    try:
        _out, err = proc.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        _kill_tree(proc.pid)
        try:
            proc.communicate(timeout=2)
        except Exception:
            pass
        return RunResult("timeout", elapsed=time.perf_counter() - t0)
    elapsed = time.perf_counter() - t0
    extra = (err or b"")[:400].decode("latin-1", "replace") if capture_stderr else ""
    if _is_exception_exit(proc.returncode):
        return RunResult(
            "crash",
            exit_code=proc.returncode,
            exception_code=proc.returncode & 0xFFFFFFFF,
            elapsed=elapsed,
            extra=extra,
        )
    return RunResult("ok", exit_code=proc.returncode, elapsed=elapsed, extra=extra)


def run_plain(work_dir: Path, timeout_sec: float) -> RunResult:
    """Запуск vuln2.exe без DBI и без отладчика."""
    _silence_wer()
    return _popen_wait([str(work_dir / "vuln2.exe")], work_dir, timeout_sec)


def _drrun_env(work_dir: Path) -> dict:
    """Окружение для drrun: свой каталог конфигурации DynamoRIO в work/.

    Без него DynamoRIO пишет конфиг в %TEMP%; если тот недоступен, регистрация
    клиента падает, и drrun возвращает ошибку, которую легко принять за краш цели.
    """
    env = dict(os.environ)
    cfg_dir = work_dir / "dynamorio_config"
    try:
        cfg_dir.mkdir(parents=True, exist_ok=True)
        env["DYNAMORIO_CONFIGDIR"] = str(cfg_dir)
    except OSError:
        pass
    return env


def run_drcov(drrun: Path, work_dir: Path, timeout_sec: float) -> RunResult:
    """drrun -t drcov -- vuln2.exe, разбор лога, лог удаляется."""
    _silence_wer()
    exe = work_dir / "vuln2.exe"
    unlink_drcov_logs(work_dir)
    cmd = [str(drrun), "-t", "drcov", "-logdir", str(work_dir), "--", str(exe)]
    result = _popen_wait(cmd, work_dir, timeout_sec, capture_stderr=True,
                         env=_drrun_env(work_dir))
    if result.status == "timeout":
        unlink_drcov_logs(work_dir)
        return result
    cov, logs = find_and_parse(work_dir)
    unlink_drcov_logs(work_dir)
    result.coverage = cov if cov is not None else set()
    result.logs = logs
    if result.status == "crash" and not logs:
        # drrun сам вернул код исключения (например, клиент не зарегистрировался):
        # это сбой инструментирования, а не падение цели — помечаем как ошибку прогона
        result.status = "error"
        result.extra = (result.extra or "") + " drrun failed without coverage log"
    return result
