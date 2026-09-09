"""Разбор бинарного лога DynamoRIO drcov (версия 3, записи BB по 8 байт)."""

import re
import struct
from pathlib import Path

KEEP_MODS = ("vuln2.exe", "func.dll")
BB_RECORD = struct.Struct("<IHH")  # start, size, mod_id


def unlink_drcov_logs(work_dir: Path) -> None:
    """Удаляет drcov* из work/, чтобы не копить логи между прогонами."""
    for p in work_dir.glob("drcov*"):
        if p.is_file():
            try:
                p.unlink()
            except OSError:
                pass


def _module_name(path: str) -> str:
    """Имя модуля из пути drcov (смешанные слэши Windows/Unix)."""
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def parse_drcov(path: Path) -> set[tuple[str, int]]:
    """Множество (имя_модуля, смещение_BB) только для vuln2.exe и func.dll."""
    raw = path.read_bytes()
    marker = b"BB Table:"
    idx = raw.find(marker)
    if idx < 0:
        return set()
    header = raw[:idx].decode("latin-1", "replace")
    modules: dict[int, str] = {}
    for line in header.splitlines():
        line = line.strip()
        if not line or line[0] not in "0123456789":
            continue
        m = re.match(r"\s*(\d+)\s*,", line)
        if not m:
            continue
        mod_id = int(m.group(1))
        path_part = line.rsplit(",", 1)[-1].strip()
        modules[mod_id] = _module_name(path_part)

    keep_ids = {mid for mid, name in modules.items() if name in KEEP_MODS}

    rest = raw[idx:]
    nl = rest.find(b"\n")
    if nl < 0:
        return set()
    payload = rest[nl + 1 :]
    if payload.startswith(b"\n"):
        payload = payload[1:]

    bbs: set[tuple[str, int]] = set()
    n = len(payload) // BB_RECORD.size
    for i in range(n):
        start, _size, mod_id = BB_RECORD.unpack_from(payload, i * BB_RECORD.size)
        if mod_id in keep_ids:
            bbs.add((modules[mod_id], start))
    return bbs


def find_and_parse(work_dir: Path) -> tuple[set[tuple[str, int]] | None, list[str]]:
    """Берёт самый свежий drcov*.log в каталоге и парсит его."""
    logs = sorted(work_dir.glob("drcov*.log"), key=lambda p: p.stat().st_mtime)
    if not logs:
        return None, []
    latest = logs[-1]
    try:
        cov = parse_drcov(latest)
    except OSError:
        return None, [p.name for p in logs]
    return cov, [p.name for p in logs]
