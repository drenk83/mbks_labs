"""Пути к цели и DynamoRIO. Локальный config.json в git не кладётся."""

import json
from pathlib import Path


HERE = Path(__file__).resolve().parent


def load_config():
    """Читает config.json (если нет — копирует example) и резолвит относительные пути."""
    example = HERE / "config.json.example"
    path = HERE / "config.json"
    if not path.exists():
        path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    raw = json.loads(path.read_text(encoding="utf-8"))

    def resolve(key):
        p = Path(raw[key])
        if not p.is_absolute():
            p = (HERE / p).resolve()
        return p

    cfg = {
        "drrun": Path(raw["drrun"]),
        "fuzzer_dir": HERE,
        "work_dir": resolve("work_dir"),
        "orig_exe": resolve("orig_exe"),
        "orig_dll": resolve("orig_dll"),
        "orig_config": resolve("orig_config"),
        "crashes_dir": resolve("crashes_dir"),
        "timeout_sec": float(raw.get("timeout_sec", 5)),
        "max_runs": int(raw.get("max_runs", 2000)),
        "plateau_runs": int(raw.get("plateau_runs", 20)),
        "shrink_streak": int(raw.get("shrink_streak", 3)),
        "adapt_log": HERE / "adapt.log",
    }
    return cfg
