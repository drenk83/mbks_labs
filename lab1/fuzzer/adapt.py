"""Планировщик стратегий по покрытию (доп. задание lab1)."""

from pathlib import Path

STRATEGIES = ["byte", "multi", "boundary", "append", "expand", "delim"]
SHRINK_FALLBACK = ["append", "expand", "delim", "boundary", "byte", "multi"]


class Scheduler:
    """Одна активная стратегия; смена по shrink (3 подряд) или plateau (N прогонов без новых BB)."""

    def __init__(self, adapt_log: Path, shrink_streak: int, plateau_runs: int):
        self.log_path = adapt_log
        self.shrink_limit = shrink_streak
        self.plateau_limit = plateau_runs
        self.weights = {s: 1.0 for s in STRATEGIES}
        self.current = "byte"
        self.energy = 1
        self.shrink_streak = 0
        self.plateau_streak = 0
        self.last_used = {s: -i for i, s in enumerate(STRATEGIES)}
        self.run_id = 0
        self.tried = set()
        if not self.log_path.exists():
            self.log_path.write_text(
                "run\tfrom\tto\treason\tbb_run\tbb_parent\tbb_global\n",
                encoding="utf-8",
            )

    def _log(self, src: str, dst: str, reason: str, bb_run: int, bb_parent: int, bb_global: int) -> None:
        """Строка в adapt.log и в консоль — это доказательство доп. задания в отчёте."""
        line = f"{self.run_id}\t{src}\t{dst}\t{reason}\t{bb_run}\t{bb_parent}\t{bb_global}\n"
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
        print(f"[adapt] run {self.run_id}: {src} -> {dst} ({reason}) BB {bb_run}/{bb_parent}/{bb_global}")

    def _pick_fallback(self) -> str:
        """Порядок отката при shrink: сначала допись/удлинение, не порча байт на месте."""
        for s in SHRINK_FALLBACK:
            if s != self.current:
                return s
        return self.current

    def _pick_lru(self) -> str:
        """На plateau — стратегия, которой давно не пользовались."""
        return min(STRATEGIES, key=lambda s: (self.last_used[s], -self.weights[s], s))

    def on_run(self, signal: str, bb_run: int, bb_parent: int, bb_global: int) -> str:
        """Учесть результат прогона. signal: gain | shrink | plateau. Возвращает действие."""
        self.run_id += 1
        self.last_used[self.current] = self.run_id
        self.tried.add(self.current)
        src = self.current
        if signal == "gain":
            self.weights[self.current] = min(16.0, self.weights[self.current] * 2.0)
            self.shrink_streak = 0
            self.plateau_streak = 0
            return "gain"
        if signal == "shrink":
            self.weights[self.current] = max(0.25, self.weights[self.current] * 0.5)
            self.shrink_streak += 1
            self.plateau_streak += 1
            if self.shrink_streak >= self.shrink_limit:
                nxt = self._pick_fallback()
                self.shrink_streak = 0
                if nxt != src:
                    self.current = nxt
                    self._log(src, nxt, "shrink", bb_run, bb_parent, bb_global)
                    return "switch-shrink"
            return "shrink"
        # plateau-ish (no new BB, coverage not smaller)
        self.plateau_streak += 1
        self.shrink_streak = 0
        if self.plateau_streak >= self.plateau_limit:
            nxt = self._pick_lru()
            self.plateau_streak = 0
            self.energy = min(5, self.energy + 1)
            if nxt != src:
                self.current = nxt
                self._log(src, nxt, "plateau", bb_run, bb_parent, bb_global)
                return "switch-plateau"
            self._log(src, src, "plateau-energy", bb_run, bb_parent, bb_global)
            return "energy"
        return "plateau"

    def all_tried(self) -> bool:
        """True, когда каждая из шести стратегий уже хотя бы раз была текущей."""
        return set(STRATEGIES) <= self.tried
