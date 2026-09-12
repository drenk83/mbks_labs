"""Планировщик стратегий фаззинга по результатам покрытия (доп. задание lab1).

Идея: покрытие измеряется на каждом прогоне и сравнивается с родительским сидом.
Глобальное множество базовых блоков (BB) при фаззинге только растёт, поэтому
«покрытие уменьшилось» трактуется как BB_прогона < BB_родителя — это сигнал
`shrink` (обычно ранний выход из разбора). На него планировщик меняет стратегию
мутаций: стратегии, которые ломают разбор «на месте», уступают место дописи и
удлинению, сохраняющим исходные байты.

Сигналы:
  gain    — появились BB, которых не было в глобальном множестве;
  shrink  — BB_прогона < BB_родителя и новых BB нет;
  plateau — новых BB нет, покрытие не уменьшилось;
  noop    — мутация ничего не изменила (не считается плато).
"""

from __future__ import annotations

import random
from pathlib import Path

# Восемь стратегий: шесть типов мутаций из ТЗ, перебор 4-байтных полей
# граничными значениями и комбинация «удлинить + испортить поле».
STRATEGIES = ["byte", "multi", "boundary", "append", "expand", "delim", "field", "combo"]

# Порядок отката при серии shrink: сначала то, что сохраняет исходные байты.
SHRINK_FALLBACK = ["append", "expand", "combo", "field", "delim", "boundary", "byte", "multi"]

LOG_HEADER = "run\tfrom\tto\treason\tbb_run\tbb_parent\tbb_global\tenergy\tweights\n"


class Scheduler:
    """Одна активная стратегия; смена по shrink-серии, плато или весам."""

    def __init__(self, adapt_log: Path, shrink_streak: int = 3, plateau_runs: int = 20,
                 rng: random.Random | None = None):
        self.log_path = Path(adapt_log)
        self.shrink_limit = shrink_streak
        self.plateau_limit = plateau_runs
        self.rng = rng or random.Random()
        self.weights = {s: 1.0 for s in STRATEGIES}
        self.current = "byte"
        self.energy = 1
        self.shrink_streak = 0
        self.plateau_streak = 0
        self.run_id = 0
        self.tried: set[str] = set()
        self.switches = 0
        self._fallback_idx = 0
        self._rotate_idx = 0
        if not self.log_path.exists():
            self.log_path.write_text(LOG_HEADER, encoding="utf-8")

    # ---------- выбор стратегии ----------

    def _pick_weighted(self, exclude: str | None = None) -> str:
        """Взвешенный случайный выбор: у стратегий с gain вес выше."""
        pool = [s for s in STRATEGIES if s != exclude]
        total = sum(self.weights[s] for s in pool)
        r = self.rng.random() * total
        acc = 0.0
        for s in pool:
            acc += self.weights[s]
            if r <= acc:
                return s
        return pool[-1]

    def _pick_fallback(self) -> str:
        """Следующая стратегия по кругу в порядке отката (не «первая попавшаяся»)."""
        n = len(SHRINK_FALLBACK)
        for step in range(1, n + 1):
            cand = SHRINK_FALLBACK[(self._fallback_idx + step) % n]
            if cand != self.current:
                self._fallback_idx = (self._fallback_idx + step) % n
                return cand
        return self.current

    def _pick_lru(self) -> str:
        """На плато — строго следующая стратегия по кругу (round-robin).

        Веса влияют только на порядок в начале цикла; важно, чтобы каждая стратегия
        получала ход: иначе планировщик может залипнуть на одной самой «лёгкой».
        """
        n = len(STRATEGIES)
        for step in range(1, n + 1):
            cand = STRATEGIES[(self._rotate_idx + step) % n]
            if cand != self.current:
                self._rotate_idx = (self._rotate_idx + step) % n
                return cand
        return self.current

    # ---------- учёт результата прогона ----------

    def on_run(self, signal: str, bb_run: int, bb_parent: int, bb_global: int) -> str:
        """Учесть результат прогона. Возвращает выполненное действие."""
        self.run_id += 1
        self.tried.add(self.current)
        src = self.current

        if signal == "gain":
            self.weights[self.current] = min(16.0, self.weights[self.current] * 2.0)
            self.shrink_streak = 0
            self.plateau_streak = 0
            return "gain"

        if signal == "noop":
            return "noop"

        if signal == "shrink":
            self.weights[self.current] = max(0.25, self.weights[self.current] * 0.5)
            self.shrink_streak += 1
            self.plateau_streak += 1
            if self.shrink_streak >= self.shrink_limit:
                nxt = self._pick_fallback()
                self.shrink_streak = 0
                if nxt != src:
                    self.current = nxt
                    self.switches += 1
                    self._log(src, nxt, "shrink", bb_run, bb_parent, bb_global)
                    return "switch-shrink"
            return "shrink"

        # plateau: новых BB нет, покрытие не уменьшилось
        self.plateau_streak += 1
        self.shrink_streak = 0
        if self.plateau_streak >= self.plateau_limit:
            nxt = self._pick_lru()
            self.plateau_streak = 0
            self.energy = min(5, self.energy + 1)
            if nxt != src:
                self.current = nxt
                self.switches += 1
                self._log(src, nxt, "plateau", bb_run, bb_parent, bb_global)
                return "switch-plateau"
            self._log(src, src, "plateau-energy", bb_run, bb_parent, bb_global)
            return "energy"
        return "plateau"

    def all_tried(self) -> bool:
        """True, когда каждая стратегия уже была текущей хотя бы раз."""
        return set(STRATEGIES) <= self.tried

    def _log(self, src: str, dst: str, reason: str, bb_run: int, bb_parent: int,
             bb_global: int) -> None:
        """Строка в adapt.log — доказательство работы адаптации для отчёта."""
        weights = " ".join(f"{s}={self.weights[s]:g}" for s in STRATEGIES)
        line = (f"{self.run_id}\t{src}\t{dst}\t{reason}\t{bb_run}\t{bb_parent}\t"
                f"{bb_global}\t{self.energy}\t{weights}\n")
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
        print(f"[adapt] run {self.run_id}: {src} -> {dst} ({reason}) "
              f"BB {bb_run}/{bb_parent}/{bb_global} energy={self.energy}")
