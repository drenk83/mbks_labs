"""Слепые мутации конфига (без /start, без имён и смещений полей).

Типы мутаций из ТЗ: замена одного байта, замена нескольких, граничные значения,
допись в конец, вставка внутрь (удлинение), работа с разделителями `,:=;`.
Плюс стратегия `combo` — «удлинить и испортить поле»: для переполнения буфера
нужно одновременно, чтобы данных стало больше и счётчик длины был испорчен,
а одной мутацией это почти недостижимо.
"""

from __future__ import annotations

import random

DELIMS = b",:=;"

# ТЗ: 0x00, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, половины и ±1.
BOUNDARY_VALUES: list[bytes] = [
    (0x00).to_bytes(1, "little"),
    (0xFF).to_bytes(1, "little"),
    (0xFF // 2).to_bytes(1, "little"),
    (0xFF // 2 + 1).to_bytes(1, "little"),
    (0xFF // 2 - 1).to_bytes(1, "little"),
    (0xFFFF).to_bytes(2, "little"),
    (0xFFFF // 2).to_bytes(2, "little"),
    (0xFFFF // 2 + 1).to_bytes(2, "little"),
    (0xFFFF // 2 - 1).to_bytes(2, "little"),
    (0xFFFFFF).to_bytes(3, "little"),
    (0xFFFFFFFF).to_bytes(4, "little"),
    (0xFFFFFFFF // 2).to_bytes(4, "little"),
    (0xFFFFFFFF // 2 + 1).to_bytes(4, "little"),
    (0xFFFFFFFF // 2 - 1).to_bytes(4, "little"),
]

# Значения, подставляемые в 4-байтные поля целиком (проход C режима --seq).
WORD_DWORD_VALUES: list[bytes] = [
    (0xFFFF).to_bytes(2, "little"),
    (0x7FFF).to_bytes(2, "little"),
    (0x8000).to_bytes(2, "little"),
    (0xFFFF // 2).to_bytes(2, "little"),
    (0xFFFFFFFF).to_bytes(4, "little"),
    (0x7FFFFFFF).to_bytes(4, "little"),
    (0x80000000).to_bytes(4, "little"),
    (0x00010000).to_bytes(4, "little"),
    (0x00002710).to_bytes(4, "little"),
    (0x00001388).to_bytes(4, "little"),
]

# Значения для перебора 4-байтных полей: граничные и «умеренно большие» длины.
# Большие, но не гигантские значения копирования дают переполнение приёмного
# буфера, не улетая сразу в незамапленную память.
LENGTH_VALUES = [
    (0x0FA0).to_bytes(2, "little"),   # 4000
    (0x1000).to_bytes(2, "little"),   # 4096
    (0x1388).to_bytes(2, "little"),   # 5000
    (0x1770).to_bytes(2, "little"),   # 6000
    (0x1F40).to_bytes(2, "little"),   # 8000
    (0x2710).to_bytes(2, "little"),   # 10000
    (0x3FFF).to_bytes(2, "little"),
    (0x7FFF).to_bytes(2, "little"),
    (0xFFFF).to_bytes(2, "little"),
    (0x7FFFFFFF).to_bytes(4, "little"),
    (0x00010000).to_bytes(4, "little"),
    (0x00400000).to_bytes(4, "little"),
    (0x00000000).to_bytes(4, "little"),
]

# Шаг удлинения по уровням «энергии»: нужно доходить до нужной длины за десятки
# прогонов, а не за тысячи.
APPEND_STEPS = {1: 64, 2: 128, 3: 256, 4: 512, 5: 1024}
EXPAND_STEPS = {1: 32, 2: 64, 3: 128, 4: 256, 5: 512}


def overlay_inplace(data: bytes, offset: int, patch: bytes) -> bytes:
    """Пишет patch по смещению; хвост, не влезающий в файл, отбрасывается."""
    if offset < 0 or offset >= len(data) or not patch:
        return data
    n = min(len(patch), len(data) - offset)
    b = bytearray(data)
    b[offset : offset + n] = patch[:n]
    return bytes(b)


def append_block(data: bytes, n: int, rng: random.Random, byte: int | None = None) -> bytes:
    """Дописать n байт в конец (значение фиксировано или случайно)."""
    n = max(1, int(n))
    if byte is None:
        return data + bytes(rng.randrange(256) for _ in range(n))
    return data + bytes([byte & 0xFF]) * n


def mutate_byte(data: bytes, rng: random.Random) -> bytes:
    """Один случайный байт → случайное значение."""
    if not data:
        return data
    b = bytearray(data)
    i = rng.randrange(len(b))
    b[i] = rng.randrange(256)
    return bytes(b)


def mutate_multi(data: bytes, rng: random.Random, n: int) -> bytes:
    """Замена n различных байт."""
    if not data:
        return data
    b = bytearray(data)
    n = max(1, min(n, len(b)))
    for i in rng.sample(range(len(b)), n):
        b[i] = rng.randrange(256)
    return bytes(b)


def mutate_boundary(data: bytes, rng: random.Random) -> bytes:
    """Граничное значение из ТЗ в случайное смещение."""
    if not data:
        return data
    return overlay_inplace(data, rng.randrange(len(data)), rng.choice(BOUNDARY_VALUES))


def mutate_append(data: bytes, rng: random.Random, energy: int = 1, byte: int = 0x41) -> bytes:
    """Дописать блок в конец: данных больше, исходные байты целы."""
    return append_block(data, APPEND_STEPS.get(energy, 64), rng, byte)


def mutate_expand(data: bytes, rng: random.Random, energy: int = 1) -> bytes:
    """Вставить блок внутрь (файл длиннее, исходное содержимое цело)."""
    n = EXPAND_STEPS.get(energy, 32)
    insert = bytes(rng.randrange(256) for _ in range(n))
    pos = rng.randrange(len(data) + 1) if data else 0
    return data[:pos] + insert + data[pos:]


def mutate_delim(data: bytes, rng: random.Random, extra: int = 4) -> bytes:
    """Портить/удлинять поле у символа `,:=;`. Нет разделителей — вернуть как было."""
    positions = [i for i, ch in enumerate(data) if ch in DELIMS]
    if not positions:
        return data
    i = rng.choice(positions)
    b = bytearray(data)
    kind = rng.randrange(3)
    if kind == 0:
        b[i] = rng.randrange(256)
        return bytes(b)
    if kind == 1:
        for j in range(max(0, i - 1), min(len(b), i + 2)):
            if j != i:
                b[j] = rng.randrange(256)
        return bytes(b)
    pad = bytes(rng.randrange(256) for _ in range(max(1, extra)))
    return bytes(b[: i + 1] + pad + b[i + 1 :])


def mutate_field(data: bytes, rng: random.Random, cursor: int = 0) -> bytes:
    """Перебор 4-байтных полей граничными и «умеренно большими» значениями.

    Смещение берётся по кругу (cursor), а не случайно: иначе за десятки прогонов
    нужное поле может ни разу не попасть под замену. Знание формата не нужно —
    просто «пройти по всем 4-байтным окнам».
    """
    if len(data) < 4:
        return data
    aligned = list(range(0, len(data) - 4, 4))
    off = aligned[cursor % len(aligned)]
    return overlay_inplace(data, off, rng.choice(WORD_DWORD_VALUES + LENGTH_VALUES))


def mutate_combo(data: bytes, rng: random.Random, energy: int = 1) -> bytes:
    """Удлинить данные (append/expand) и сразу испортить 4-байтное поле.

    Именно сочетание «данных больше» + «счётчик длины испорчен» даёт переполнение
    буфера в цели: одной мутацией такое совпадение почти недостижимо.
    """
    out = mutate_append(data, rng, energy) if rng.random() < 0.5 else mutate_expand(data, rng, energy)
    x = rng.randrange(3)
    if x == 0:
        return mutate_boundary(out, rng)
    if x == 1:
        limit = max(1, len(out) - 4)
        off = rng.randrange(0, limit) & ~3  # выровненное 4-байтное поле
        return overlay_inplace(out, off, rng.choice(WORD_DWORD_VALUES))
    return mutate_multi(out, rng, 4)


def mutate(data: bytes, strategy: str, energy: int, rng: random.Random,
           cursor: int = 0) -> bytes:
    """Диспетчер стратегий для режима с обратной связью по покрытию.

    cursor — позиция перебора для стратегии `field` (растёт на каждом прогоне).
    """
    if strategy == "byte":
        return mutate_byte(data, rng)
    if strategy == "multi":
        return mutate_multi(data, rng, min(1 + energy, 8))
    if strategy == "boundary":
        return mutate_boundary(data, rng)
    if strategy == "append":
        return mutate_append(data, rng, energy)
    if strategy == "expand":
        return mutate_expand(data, rng, energy)
    if strategy == "delim":
        return mutate_delim(data, rng, 2 * energy)
    if strategy == "field":
        return mutate_field(data, rng, cursor)
    if strategy == "combo":
        return mutate_combo(data, rng, energy)
    return mutate_byte(data, rng)


# ---------- детерминированные проходы режима auto --seq ----------


def seq_pass_a(data: bytes):
    """Проход A: каждое смещение × граничные значения из ТЗ (на месте)."""
    for offset in range(len(data)):
        for patch in BOUNDARY_VALUES:
            yield ("A", offset, patch, overlay_inplace(data, offset, patch))


def seq_pass_b(data: bytes, unit: int = 1024, max_blocks: int = 6):
    """Проход B: файл удлиняется блоками (данных больше, поля не тронуты)."""
    for k in range(1, max_blocks + 1):
        yield ("B", unit * k, b"", append_block(data, unit * k, random.Random(k), 0x41))


def seq_pass_c(data: bytes, unit: int = 1024, max_blocks: int = 4):
    """Проход C: удлинённый файл × граничные значения в выровненных 4-байтных полях.

    Ключевой проход: переполнение требует одновременно длинных данных и
    испорченного счётчика длины.
    """
    for k in range(1, max_blocks + 1):
        long_data = append_block(data, unit * k, random.Random(k), 0x41)
        for offset in range(0, len(data) - 4, 4):
            for patch in WORD_DWORD_VALUES:
                yield ("C", offset, patch, overlay_inplace(long_data, offset, patch))


def seq_pass_d(data: bytes, unit: int = 1024, max_blocks: int = 4):
    """Проход D: обрезка файла (поведение на коротком вводе)."""
    for k in range(1, max_blocks + 1):
        cut = unit * k
        if len(data) > cut:
            yield ("D", cut, b"", data[: len(data) - cut])


def seq_plan(data: bytes, passes: str = "ABC"):
    """Все детерминированные прогоны режима --seq в выбранных проходах."""
    if "A" in passes:
        yield from seq_pass_a(data)
    if "B" in passes:
        yield from seq_pass_b(data)
    if "C" in passes:
        yield from seq_pass_c(data)
    if "D" in passes:
        yield from seq_pass_d(data)
