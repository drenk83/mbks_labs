"""Слепые мутации конфига: без /start, shell_len и прочих полей формата."""

import random

DELIMS = b",:=;"

# ТЗ: 0x00, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, половины и ±1.
BOUNDARY_VALUES = [
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
    (0xFF // 2).to_bytes(1, "little"),
]


def overlay_inplace(data: bytes, offset: int, patch: bytes) -> bytes:
    """Пишет patch по смещению; хвост, не влезающий в файл, отбрасывается."""
    if offset < 0 or offset >= len(data) or not patch:
        return data
    n = min(len(patch), len(data) - offset)
    b = bytearray(data)
    b[offset : offset + n] = patch[:n]
    return bytes(b)


def energy_params(energy: int) -> dict:
    """Сколько байт трогать при данном уровне энергии (1..5, растёт на plateau)."""
    e = max(1, min(int(energy), 5))
    return {
        "multi": min(1 + e, 8),
        "append": 8 * (2 ** (e - 1)),
        "expand": 4 * (2 ** (e - 1)),
        "delim_extra": 2 * e,
    }


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
    patch = rng.choice(BOUNDARY_VALUES)
    offset = rng.randrange(len(data))
    return overlay_inplace(data, offset, patch)


def mutate_append(data: bytes, rng: random.Random, n: int) -> bytes:
    """Дописать n случайных байт в конец."""
    n = max(1, n)
    return data + bytes(rng.randrange(256) for _ in range(n))


def mutate_expand(data: bytes, rng: random.Random, n: int) -> bytes:
    """Вставить n байт в случайное место (файл становится длиннее)."""
    n = max(1, n)
    insert = bytes(rng.randrange(256) for _ in range(n))
    pos = rng.randrange(len(data) + 1) if data else 0
    return data[:pos] + insert + data[pos:]


def mutate_delim(data: bytes, rng: random.Random, extra: int) -> bytes:
    """Портить/удлинять поле у символа ,:=;. Нет разделителей — вернуть как было."""
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
        left = max(0, i - 1)
        right = min(len(b), i + 2)
        for j in range(left, right):
            if j != i:
                b[j] = rng.randrange(256)
        return bytes(b)
    pad = bytes(rng.randrange(256) for _ in range(max(1, extra)))
    return bytes(b[: i + 1] + pad + b[i + 1 :])


def mutate(data: bytes, strategy: str, energy: int, rng: random.Random) -> bytes:
    """Диспетчер стратегий для coverage-режима."""
    p = energy_params(energy)
    if strategy == "byte":
        return mutate_byte(data, rng)
    if strategy == "multi":
        return mutate_multi(data, rng, p["multi"])
    if strategy == "boundary":
        return mutate_boundary(data, rng)
    if strategy == "append":
        return mutate_append(data, rng, p["append"])
    if strategy == "expand":
        return mutate_expand(data, rng, p["expand"])
    if strategy == "delim":
        return mutate_delim(data, rng, p["delim_extra"])
    return mutate_byte(data, rng)


def seq_plan(data: bytes):
    """Все пары (смещение, граничное значение, мутант) для auto --seq."""
    for offset in range(len(data)):
        for patch in BOUNDARY_VALUES:
            yield offset, patch, overlay_inplace(data, offset, patch)
