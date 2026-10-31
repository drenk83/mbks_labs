import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "sc.asm")
OUT = os.path.join(HERE, "payload_asm.bin")
NASM_DEFAULT = os.path.join(HERE, "..", "tools", "nasm", "nasm.exe")

LIMIT = 740          # больше не влезает: срабатывает защита стека


def find_nasm():
    p = os.environ.get("NASM", NASM_DEFAULT)
    if os.path.exists(p):
        return p
    p = shutil.which("nasm")
    if p:
        return p
    raise SystemExit("не найден NASM - задайте путь в переменной NASM")


def main():
    nasm = find_nasm()
    r = subprocess.run([nasm, "-f", "bin", "-o", OUT, SRC], capture_output=True)
    if r.returncode:
        raise SystemExit("nasm: " + r.stderr.decode("latin1", "replace"))

    code = open(OUT, "rb").read()
    nulls = code.count(0)
    print("исходник : %s" % os.path.basename(SRC))
    print("payload  : %d байт, нулевых %d" % (len(code), nulls))
    print("лимит    : %d байт -> %s" % (LIMIT, "ВЛЕЗАЕТ" if len(code) < LIMIT else "НЕ ВЛЕЗАЕТ"))
    if nulls:
        print("ОШИБКА: в payload есть нулевые байты - копирование оборвётся")
        return 1
    if len(code) >= LIMIT:
        print("ОШИБКА: payload слишком длинный")
        return 1
    print("записан  : %s" % OUT)
    return 0


if __name__ == '__main__':
    sys.exit(main())
