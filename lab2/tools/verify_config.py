"""Прогон эксплойта и проверка результата.

Запускает exploit\\vuln3.exe в его каталоге, затем печатает содержимое
ports.txt. Сторонние программы не запускаются - только сам уязвимый процесс.

Использование:
    python tools\\verify_config.py
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXPLOIT = os.path.normpath(os.path.join(HERE, "..", "exploit"))
EXE = os.path.join(EXPLOIT, "vuln3.exe")
PORTS = os.path.join(EXPLOIT, "ports.txt")


def main():
    if not os.path.exists(EXE):
        raise SystemExit("не найден %s" % EXE)
    for f in ("ports.txt", "services.txt"):
        p = os.path.join(EXPLOIT, f)
        if os.path.exists(p):
            os.remove(p)

    pr = subprocess.run([EXE], cwd=EXPLOIT, capture_output=True, timeout=30)
    print("exit     : 0x%08X" % (pr.returncode & 0xFFFFFFFF))
    for line in pr.stdout.decode("latin1", "replace").splitlines():
        if any(k in line for k in ("Variant", "shell_len", "ERROR", "Hello")):
            print("   " + line.strip()[:110])

    if os.path.exists(PORTS):
        text = open(PORTS, "r", encoding="ascii", errors="replace").read()
        print("ports.txt:")
        for line in text.splitlines():
            print("   " + line)
        print("всего строк: %d" % len([l for l in text.splitlines() if l.strip()]))
    else:
        print("ports.txt: НЕ СОЗДАН")
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
