#!/usr/bin/env python3
"""Держит сессию Frida, пока adb открывает .eml и сканер. CLI frida выходит по EOF stdin."""

import subprocess
import sys
import time
from pathlib import Path

import frida

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "trace.js"
LOG = ROOT / "results" / "frida" / "trace.log"
EML_PNG = ROOT / "results" / "frida" / "screen-eml.png"
SCAN_PNG = ROOT / "results" / "frida" / "screen-scanner.png"
EML = "file:///data/data/ru.yandex.mail/files/lab5-external.eml"


def adb(args, timeout=30):
    print("adb", " ".join(args), flush=True)
    result = subprocess.run(["adb", *args], capture_output=True, timeout=timeout)
    if result.stdout:
        sys.stdout.buffer.write(result.stdout[:500])
        sys.stdout.buffer.write(b"\n")
    if result.stderr:
        sys.stderr.buffer.write(result.stderr[:500])
        sys.stderr.buffer.write(b"\n")
    return result.returncode


def main():
    pid = int(sys.argv[1])
    LOG.parent.mkdir(parents=True, exist_ok=True)
    log = LOG.open("w", encoding="utf-8")

    def on_message(message, data):
        log.write(repr(message) + "\n")
        log.flush()
        payload = message.get("payload", message)
        print(payload, flush=True)

    device = frida.get_usb_device(timeout=10)
    session = device.attach(pid)
    script = session.create_script(SCRIPT.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()

    deadline = time.time() + 20
    ready = False
    while time.time() < deadline:
        if "java-ready" in LOG.read_text(encoding="utf-8", errors="replace"):
            ready = True
            break
        time.sleep(0.2)
    print(f"ready={ready}", flush=True)
    if not ready:
        session.detach()
        return 2

    time.sleep(1)
    adb([
        "shell", "am", "start",
        "-a", "android.intent.action.VIEW",
        "-d", EML,
        "-t", "message/rfc822",
        "-n", "ru.yandex.mail/com.yandex.mail.eml.EmlActivity",
    ])
    time.sleep(5)
    shot = subprocess.run(["adb", "exec-out", "screencap", "-p"], capture_output=True, timeout=20)
    if shot.stdout.startswith(b"\x89PNG"):
        EML_PNG.write_bytes(shot.stdout)
        print(f"eml_png={len(shot.stdout)}", flush=True)
    else:
        print(f"eml_png_fail={shot.stderr[:200]!r}", flush=True)

    adb([
        "shell", "am", "start",
        "-n", "ru.yandex.mail/com.yandex.mail360.camera.doc.scanner.DocScannerCameraActivity",
    ])
    time.sleep(6)
    shot = subprocess.run(["adb", "exec-out", "screencap", "-p"], capture_output=True, timeout=20)
    if shot.stdout.startswith(b"\x89PNG"):
        SCAN_PNG.write_bytes(shot.stdout)
        print(f"scan_png={len(shot.stdout)}", flush=True)
    else:
        print(f"scan_png_fail={shot.stderr[:200]!r}", flush=True)

    time.sleep(2)
    session.detach()
    print("detached", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
