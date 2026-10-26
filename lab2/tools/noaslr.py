# -*- coding: utf-8 -*-
"""
PyCommand для Immunity Debugger.

Печатает загруженные модули без ASLR (в PE-заголовке сброшен
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, бит 0x40) и ищет в них
инструкцию jmp esp (байты FF E4).

Положить файл в каталог PyCommands рядом с ImmunityDebugger.exe
и выполнить в командной строке отладчика:

    !noaslr
"""
import struct
import immlib

DESC = "List modules without ASLR and find jmp esp"

DYNAMIC_BASE = 0x40


def dll_characteristics(imm, base):
    pe_offset = struct.unpack("<I", imm.readMemory(base + 0x3C, 4))[0]
    # PE32: DllCharacteristics лежит на смещении 0x5E от сигнатуры PE
    raw = imm.readMemory(base + pe_offset + 0x5E, 2)
    return struct.unpack("<H", raw)[0]


def main(args):
    imm = immlib.Debugger()
    imm.log("---- modules without ASLR ----")
    modules = imm.getAllModules()
    for name in modules.keys():
        mod = imm.getModule(name)
        if mod is None:
            continue
        base = mod.getBase()
        try:
            chars = dll_characteristics(imm, base)
        except Exception:
            imm.log("skip  %s  0x%08X  header unreadable" % (name, base))
            continue
        if chars & DYNAMIC_BASE:
            continue
        imm.log("NOASLR  %s  base 0x%08X  DllCharacteristics 0x%04X" % (name, base, chars))
        try:
            hits = imm.searchCommandsOnModule(base, "jmp esp")
        except Exception:
            hits = []
        if not hits:
            imm.log("        jmp esp: not found")
            continue
        for addr in hits:
            imm.log("        jmp esp  0x%08X" % addr)
    imm.log("---- done ----")
    return "noaslr: see log"
