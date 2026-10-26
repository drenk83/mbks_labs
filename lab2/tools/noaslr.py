"""
PyCommand for Immunity Debugger.

Lists loaded modules and their ASLR flag (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
bit 0x40), then searches modules without ASLR for the "jmp esp" instruction
(bytes FF E4).

Install:
    copy this file into the PyCommands folder of Immunity Debugger,
    restart the debugger, then type in the command line:

    !noaslr

Without administrator rights the same script can be executed in place:

    !pyexec execfile(r"C:\\path\\to\\noaslr.py");main([])

The file is ASCII only and Python 2.7 compatible on purpose: Immunity
Debugger uses an embedded Python 2.7 interpreter.
"""

import immlib

DESC = "List modules without ASLR and find jmp esp in them"

DYNAMIC_BASE = 0x40
PAGE = 0x1000
MAX_HITS = 10


def _byte(data, i):
    """Return byte value at index i for both Python 2 (str) and Python 3 (bytes)."""
    ch = data[i]
    if isinstance(ch, int):
        return ch
    return ord(ch)

def read_dword(imm, addr):
    """Read 32-bit little-endian value, return None if unreadable."""
    try:
        data = imm.readMemory(addr, 4)
    except Exception:
        return None
    if data is None or len(data) < 4:
        return None
    return (_byte(data, 0) | (_byte(data, 1) << 8) |
            (_byte(data, 2) << 16) | (_byte(data, 3) << 24))


def read_word(imm, addr):
    """Read 16-bit little-endian value, return None if unreadable."""
    try:
        data = imm.readMemory(addr, 2)
    except Exception:
        return None
    if data is None or len(data) < 2:
        return None
    return _byte(data, 0) | (_byte(data, 1) << 8)


def pe_header(imm, base):
    """Return (DllCharacteristics, SizeOfImage) or (None, None)."""
    pe = read_dword(imm, base + 0x3C)
    if pe is None or pe <= 0 or pe > 0x1000:
        return None, None
    # PE32: SizeOfImage at +0x50, DllCharacteristics at +0x5E from signature
    size = read_dword(imm, base + pe + 0x50)
    chars = read_word(imm, base + pe + 0x5E)
    return chars, size


def normalize_hits(hits):
    """Bring search results to a list of integer addresses.

    Immunity returns different shapes depending on the build: a plain list of
    addresses, or a list of lists where the address is the first element.
    """
    out = []
    if not hits:
        return out
    for item in hits:
        value = item
        while isinstance(value, (list, tuple)) and value:
            value = value[0]
        try:
            out.append(int(value))
        except Exception:
            continue
    return out


def scan_jmp_esp(imm, base, size):
    """Scan module image for bytes FF E4, return list of addresses."""
    hits = []
    if not size or size <= 0 or size > 0x4000000:
        return hits
    offset = 0
    while offset < size and len(hits) < MAX_HITS:
        try:
            chunk = imm.readMemory(base + offset, min(PAGE + 1, size - offset))
        except Exception:
            chunk = None
        if chunk:
            idx = chunk.find(b"\xff\xe4")
            if idx >= 0:
                hits.append(base + offset + idx)
        offset += PAGE
    return hits


def module_base(imm, name, mod):
    """Get base address from a module object or by module name."""
    if hasattr(mod, "getBase"):
        try:
            return mod.getBase()
        except Exception:
            return None
    try:
        m = imm.getModule(name)
    except Exception:
        m = None
    if m is not None and hasattr(m, "getBase"):
        try:
            return m.getBase()
        except Exception:
            return None
    return None


def main(args):
    imm = immlib.Debugger()
    imm.log("---- modules without ASLR ----")

    modules = imm.getAllModules()
    if hasattr(modules, "items"):
        items = list(modules.items())
    elif modules:
        items = [(m.getName(), m) for m in modules]
    else:
        items = []

    imm.log("modules loaded: %d" % len(items))
    if not items:
        imm.log("no modules: open vuln3.exe and wait for the pause first")
        return "noaslr: no process"

    without = 0
    for name, mod in sorted(items):
        base = module_base(imm, name, mod)
        if not base:
            imm.log("skip    %s  cannot get base address" % name)
            continue
        chars, size = pe_header(imm, base)
        if chars is None:
            imm.log("skip    %s  base 0x%08X  PE header unreadable" % (name, base))
            continue

        if chars & DYNAMIC_BASE:
            imm.log("ASLR    %-16s base 0x%08X  DllCharacteristics 0x%04X"
                    % (name, base, chars))
            continue

        without += 1
        imm.log("NOASLR  %-16s base 0x%08X  DllCharacteristics 0x%04X"
                % (name, base, chars))

        hits = []
        try:
            hits = imm.searchCommandsOnModule(base, "jmp esp")
        except Exception:
            hits = []
        hits = normalize_hits(hits)
        if not hits:
            hits = normalize_hits(scan_jmp_esp(imm, base, size))
        if not hits:
            imm.log("        jmp esp: not found")
            continue
        for addr in hits[:MAX_HITS]:
            imm.log("        jmp esp  0x%08X" % addr)

    imm.log("---- done, modules without ASLR: %d ----" % without)
    return "noaslr: see log"
