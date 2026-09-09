"""Debug-loop 32-bit vuln2.exe из 64-bit Python: Wow64GetThreadContext, не GetThreadContext."""

import ctypes
from ctypes import wintypes
from pathlib import Path

from runner import RunResult, _is_exception_exit

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_NO_WINDOW = 0x08000000
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
STATUS_WX86_BREAKPOINT = 0x4000001F
STATUS_WX86_SINGLE_STEP = 0x4000001E
DBG_PRINTEXCEPTION_C = 0x40010006
DBG_PRINTEXCEPTION_WIDE_C = 0x4001000A

FATAL_EXCEPTIONS = {
    0xC0000005,  # ACCESS_VIOLATION
    0xC0000006,  # IN_PAGE_ERROR
    0xC000001D,  # ILLEGAL_INSTRUCTION
    0xC0000025,  # NONCONTINUABLE_EXCEPTION
    0xC000008C,  # ARRAY_BOUNDS_EXCEEDED
    0xC0000094,  # INTEGER_DIVIDE_BY_ZERO
    0xC0000096,  # PRIVILEGED_INSTRUCTION
    0xC00000FD,  # STACK_OVERFLOW
    0xC0000409,  # FAST_FAIL
    0xC0000374,  # HEAP_CORRUPTION
}

THREAD_GET_CONTEXT = 0x0008
THREAD_QUERY_INFORMATION = 0x0040
THREAD_SUSPEND_RESUME = 0x0002

SEM_FAILCRITICALERRORS = 0x0001
SEM_NOGPFAULTERRORBOX = 0x0002
SEM_NOOPENFILEERRORBOX = 0x8000

WOW64_CONTEXT_i386 = 0x00010000
WOW64_CONTEXT_CONTROL = 0x00000001
WOW64_CONTEXT_INTEGER = 0x00000002
WOW64_CONTEXT_SEGMENTS = 0x00000004
WOW64_CONTEXT_FULL = (
    WOW64_CONTEXT_i386
    | WOW64_CONTEXT_CONTROL
    | WOW64_CONTEXT_INTEGER
    | WOW64_CONTEXT_SEGMENTS
)

STACK_DUMP_SIZE = 128


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", wintypes.DWORD),
        ("ExceptionFlags", wintypes.DWORD),
        ("ExceptionRecord", ctypes.c_void_p),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", wintypes.DWORD),
        ("ExceptionInformation", ctypes.c_uint64 * 15),
    ]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", wintypes.DWORD),
    ]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("lpBaseOfImage", wintypes.LPVOID),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpThreadLocalBase", wintypes.LPVOID),
        ("lpStartAddress", wintypes.LPVOID),
        ("lpImageName", wintypes.LPVOID),
        ("fUnicode", wintypes.WORD),
    ]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("lpBaseOfDll", wintypes.LPVOID),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpImageName", wintypes.LPVOID),
        ("fUnicode", wintypes.WORD),
    ]


class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]


class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("raw", ctypes.c_ubyte * 176),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]


class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wintypes.DWORD),
        ("StatusWord", wintypes.DWORD),
        ("TagWord", wintypes.DWORD),
        ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.DWORD),
        ("DataOffset", wintypes.DWORD),
        ("DataSelector", wintypes.DWORD),
        ("RegisterArea", ctypes.c_byte * 80),
        ("Spare0", wintypes.DWORD),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wintypes.DWORD),
        ("Dr0", wintypes.DWORD),
        ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD),
        ("Dr3", wintypes.DWORD),
        ("Dr6", wintypes.DWORD),
        ("Dr7", wintypes.DWORD),
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
        ("SegGs", wintypes.DWORD),
        ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD),
        ("SegDs", wintypes.DWORD),
        ("Edi", wintypes.DWORD),
        ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD),
        ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD),
        ("Eax", wintypes.DWORD),
        ("Ebp", wintypes.DWORD),
        ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD),
        ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD),
        ("SegSs", wintypes.DWORD),
        ("ExtendedRegisters", ctypes.c_byte * 512),
    ]


kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.BOOL,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL
kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wintypes.DWORD]
kernel32.WaitForDebugEvent.restype = wintypes.BOOL
kernel32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
kernel32.ContinueDebugEvent.restype = wintypes.BOOL
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE
kernel32.Wow64GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
kernel32.Wow64GetThreadContext.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.SetErrorMode.argtypes = [wintypes.UINT]
kernel32.SetErrorMode.restype = wintypes.UINT
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL


def _ignore_exception(code: int) -> bool:
    """Точки останова загрузчика и OutputDebugString — не краш цели."""
    return code in (
        EXCEPTION_BREAKPOINT,
        EXCEPTION_SINGLE_STEP,
        STATUS_WX86_BREAKPOINT,
        STATUS_WX86_SINGLE_STEP,
        DBG_PRINTEXCEPTION_C,
        DBG_PRINTEXCEPTION_WIDE_C,
    )


def _close_event_file(handle) -> None:
    """CREATE_PROCESS/LOAD_DLL дают hFile; не закрыть — лок на exe/dll."""
    if handle:
        kernel32.CloseHandle(handle)


def _regs_and_stack(h_process, tid: int) -> tuple[dict | None, bytes | None]:
    """32-bit EAX…EIP и 128 байт по ESP в момент исключения."""
    access = THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME
    h_thread = kernel32.OpenThread(access, False, tid)
    if not h_thread:
        return None, None
    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL
        if not kernel32.Wow64GetThreadContext(h_thread, ctypes.byref(ctx)):
            return None, None
        regs = {
            "EAX": ctx.Eax,
            "EBX": ctx.Ebx,
            "ECX": ctx.Ecx,
            "EDX": ctx.Edx,
            "ESI": ctx.Esi,
            "EDI": ctx.Edi,
            "EBP": ctx.Ebp,
            "ESP": ctx.Esp,
            "EIP": ctx.Eip,
            "EFLAGS": ctx.EFlags,
        }
        buf = (ctypes.c_byte * STACK_DUMP_SIZE)()
        got = ctypes.c_size_t(0)
        stack = None
        if kernel32.ReadProcessMemory(
            h_process,
            ctypes.c_void_p(ctx.Esp),
            buf,
            STACK_DUMP_SIZE,
            ctypes.byref(got),
        ):
            stack = bytes(buf[: got.value])
        return regs, stack
    finally:
        kernel32.CloseHandle(h_thread)


def format_crash_log(result: RunResult) -> str:
    """Текст для lab1/crashes/crash_*.txt."""
    lines = [
        f"status: {result.status}",
        f"exit_code: {result.exit_code}",
        f"exception: 0x{(result.exception_code or 0):08X}",
        f"elapsed_sec: {result.elapsed:.3f}",
    ]
    if result.regs:
        for name in ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP", "EFLAGS"):
            if name in result.regs:
                lines.append(f"{name}=0x{result.regs[name]:08X}")
    if result.stack:
        lines.append("stack:")
        blob = result.stack
        for i in range(0, len(blob), 16):
            chunk = blob[i : i + 16]
            hexpart = " ".join(f"{b:02X}" for b in chunk)
            lines.append(f"  +{i:02X}  {hexpart}")
    if result.extra:
        lines.append(f"extra: {result.extra}")
    return "\n".join(lines) + "\n"


def run_under_debugger(work_dir: Path, timeout_sec: float) -> RunResult:
    """DEBUG_ONLY_THIS_PROCESS: штатный выход, краш (AV/stack) или timeout."""
    import time

    kernel32.SetErrorMode(
        SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
    )
    exe = work_dir / "vuln2.exe"
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    si.dwFlags = 0x00000001  # STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(f'"{exe}"')
    flags = DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW
    ok = kernel32.CreateProcessW(
        str(exe),
        cmd,
        None,
        None,
        False,
        flags,
        None,
        str(work_dir),
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    if not ok:
        err = ctypes.get_last_error()
        return RunResult("timeout", extra=f"CreateProcess failed: {err}")

    t0 = time.perf_counter()
    deadline = t0 + timeout_sec
    status = "ok"
    exception_code = None
    regs = None
    stack = None
    exit_code = None
    extra = ""

    try:
        while True:
            remaining_ms = int(max(0.0, (deadline - time.perf_counter()) * 1000))
            if remaining_ms == 0:
                kernel32.TerminateProcess(pi.hProcess, 1)
                status = "timeout"
                extra = "timeout"
                break
            ev = DEBUG_EVENT()
            if not kernel32.WaitForDebugEvent(ctypes.byref(ev), min(remaining_ms, 200)):
                continue
            code = ev.dwDebugEventCode
            cont = DBG_CONTINUE
            if code == CREATE_PROCESS_DEBUG_EVENT:
                _close_event_file(ev.u.CreateProcessInfo.hFile)
            elif code == LOAD_DLL_DEBUG_EVENT:
                _close_event_file(ev.u.LoadDll.hFile)
            elif code == EXCEPTION_DEBUG_EVENT:
                rec = ev.u.Exception.ExceptionRecord
                first = ev.u.Exception.dwFirstChance
                exc = rec.ExceptionCode & 0xFFFFFFFF
                if _ignore_exception(exc):
                    cont = DBG_CONTINUE
                elif (not first) or exc in FATAL_EXCEPTIONS:
                    exception_code = exc
                    regs, stack = _regs_and_stack(pi.hProcess, ev.dwThreadId)
                    status = "crash"
                    extra = f"first_chance={first}"
                    kernel32.TerminateProcess(pi.hProcess, exc)
                    cont = DBG_CONTINUE
                else:
                    cont = DBG_EXCEPTION_NOT_HANDLED
            elif code == EXIT_PROCESS_DEBUG_EVENT:
                exit_code = ev.u.ExitProcess.dwExitCode
                kernel32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
                break
            kernel32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
            if status == "crash":
                # drain until process dies or timeout
                drain_deadline = time.perf_counter() + 1.0
                while time.perf_counter() < drain_deadline:
                    ev2 = DEBUG_EVENT()
                    if not kernel32.WaitForDebugEvent(ctypes.byref(ev2), 100):
                        break
                    if ev2.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                        exit_code = ev2.u.ExitProcess.dwExitCode
                        kernel32.ContinueDebugEvent(ev2.dwProcessId, ev2.dwThreadId, DBG_CONTINUE)
                        break
                    kernel32.ContinueDebugEvent(ev2.dwProcessId, ev2.dwThreadId, DBG_CONTINUE)
                break
        if status == "ok" and _is_exception_exit(exit_code):
            status = "crash"
            exception_code = exit_code & 0xFFFFFFFF
        if status == "ok" and exit_code not in (0, None) and exception_code is None:
            if _is_exception_exit(exit_code):
                status = "crash"
    finally:
        if pi.hThread:
            kernel32.CloseHandle(pi.hThread)
        if pi.hProcess:
            kernel32.CloseHandle(pi.hProcess)

    return RunResult(
        status,
        exit_code=exit_code,
        exception_code=exception_code,
        regs=regs,
        stack=stack,
        elapsed=time.perf_counter() - t0,
        extra=extra,
    )
