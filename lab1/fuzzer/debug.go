package main

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// Раскладка 32-битных DEBUG_EVENT и CONTEXT. На 64-битном фаззере эти числа неверны.
	debugEventSize = 96
	contextSize    = 716
	contextFull    = 0x10007 // CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS

	exceptionDebugEvent     = 1
	createProcessDebugEvent = 3
	exitProcessDebugEvent   = 5
	loadDLLDebugEvent       = 6
	// Остановка на входе в процесс и одиночный шаг отладчика падением не считаются.
	exceptionBreakpoint = 0x80000003
	exceptionSingleStep = 0x80000004
	dbgContinue         = 0x00010002 // DBG_CONTINUE, не DBG_EXCEPTION_NOT_HANDLED
	errorSemTimeout     = 121        // WaitForDebugEvent исчерпал свой интервал
	// Этих прав хватает, чтобы снять регистры потока и прочитать его стек.
	threadGetContext       = 0x0008
	threadQueryInformation = 0x0040
	createNoWindow         = 0x08000000
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procWaitForDebugEvent = kernel32.NewProc("WaitForDebugEvent")
	procContinueDebug     = kernel32.NewProc("ContinueDebugEvent")
	procGetThreadContext  = kernel32.NewProc("GetThreadContext")
	procOpenThread        = kernel32.NewProc("OpenThread")
	procReadMemory        = kernel32.NewProc("ReadProcessMemory")
	procTerminateProcess  = kernel32.NewProc("TerminateProcess")
)

// Crash — снимок падения 32-битной цели.
type Crash struct {
	Code                    uint32
	Eax, Ebx, Ecx, Edx      uint32
	Esi, Edi, Ebp, Esp, Eip uint32
	EFlags                  uint32
	Stack                   []byte
	StackErr                string
}

// LogText собирает crashN.log: код исключения, мутация, регистры и дамп стека.
func (c *Crash) LogText(change string) string {
	var b stringsBuilder
	b.WriteString("Program crashed.\n")
	b.WriteString(fmt.Sprintf("Exception code: %08X\n\n", c.Code))
	if change != "" {
		b.WriteString("Mutation: " + change + "\n\n")
	}
	b.WriteString("Registers:\n")
	b.WriteString(fmt.Sprintf("Eax: 0x%X\nEbx: 0x%X\nEcx: 0x%X\nEdx: 0x%X\n", c.Eax, c.Ebx, c.Ecx, c.Edx))
	b.WriteString(fmt.Sprintf("Esi: 0x%X\nEdi: 0x%X\nEbp: 0x%X\nEsp: 0x%X\nEip: 0x%X\nEFlags: 0x%X\n\n", c.Esi, c.Edi, c.Ebp, c.Esp, c.Eip, c.EFlags))
	if c.StackErr != "" {
		b.WriteString(c.StackErr + "\n")
		return b.String()
	}
	b.WriteString(fmt.Sprintf("Stack (%d) bytes read:\n", len(c.Stack)))
	for i := 0; i < len(c.Stack); i += 16 {
		end := i + 16
		if end > len(c.Stack) {
			end = len(c.Stack)
		}
		b.WriteString(fmt.Sprintf("0x%08x ", c.Esp+uint32(i)))
		for _, v := range c.Stack[i:end] {
			b.WriteString(fmt.Sprintf(" %02x", v))
		}
		b.WriteString("\n")
	}
	return b.String()
}

type stringsBuilder struct{ b []byte }

func (s *stringsBuilder) WriteString(v string) { s.b = append(s.b, v...) }
func (s *stringsBuilder) String() string       { return string(s.b) }

// debugEvent повторяет DEBUG_EVENT: код, идентификаторы и сырой union на 84 байта.
// Из union читаем только первые 4 байта — код исключения или хендл файла.
type debugEvent struct {
	Code uint32
	Pid  uint32
	Tid  uint32
	U    [84]byte
}

// RunDebug запускает 32-битный exe и возвращает снимок, если поймано исключение.
// Чистый выход — nil, nil.
func RunDebug(exe, workDir string, timeout time.Duration) (*Crash, error) {
	// Порт отладчика принадлежит потоку, вызвавшему CreateProcess.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	exePtr, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return nil, err
	}
	dirPtr, err := windows.UTF16PtrFromString(workDir)
	if err != nil {
		return nil, err
	}
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	err = windows.CreateProcess(exePtr, nil, nil, nil, false, windows.DEBUG_ONLY_THIS_PROCESS|createNoWindow, nil, dirPtr, &si, &pi)
	if err != nil {
		return nil, fmt.Errorf("CreateProcess: %w", err)
	}
	alive := true
	defer func() {
		if alive {
			procTerminateProcess.Call(uintptr(pi.Process), 1)
		}
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	}()

	deadline := time.Now().Add(timeout)
	var crash *Crash
	for {
		var ev debugEvent
		wait := uint32(500)
		r, _, callErr := procWaitForDebugEvent.Call(uintptr(unsafe.Pointer(&ev)), uintptr(wait))
		if r == 0 {
			if errnoOf(callErr) == errorSemTimeout {
				if time.Now().After(deadline) {
					return crash, fmt.Errorf("таймаут ожидания цели")
				}
				continue
			}
			return crash, fmt.Errorf("WaitForDebugEvent: %v", callErr)
		}
		switch ev.Code {
		case createProcessDebugEvent, loadDLLDebugEvent:
			// В событии лежит хендл файла образа. Его закрывает отладчик, не система.
			closeDebugFile(ev.U[:4])
			continueDebug(ev, dbgContinue)
		case exceptionDebugEvent:
			code := binary.LittleEndian.Uint32(ev.U[:4])
			if code == exceptionBreakpoint || code == exceptionSingleStep {
				continueDebug(ev, dbgContinue)
				continue
			}
			// Снимок берётся, пока процесс ещё жив. Дальше его завершаем сами.
			crash = readCrash(pi.Process, ev.Tid, code)
			procTerminateProcess.Call(uintptr(pi.Process), 1)
			continueDebug(ev, dbgContinue)
			drainDebug(&ev, time.Now().Add(2*time.Second))
			alive = false
			return crash, nil
		case exitProcessDebugEvent:
			continueDebug(ev, dbgContinue)
			alive = false
			return crash, nil
		default:
			continueDebug(ev, dbgContinue)
		}
	}
}

func errnoOf(err error) uintptr {
	errno, ok := err.(syscall.Errno)
	if !ok {
		return 0
	}
	return uintptr(errno)
}

func continueDebug(ev debugEvent, status uint32) {
	procContinueDebug.Call(uintptr(ev.Pid), uintptr(ev.Tid), uintptr(status))
}

// closeDebugFile закрывает хендл из CREATE_PROCESS или LOAD_DLL.
func closeDebugFile(handle []byte) {
	h := binary.LittleEndian.Uint32(handle)
	if h != 0 {
		windows.CloseHandle(windows.Handle(h))
	}
}

// drainDebug дочитывает очередь до выхода процесса, чтобы порт отладчика освободился.
func drainDebug(ev *debugEvent, deadline time.Time) {
	for time.Now().Before(deadline) {
		r, _, callErr := procWaitForDebugEvent.Call(uintptr(unsafe.Pointer(ev)), 200)
		if r == 0 {
			if errnoOf(callErr) == errorSemTimeout {
				continue
			}
			return
		}
		if ev.Code == createProcessDebugEvent || ev.Code == loadDLLDebugEvent {
			closeDebugFile(ev.U[:4])
		}
		continueDebug(*ev, dbgContinue)
		if ev.Code == exitProcessDebugEvent {
			return
		}
	}
}

// readCrash снимает регистры упавшего потока и 256 байт стека от ESP.
func readCrash(process windows.Handle, tid, code uint32) *Crash {
	c := &Crash{Code: code}
	thread, _, err := procOpenThread.Call(threadGetContext|threadQueryInformation, 0, uintptr(tid))
	if thread == 0 {
		c.StackErr = fmt.Sprintf("OpenThread: %v", err)
		return c
	}
	defer windows.CloseHandle(windows.Handle(thread))

	var ctx [contextSize]byte
	binary.LittleEndian.PutUint32(ctx[0:4], contextFull)
	r, _, err := procGetThreadContext.Call(thread, uintptr(unsafe.Pointer(&ctx[0])))
	if r == 0 {
		c.StackErr = fmt.Sprintf("GetThreadContext: %v", err)
		return c
	}
	// Смещения полей в 32-битном CONTEXT. Первые 4 байта — флаг ContextFlags.
	c.Edi = u32(ctx[156:])
	c.Esi = u32(ctx[160:])
	c.Ebx = u32(ctx[164:])
	c.Edx = u32(ctx[168:])
	c.Ecx = u32(ctx[172:])
	c.Eax = u32(ctx[176:])
	c.Ebp = u32(ctx[180:])
	c.Eip = u32(ctx[184:])
	c.EFlags = u32(ctx[192:])
	c.Esp = u32(ctx[196:])

	stack := make([]byte, 256)
	var n uint32
	r, _, err = procReadMemory.Call(uintptr(process), uintptr(c.Esp), uintptr(unsafe.Pointer(&stack[0])), uintptr(len(stack)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || n == 0 {
		c.StackErr = fmt.Sprintf("стек по Esp %08X прочитать не удалось: %v", c.Esp, err)
		return c
	}
	c.Stack = stack[:n]
	return c
}

func u32(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b[:4])
}
