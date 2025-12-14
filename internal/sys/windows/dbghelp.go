package winsys

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modDbghelp = syscall.NewLazyDLL("dbghelp.dll")

	procSymInitialize = modDbghelp.NewProc("SymInitialize")
	procSymCleanup    = modDbghelp.NewProc("SymCleanup")
	procStackWalk64   = modDbghelp.NewProc("StackWalk64")
)

const (
	IMAGE_FILE_MACHINE_I386  = 0x014c
	IMAGE_FILE_MACHINE_AMD64 = 0x8664

	AddrMode1616 = 0
	AddrMode1632 = 1
	AddrModeReal = 2
	AddrModeFlat = 3
)

type ADDRESS64 struct {
	Offset  uint64
	Segment uint16
	Mode    int32
}

type KDHELP64 struct {
	Thread                    uint64
	ThCallbackStack           uint32
	ThCallbackBStore          uint32
	NextCallback              uint32
	FramePointer              uint32
	KiCallUserMode            uint64
	KeUserCallbackDispatcher  uint64
	SystemRangeStart          uint64
	KiUserExceptionDispatcher uint64
	StackBase                 uint64
	StackLimit                uint64
	Reserved                  [5]uint64
}

type STACKFRAME64 struct {
	AddrPC         ADDRESS64
	AddrReturn     ADDRESS64
	AddrFrame      ADDRESS64
	AddrStack      ADDRESS64
	AddrBStore     ADDRESS64
	FuncTableEntry uint64
	Params         [4]uint64
	Far            bool
	Virtual        bool
	Reserved       [3]uint64
	KdHelp         KDHELP64
}

func SymInitialize(hProcess windows.Handle) error {
	// fInvadeProcess = TRUE (load symbols for modules)
	ret, _, err := procSymInitialize.Call(
		uintptr(hProcess),
		0,
		1,
	)
	if ret == 0 {
		return err
	}
	return nil
}

func SymCleanup(hProcess windows.Handle) error {
	ret, _, err := procSymCleanup.Call(uintptr(hProcess))
	if ret == 0 {
		return err
	}
	return nil
}

// StackWalk64
// context MUST be a pointer to windows.CONTEXT (aligned)
func StackWalk64(machineType uint32, hProcess windows.Handle, hThread windows.Handle, stackFrame *STACKFRAME64, context unsafe.Pointer) (bool, error) {
	// FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress: pass 0/nil for default
	// ReadMemoryRoutine: pass 0 for ReadProcessMemory

	ret, _, err := procStackWalk64.Call(
		uintptr(machineType),
		uintptr(hProcess),
		uintptr(hThread),
		uintptr(unsafe.Pointer(stackFrame)),
		uintptr(context),
		0,
		0, // SymFunctionTableAccess64
		0, // SymGetModuleBase64
		0,
	)
	if ret == 0 {
		// StackWalk64 returns TRUE on success, FALSE on failure
		// If FALSE, it means end of stack or error.
		return false, err
	}
	return true, nil
}
