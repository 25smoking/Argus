package winsys

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	moddbghelp            = syscall.NewLazyDLL("dbghelp.dll")
	procMiniDumpWriteDump = moddbghelp.NewProc("MiniDumpWriteDump")
)

// MiniDumpType flags
const (
	MiniDumpNormal         = 0x00000000
	MiniDumpWithFullMemory = 0x00000002
)

// DumpProcess 创建指定进程的内存转储 (MiniDump)
// dumpType: MiniDumpNormal (小) 或 MiniDumpWithFullMemory (完整)
func DumpProcess(pid uint32, filePath string, fullMem bool) error {
	// 1. Open Process
	// PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
	access := uint32(windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ)
	hProcess, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess failed: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	// 2. Create Output File
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("create file failed: %w", err)
	}
	// We need the file handle. Go's os.File has Fd(), which on Windows is the Handle.
	hFile := windows.Handle(f.Fd())
	defer f.Close()

	// 3. Dump
	dumpType := uintptr(MiniDumpNormal)
	if fullMem {
		dumpType = uintptr(MiniDumpWithFullMemory)
	}

	// BOOL MiniDumpWriteDump(
	//   HANDLE hProcess,
	//   DWORD ProcessId,
	//   HANDLE hFile,
	//   MINIDUMP_TYPE DumpType,
	//   PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
	//   PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
	//   PMINIDUMP_CALLBACK_INFORMATION CallbackParam
	// );
	ret, _, err := procMiniDumpWriteDump.Call(
		uintptr(hProcess),
		uintptr(pid),
		uintptr(hFile),
		dumpType,
		0,
		0,
		0,
	)

	if ret == 0 {
		return fmt.Errorf("MiniDumpWriteDump failed: %w", err)
	}

	return nil
}
