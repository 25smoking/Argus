package winsys

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
	procVirtualQueryEx    = kernel32.NewProc("VirtualQueryEx")
)

// VirtualQueryEx wrappers
func VirtualQueryEx(handle windows.Handle, address uintptr) (windows.MemoryBasicInformation, error) {
	var mbi windows.MemoryBasicInformation
	ret, _, err := procVirtualQueryEx.Call(
		uintptr(handle),
		address,
		uintptr(unsafe.Pointer(&mbi)),
		uintptr(unsafe.Sizeof(mbi)),
	)
	if ret == 0 {
		return mbi, err
	}
	return mbi, nil
}

// OpenProcessForMemory 打开进程以进行内存读取
func OpenProcessForMemory(pid uint32) (windows.Handle, error) {
	// PROCESS_VM_READ (0x0010) | PROCESS_QUERY_INFORMATION (0x0400)
	desiredAccess := uint32(windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION)
	return windows.OpenProcess(desiredAccess, false, pid)
}

// ReadProcessMemory 读取指定进程内存
func ReadProcessMemory(handle windows.Handle, address uintptr, size int) ([]byte, error) {
	buf := make([]byte, size)
	var bytesRead uintptr

	ret, _, err := procReadProcessMemory.Call(
		uintptr(handle),
		address,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	// ReadProcessMemory returns non-zero on success
	if ret == 0 {
		return nil, err
	}

	return buf[:bytesRead], nil
}

// MemoryRegionInfo 简化的内存区域信息
type MemoryRegionInfo struct {
	BaseAddress uintptr
	RegionSize  uintptr
	State       uint32
	Protect     uint32
	Type        uint32
}

// ScanMemoryRegions 扫描进程的内存区域，返回可读的区域列表
func ScanMemoryRegions(handle windows.Handle) ([]MemoryRegionInfo, error) {
	var results []MemoryRegionInfo
	var mbi windows.MemoryBasicInformation
	var address uintptr = 0

	// 循环遍历整个内存空间
	for {
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(handle),
			address,
			uintptr(unsafe.Pointer(&mbi)),
			uintptr(unsafe.Sizeof(mbi)),
		)

		if ret == 0 {
			break
		}

		// Filter: MEM_COMMIT (0x1000)
		if mbi.State == 0x1000 {
			// Filter: Readable pages
			// PAGE_READONLY(0x02), PAGE_READWRITE(0x04), PAGE_EXECUTE_READ(0x20), PAGE_EXECUTE_READWRITE(0x40)
			isReadable := (mbi.Protect & (windows.PAGE_READONLY | windows.PAGE_READWRITE | windows.PAGE_EXECUTE_READ | windows.PAGE_EXECUTE_READWRITE)) != 0
			// Exclude PAGE_GUARD (0x100) or PAGE_NOACCESS (0x01)
			isGuard := (mbi.Protect & windows.PAGE_GUARD) != 0

			if isReadable && !isGuard {
				results = append(results, MemoryRegionInfo{
					BaseAddress: mbi.BaseAddress,
					RegionSize:  mbi.RegionSize,
					State:       mbi.State,
					Protect:     mbi.Protect,
					Type:        mbi.Type,
				})
			}
		}

		// Update address for next iteration
		address = mbi.BaseAddress + mbi.RegionSize
	}

	return results, nil
}

// GetProtString converts memory protection constants to string
func GetProtString(protect uint32) string {
	if protect&windows.PAGE_NOACCESS != 0 {
		return "NA"
	}
	if protect&windows.PAGE_EXECUTE_READWRITE != 0 {
		return "RWX"
	}
	if protect&windows.PAGE_EXECUTE_READ != 0 {
		return "RX"
	}
	if protect&windows.PAGE_EXECUTE != 0 {
		return "X"
	}
	if protect&windows.PAGE_READWRITE != 0 {
		return "RW"
	}
	if protect&windows.PAGE_READONLY != 0 {
		return "R"
	}
	return fmt.Sprintf("0x%x", protect)
}
