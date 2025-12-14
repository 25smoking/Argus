package winsys

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modntdll                     = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySystemInformation = modntdll.NewProc("NtQuerySystemInformation")
)

const (
	SystemProcessInformation    = 5
	STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
	STATUS_SUCCESS              = 0x00000000
)

// SystemProcessInformationStruct 简化定义，只取我们需要的 PID 和 Name
// 完整结构较为复杂，包含线程信息等
type SystemProcessInformationStruct struct {
	NextEntryOffset              uint32
	NumberOfThreads              uint32
	WorkingSetPrivateSize        int64 // diff size
	HardFaultCount               uint32
	NumberOfThreadsHighWatermark uint32
	CycleTime                    uint64
	CreateTime                   int64
	UserTime                     int64
	KernelTime                   int64
	ImageName                    UnicodeString // windows.UnicodeString not always available
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
	HandleCount                  uint32
	SessionId                    uint32
	UniqueProcessKey             uintptr
	PeakVirtualSize              uintptr
	VirtualSize                  uintptr
	PageFaultCount               uint32
	PeakWorkingSetSize           uintptr
	WorkingSetSize               uintptr
	QuotaPeakPagedPoolUsage      uintptr
	QuotaPagedPoolUsage          uintptr
	QuotaPeakNonPagedPoolUsage   uintptr
	QuotaNonPagedPoolUsage       uintptr
	PagefileUsage                uintptr
	PeakPagefileUsage            uintptr
	PrivatePageCount             uintptr
	ReadOperationCount           int64
	WriteOperationCount          int64
	OtherOperationCount          int64
	ReadTransferCount            int64
	WriteTransferCount           int64
	OtherTransferCount           int64
}

type UnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// GetProcessListNative 使用 NtQuerySystemInformation 枚举进程 (Native API)
func GetProcessListNative() (map[int]string, error) {
	var size uint32 = 0
	// 第一次调用获取长度
	status, _, _ := procNtQuerySystemInformation.Call(
		uintptr(SystemProcessInformation),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
	)

	if size == 0 {
		// 某些系统即使失败也会返回 size，如果为0则设个默认值重试
		size = 1024 * 1024 // 1MB
	}

	buffer := make([]byte, size)
	var retSz uint32

	// 循环尝试，因为缓冲区大小可能在两次调用间变化
	for {
		status, _, _ = procNtQuerySystemInformation.Call(
			uintptr(SystemProcessInformation),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&retSz)),
		)

		if status == STATUS_SUCCESS {
			break
		} else if status == uintptr(STATUS_INFO_LENGTH_MISMATCH) {
			if retSz > size {
				size = retSz
			} else {
				size *= 2
			}
			buffer = make([]byte, size)
		} else {
			return nil, fmt.Errorf("NtQuerySystemInformation failed with status 0x%x", status)
		}
	}

	procs := make(map[int]string)
	offset := 0
	for {
		p := (*SystemProcessInformationStruct)(unsafe.Pointer(&buffer[offset]))

		pid := int(p.UniqueProcessId)
		name := ""
		if p.ImageName.Buffer != nil {
			name = windows.UTF16PtrToString(p.ImageName.Buffer)
		}

		procs[pid] = name

		if p.NextEntryOffset == 0 {
			break
		}
		offset += int(p.NextEntryOffset)
	}

	return procs, nil
}

// GetProcessListBruteForce 暴力枚举 PID (0-65535)
// 返回存在的 PID 列表
func GetProcessListBruteForce() ([]int, error) {
	var pids []int
	var rights uint32 = windows.PROCESS_QUERY_LIMITED_INFORMATION

	// PID 0 (System Idle), 4 (System) always exist
	pids = append(pids, 0, 4)

	// 从 8 开始，步长 4
	for i := 8; i < 0xFFFF; i += 4 {
		h, err := windows.OpenProcess(rights, false, uint32(i))
		if err == nil {
			pids = append(pids, i)
			windows.CloseHandle(h)
		} else {
			// Access Denied (Error 5) means process exists but we can't open it.
			// Invalid Parameter (Error 87) means process doesn't exist (usually).
			if err == windows.ERROR_ACCESS_DENIED {
				pids = append(pids, i)
			}
		}
	}

	return pids, nil
}
