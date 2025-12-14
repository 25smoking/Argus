//go:build windows
// +build windows

package winsys

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Integrity Levels (完整性级别常量)
const (
	SECURITY_MANDATORY_UNTRUSTED_RID         = 0x00000000
	SECURITY_MANDATORY_LOW_RID               = 0x00001000
	SECURITY_MANDATORY_MEDIUM_RID            = 0x00002000
	SECURITY_MANDATORY_MEDIUM_PLUS_RID       = 0x00002100
	SECURITY_MANDATORY_HIGH_RID              = 0x00003000
	SECURITY_MANDATORY_SYSTEM_RID            = 0x00004000
	SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000
)

// 已知的受保护系统进程列表（扩展版）
var protectedProcessNames = map[string]bool{
	"system":          true, // PID 4
	"registry":        true,
	"smss.exe":        true, // Session Manager
	"csrss.exe":       true, // Client/Server Runtime (受严格保护)
	"wininit.exe":     true, // Windows Initialization
	"services.exe":    true, // Service Control Manager
	"lsass.exe":       true, // Local Security Authority (非常敏感)
	"winlogon.exe":    true, // Windows Logon Process
	"fontdrvhost.exe": true, // Font Driver Host
	"dwm.exe":         true, // Desktop Window Manager
	"audiodg.exe":     true, // Windows Audio Device Graph Isolation
	"conhost.exe":     true, // Console Window Host (某些情况下受保护)
	"ntoskrnl.exe":    true, // NT Kernel
	"hal.dll":         true,
}

// GetProcessIntegrityLevel 获取进程的完整性级别
// 返回值: 完整性级别RID (如 SECURITY_MANDATORY_SYSTEM_RID)
func GetProcessIntegrityLevel(pid uint32) (uint32, error) {
	// 1. 打开进程句柄 (只需要 QUERY_INFORMATION 权限)
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return 0, fmt.Errorf("OpenProcess failed for PID %d: %w", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	// 2. 打开进程令牌
	var hToken windows.Token
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_QUERY, &hToken)
	if err != nil {
		return 0, fmt.Errorf("OpenProcessToken failed: %w", err)
	}
	defer hToken.Close()

	// 3. 获取令牌完整性级别 (TOKEN_MANDATORY_LABEL)
	var returnedLen uint32
	var tokenInfo [256]byte // 缓冲区

	err = windows.GetTokenInformation(
		hToken,
		windows.TokenIntegrityLevel, // 25 = TokenIntegrityLevel
		&tokenInfo[0],
		uint32(len(tokenInfo)),
		&returnedLen,
	)
	if err != nil {
		return 0, fmt.Errorf("GetTokenInformation failed: %w", err)
	}

	// 4. 解析 TOKEN_MANDATORY_LABEL 结构
	type TOKEN_MANDATORY_LABEL struct {
		Label windows.SIDAndAttributes
	}
	label := (*TOKEN_MANDATORY_LABEL)(unsafe.Pointer(&tokenInfo[0]))

	// 5. 获取 SID 的最后一个子权限 (SubAuthority)，这就是完整性级别
	sid := label.Label.Sid
	subAuthCount := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(sid)) + 1))
	if subAuthCount == 0 {
		return 0, fmt.Errorf("invalid SID")
	}

	// 最后一个 SubAuthority 就是完整性级别
	subAuthPtr := uintptr(unsafe.Pointer(sid)) + 8 + uintptr(subAuthCount-1)*4
	integrityLevel := *(*uint32)(unsafe.Pointer(subAuthPtr))

	return integrityLevel, nil
}

// IsProtectedProcess 检查进程是否是受保护的系统进程
// 通过进程名检查（快速预筛选）
func IsProtectedProcess(processName string) bool {
	lowerName := strings.ToLower(processName)
	return protectedProcessNames[lowerName]
}

// IsSafeToScan 综合判断进程是否安全可扫描
// 返回 true 表示安全可以扫描, false 表示应该跳过
func IsSafeToScan(pid uint32, processName string) bool {
	// 1. PID 0 和 4 是内核进程，绝对不能扫描
	if pid == 0 || pid == 4 {
		return false
	}

	// 2. 检查进程名黑名单（快速预筛选）
	if IsProtectedProcess(processName) {
		return false
	}

	// 3. 检查完整性级别
	integrityLevel, err := GetProcessIntegrityLevel(pid)
	if err != nil {
		// 如果无法获取完整性级别（可能是权限不足或进程已退出），
		// 为了安全起见，跳过该进程
		return false
	}

	// 4. 跳过 System 级别及以上的进程
	// System (0x4000) 和 Protected (0x5000) 级别的进程通常是操作系统核心组件
	if integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID {
		return false
	}

	// 5. 其他情况认为安全可扫描
	return true
}

// GetIntegrityLevelName 获取完整性级别的可读名称（用于调试）
func GetIntegrityLevelName(level uint32) string {
	switch level {
	case SECURITY_MANDATORY_UNTRUSTED_RID:
		return "Untrusted"
	case SECURITY_MANDATORY_LOW_RID:
		return "Low"
	case SECURITY_MANDATORY_MEDIUM_RID:
		return "Medium"
	case SECURITY_MANDATORY_MEDIUM_PLUS_RID:
		return "Medium Plus"
	case SECURITY_MANDATORY_HIGH_RID:
		return "High"
	case SECURITY_MANDATORY_SYSTEM_RID:
		return "System"
	case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
		return "Protected Process"
	default:
		return fmt.Sprintf("Unknown (0x%X)", level)
	}
}
