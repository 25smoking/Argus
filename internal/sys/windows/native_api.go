//go:build windows
// +build windows

package winsys

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ======================= 进程相关 API =======================

// ProcessInfo 进程信息结构
type ProcessInfo struct {
	PID       uint32
	PPID      uint32
	Name      string
	ExePath   string
	ThreadCnt uint32
}

// GetProcessList 使用 CreateToolhelp32Snapshot 获取进程列表
// 替代 tasklist / wmic process 命令
func GetProcessList() ([]ProcessInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var processes []ProcessInfo
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, fmt.Errorf("Process32First failed: %w", err)
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		processes = append(processes, ProcessInfo{
			PID:       entry.ProcessID,
			PPID:      entry.ParentProcessID,
			Name:      name,
			ThreadCnt: entry.Threads,
		})

		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return processes, nil
}

// GetParentProcessID 获取指定进程的父进程 ID
// 替代 wmic process get ParentProcessId
func GetParentProcessID(pid uint32) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err = windows.Process32First(snapshot, &entry); err != nil {
		return 0, err
	}

	for {
		if entry.ProcessID == pid {
			return entry.ParentProcessID, nil
		}
		if err = windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return 0, fmt.Errorf("process %d not found", pid)
}

// GetProcessExePath 获取进程的可执行路径
func GetProcessExePath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// ModuleInfo 模块信息
type ModuleInfo struct {
	Name        string
	BaseAddress uintptr
	Size        uint32
}

// GetProcessModules 获取进程加载的所有模块
func GetProcessModules(pid uint32) ([]ModuleInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var me32 windows.ModuleEntry32
	me32.Size = uint32(unsafe.Sizeof(me32))

	if err := windows.Module32First(snapshot, &me32); err != nil {
		return nil, err
	}

	var modules []ModuleInfo
	for {
		modules = append(modules, ModuleInfo{
			Name:        windows.UTF16ToString(me32.Module[:]),
			BaseAddress: uintptr(me32.ModBaseAddr),
			Size:        me32.ModBaseSize,
		})

		if err := windows.Module32Next(snapshot, &me32); err != nil {
			break
		}
	}
	return modules, nil
}

// ======================= 网络相关 API =======================

// TcpConnection TCP 连接信息
type TcpConnection struct {
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	State      string
	OwnerPID   uint32
}

// TCP 状态常量
var tcpStateNames = map[uint32]string{
	1:  "CLOSED",
	2:  "LISTEN",
	3:  "SYN_SENT",
	4:  "SYN_RECEIVED",
	5:  "ESTABLISHED",
	6:  "FIN_WAIT1",
	7:  "FIN_WAIT2",
	8:  "CLOSE_WAIT",
	9:  "CLOSING",
	10: "LAST_ACK",
	11: "TIME_WAIT",
	12: "DELETE_TCB",
}

// MIB_TCPROW_OWNER_PID 结构
type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_TCPTABLE_OWNER_PID 结构
type MIB_TCPTABLE_OWNER_PID struct {
	NumEntries uint32
	Table      [1]MIB_TCPROW_OWNER_PID
}

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	AF_INET                 = 2
	TCP_TABLE_OWNER_PID_ALL = 5
)

// GetTcpConnections 使用 GetExtendedTcpTable 获取 TCP 连接
// 替代 netstat -an 命令
func GetTcpConnections() ([]TcpConnection, error) {
	var size uint32 = 0

	// 第一次调用获取所需缓冲区大小
	procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1, // sorted
		AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	if size == 0 {
		return nil, fmt.Errorf("failed to get buffer size")
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed with code %d", ret)
	}

	table := (*MIB_TCPTABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
	numEntries := table.NumEntries

	var connections []TcpConnection
	entrySize := unsafe.Sizeof(MIB_TCPROW_OWNER_PID{})

	for i := uint32(0); i < numEntries; i++ {
		offset := unsafe.Sizeof(uint32(0)) + uintptr(i)*entrySize
		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset))

		localIP := ipToString(row.LocalAddr)
		remoteIP := ipToString(row.RemoteAddr)

		stateName := tcpStateNames[row.State]
		if stateName == "" {
			stateName = "UNKNOWN"
		}

		connections = append(connections, TcpConnection{
			LocalAddr:  localIP,
			LocalPort:  ntohs(uint16(row.LocalPort)),
			RemoteAddr: remoteIP,
			RemotePort: ntohs(uint16(row.RemotePort)),
			State:      stateName,
			OwnerPID:   row.OwningPid,
		})
	}

	return connections, nil
}

// ipToString 将 uint32 转换为点分十进制 IP
func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24))
}

// ntohs 网络字节序转主机字节序
func ntohs(n uint16) uint16 {
	return (n>>8)&0xff | (n<<8)&0xff00
}

// ======================= 服务相关 API =======================

// ServiceInfo 服务信息
type ServiceInfo struct {
	Name        string
	DisplayName string
	BinaryPath  string
	StartType   string
	Status      string
}

// 服务状态
var serviceStatusNames = map[uint32]string{
	windows.SERVICE_STOPPED:          "Stopped",
	windows.SERVICE_START_PENDING:    "StartPending",
	windows.SERVICE_STOP_PENDING:     "StopPending",
	windows.SERVICE_RUNNING:          "Running",
	windows.SERVICE_CONTINUE_PENDING: "ContinuePending",
	windows.SERVICE_PAUSE_PENDING:    "PausePending",
	windows.SERVICE_PAUSED:           "Paused",
}

// 服务启动类型
var serviceStartTypes = map[uint32]string{
	windows.SERVICE_AUTO_START:   "Automatic",
	windows.SERVICE_BOOT_START:   "Boot",
	windows.SERVICE_DEMAND_START: "Manual",
	windows.SERVICE_DISABLED:     "Disabled",
	windows.SERVICE_SYSTEM_START: "System",
}

// EnumServices 枚举所有服务
// 替代 sc query / wmic service 命令
func EnumServices() ([]ServiceInfo, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("OpenSCManager failed: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	var needed, returned uint32
	var resumeHandle uint32

	// 第一次调用获取所需大小
	windows.EnumServicesStatusEx(
		scm,
		windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32,
		windows.SERVICE_STATE_ALL,
		nil,
		0,
		&needed,
		&returned,
		&resumeHandle,
		nil,
	)

	if needed == 0 {
		return nil, fmt.Errorf("EnumServicesStatusEx: no buffer needed")
	}

	buf := make([]byte, needed)
	if err := windows.EnumServicesStatusEx(
		scm,
		windows.SC_ENUM_PROCESS_INFO,
		windows.SERVICE_WIN32,
		windows.SERVICE_STATE_ALL,
		&buf[0],
		needed,
		&needed,
		&returned,
		&resumeHandle,
		nil,
	); err != nil {
		return nil, fmt.Errorf("EnumServicesStatusEx failed: %w", err)
	}

	var services []ServiceInfo
	entrySize := unsafe.Sizeof(windows.ENUM_SERVICE_STATUS_PROCESS{})

	for i := uint32(0); i < returned; i++ {
		entry := (*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + uintptr(i)*entrySize))

		svcName := windows.UTF16PtrToString(entry.ServiceName)
		displayName := windows.UTF16PtrToString(entry.DisplayName)

		status := serviceStatusNames[entry.ServiceStatusProcess.CurrentState]
		if status == "" {
			status = "Unknown"
		}

		// 获取服务二进制路径需要单独查询
		binaryPath, startType := getServiceConfig(scm, svcName)

		services = append(services, ServiceInfo{
			Name:        svcName,
			DisplayName: displayName,
			BinaryPath:  binaryPath,
			StartType:   startType,
			Status:      status,
		})
	}

	return services, nil
}

// getServiceConfig 获取服务配置(路径和启动类型)
func getServiceConfig(scm windows.Handle, serviceName string) (string, string) {
	svcNamePtr, _ := windows.UTF16PtrFromString(serviceName)
	svc, err := windows.OpenService(scm, svcNamePtr, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return "", ""
	}
	defer windows.CloseServiceHandle(svc)

	var needed uint32
	windows.QueryServiceConfig(svc, nil, 0, &needed)

	if needed == 0 {
		return "", ""
	}

	buf := make([]byte, needed)
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	if err := windows.QueryServiceConfig(svc, config, needed, &needed); err != nil {
		return "", ""
	}

	binaryPath := windows.UTF16PtrToString(config.BinaryPathName)
	startType := serviceStartTypes[config.StartType]
	if startType == "" {
		startType = "Unknown"
	}

	return binaryPath, startType
}

// IsAdmin checks if the current process has administrative privileges
func IsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

// GetOSVersion 获取Windows版本信息
func GetOSVersion() (string, error) {
	version := windows.RtlGetVersion()

	var osName string
	switch {
	case version.MajorVersion == 10 && version.MinorVersion == 0 && version.BuildNumber >= 22000:
		osName = "11"
	case version.MajorVersion == 10 && version.MinorVersion == 0:
		osName = "10"
	case version.MajorVersion == 6 && version.MinorVersion == 3:
		osName = "8.1"
	case version.MajorVersion == 6 && version.MinorVersion == 2:
		osName = "8"
	case version.MajorVersion == 6 && version.MinorVersion == 1:
		osName = "7"
	case version.MajorVersion == 6 && version.MinorVersion == 0:
		osName = "Vista"
	default:
		osName = fmt.Sprintf("%d.%d", version.MajorVersion, version.MinorVersion)
	}

	return fmt.Sprintf("%s (Build %d)", osName, version.BuildNumber), nil
}
