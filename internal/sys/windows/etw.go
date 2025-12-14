package winsys

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procStartTraceW    = modAdvapi32.NewProc("StartTraceW")
	procControlTraceW  = modAdvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = modAdvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = modAdvapi32.NewProc("OpenTraceW")
	procProcessTrace   = modAdvapi32.NewProc("ProcessTrace")
	procCloseTrace     = modAdvapi32.NewProc("CloseTrace")
)

const (
	PROCESS_TRACE_MODE_REAL_TIME        = 0x00000100
	PROCESS_TRACE_MODE_EVENT_RECORD     = 0x10000000
	EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
	EVENT_CONTROL_CODE_ENABLE_PROVIDER  = 1
	TRACE_LEVEL_INFORMATION             = 4
	EVENT_TRACE_CONTROL_STOP            = 1
)

type EVENT_TRACE_PROPERTIES struct {
	Wnode               WNODE_HEADER
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type WNODE_HEADER struct {
	BufferSize        uint32
	ProviderId        uint32
	HistoricalContext uint64
	TimeStamp         int64
	Guid              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

type EVENT_TRACE_LOGFILE struct {
	LogFileName    *uint16
	LoggerName     *uint16
	CurrentTime    int64
	BuffersRead    uint32
	LogFileMode    uint32
	CurrentEvent   EVENT_TRACE
	LogfileHeader  TRACE_LOGFILE_HEADER
	BufferCallback uintptr
	BufferSize     uint32
	Filled         uint32
	EventsLost     uint32
	EventCallback  uintptr // PEVENT_RECORD_CALLBACK
	IsKernelTrace  uint32
	Context        unsafe.Pointer
}

type EVENT_TRACE struct {
	Header           EVENT_TRACE_HEADER
	InstanceId       uint32
	ParentInstanceId uint32
	ParentGuid       windows.GUID
	MofData          unsafe.Pointer
	MofLength        uint32
	Union            uint32
}

type EVENT_TRACE_HEADER struct {
	Size           uint16
	FieldTypeFlags uint16
	Type           uint8
	Level          uint8
	Version        uint16
	ThreadId       uint32
	ProcessId      uint32
	TimeStamp      int64
	Guid           windows.GUID
	KernelTime     uint32
	UserTime       uint32
}

type TRACE_LOGFILE_HEADER struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	StartBuffers       uint32
	PointerSize        uint32
	EventsLost         uint32
	CpuSpeedInMHz      uint32
	LoggerName         *uint16
	LogFileName        *uint16
	TimeZone           TIME_ZONE_INFORMATION
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

type TIME_ZONE_INFORMATION struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate SYSTEMTIME
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate SYSTEMTIME
	DaylightBias int32
}

type SYSTEMTIME struct {
	Year         uint16
	Month        uint16
	DayOfWeek    uint16
	Day          uint16
	Hour         uint16
	Minute       uint16
	Second       uint16
	Milliseconds uint16
}

type EVENT_RECORD struct {
	Header            EVENT_HEADER
	BufferContext     ETW_BUFFER_CONTEXT
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

type EVENT_HEADER struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      windows.GUID
	EventDescriptor EVENT_DESCRIPTOR
	// ... union ...
	KernelTime uint32
	UserTime   uint32
	ActivityId windows.GUID
}

type EVENT_DESCRIPTOR struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type ETW_BUFFER_CONTEXT struct {
	ProcessorNumber uint8
	Alignment       uint8
	LoggerId        uint16
}

// StartTraceW
func StartTrace(sessionName string, props *EVENT_TRACE_PROPERTIES) (windows.Handle, error) {
	namePtr, _ := syscall.UTF16PtrFromString(sessionName)
	var handle windows.Handle
	ret, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(props)),
	)
	if ret != 0 {
		// ALREADY_EXISTS = 183. We might want to handle it (stop and restart).
		return 0, syscall.Errno(ret)
	}
	return handle, nil
}

// ControlTraceW (Code 1 = Stop)
func StopTrace(handle windows.Handle, sessionName string, props *EVENT_TRACE_PROPERTIES) error {
	namePtr := uintptr(0)
	if sessionName != "" {
		ptr, _ := syscall.UTF16PtrFromString(sessionName)
		namePtr = uintptr(unsafe.Pointer(ptr))
	} else {
		// If session name is empty, handle is used
	}

	// Either handle or session name must be valid.
	ret, _, _ := procControlTraceW.Call(
		uintptr(handle),
		namePtr,
		uintptr(unsafe.Pointer(props)),
		uintptr(EVENT_TRACE_CONTROL_STOP),
	)
	if ret != 0 {
		return syscall.Errno(ret)
	}
	return nil
}

// EnableTraceEx2
func EnableTraceEx2(traceHandle windows.Handle, providerId *windows.GUID, controlCode uint32, level uint8, matchAnyKeyword uint64, matchAllKeyword uint64, timeout uint32, enableParameters uintptr) error {
	ret, _, _ := procEnableTraceEx2.Call(
		uintptr(traceHandle),
		uintptr(unsafe.Pointer(providerId)),
		uintptr(controlCode),
		uintptr(level),
		uintptr(matchAnyKeyword),
		uintptr(matchAllKeyword),
		uintptr(timeout),
		enableParameters,
	)
	if ret != 0 {
		return syscall.Errno(ret)
	}
	return nil
}

// OpenTraceW
func OpenTrace(logfile *EVENT_TRACE_LOGFILE) (windows.Handle, error) {
	ret, _, _ := procOpenTraceW.Call(uintptr(unsafe.Pointer(logfile)))
	if ret == 0xFFFFFFFFFFFFFFFF { // INVALID_HANDLE_VALUE equivalent for trace? Usually large number
		return 0, syscall.GetLastError()
	}
	// Note: OpenTrace returns a Handle on success. On error it might return generic error handle.
	// Actually return type is TRACEHANDLE (uint64).
	return windows.Handle(ret), nil
}

// ProcessTrace
func ProcessTrace(handle windows.Handle) error {
	handles := []windows.Handle{handle}
	ret, _, _ := procProcessTrace.Call(
		uintptr(unsafe.Pointer(&handles[0])),
		1, // handle count
		0,
		0,
	)
	if ret != 0 {
		return syscall.Errno(ret)
	}
	return nil
}

// CloseTrace
func CloseTrace(handle windows.Handle) error {
	ret, _, _ := procCloseTrace.Call(uintptr(handle))
	if ret != 0 {
		return syscall.Errno(ret)
	}
	return nil
}
