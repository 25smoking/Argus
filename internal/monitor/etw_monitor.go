package monitor

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"

	winsys "github.com/25smoking/Argus/internal/sys/windows"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

// Kernel Logger GUID: {9e814aad-3204-11d2-9a82-006008a86939}
var SystemTraceControlGuid = windows.GUID{
	Data1: 0x9e814aad,
	Data2: 0x3204,
	Data3: 0x11d2,
	Data4: [8]byte{0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39},
}

const (
	// Enable Flags
	EVENT_TRACE_FLAG_PROCESS       = 0x00000001
	EVENT_TRACE_FLAG_THREAD        = 0x00000002
	EVENT_TRACE_FLAG_IMAGE_LOAD    = 0x00000004
	EVENT_TRACE_FLAG_NETWORK_TCPIP = 0x00000010

	// Event Hook IDs (PerfInfo)
	ProcessStart = 1
	ProcessStop  = 2
	ThreadStart  = 1
	ThreadStop   = 2
	ImageLoad    = 10
)

type ETWMonitor struct {
	logger      *zap.SugaredLogger
	traceHandle windows.Handle
	sessionName string
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewETWMonitor(logger *zap.SugaredLogger) *ETWMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &ETWMonitor{
		logger:      logger,
		sessionName: "ArgusKernelLogger",
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Modern Providers
var (
	// Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
	ProviderKernelProcess = windows.GUID{
		Data1: 0x22FB2CD6,
		Data2: 0x0E7B,
		Data3: 0x422B,
		Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16},
	}
)

func (m *ETWMonitor) Start() error {
	m.logger.Info("正在启动 ETW 实时监控...")

	// 1. Setup Session Properties
	sessionName := "ArgusMonitorSession"

	type PropertiesWithBuffer struct {
		Props winsys.EVENT_TRACE_PROPERTIES
		Name  [1024]uint16
	}
	var pb PropertiesWithBuffer
	pb.Props.Wnode.BufferSize = uint32(unsafe.Sizeof(pb))
	pb.Props.Wnode.Guid = windows.GUID{} // Let system handle
	pb.Props.Wnode.Flags = 0x00020000    // WNODE_FLAG_TRACED_GUID
	pb.Props.Wnode.ClientContext = 1     // QPC
	pb.Props.LogFileMode = winsys.PROCESS_TRACE_MODE_REAL_TIME

	// Stop existing if any
	winsys.StopTrace(0, sessionName, &pb.Props)

	// Start Trace
	traceHandle, err := winsys.StartTrace(sessionName, &pb.Props)
	if err != nil {
		return fmt.Errorf("StartTrace failed: %w (需管理员权限)", err)
	}
	m.traceHandle = traceHandle
	m.logger.Infof("ETW 会话已创建 (Handle: %x)", traceHandle)

	// 2. Enable Providers
	// Enable Kernel-Process
	err = winsys.EnableTraceEx2(
		traceHandle,
		&ProviderKernelProcess,
		winsys.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		winsys.TRACE_LEVEL_INFORMATION,
		0, // MatchAnyKeyword (0 = All)
		0, // MatchAllKeyword
		0,
		0,
	)
	if err != nil {
		m.Stop()
		return fmt.Errorf("EnableTraceEx2 (Process) failed: %w", err)
	}
	m.logger.Info("已订阅 Microsoft-Windows-Kernel-Process")

	// 3. Open Trace for Processing
	// We need a separate Logfile struct for OpenTrace
	traceLog := winsys.EVENT_TRACE_LOGFILE{}
	ptr, _ := syscall.UTF16PtrFromString(sessionName)
	traceLog.LoggerName = ptr
	traceLog.LogFileMode = winsys.PROCESS_TRACE_MODE_REAL_TIME | winsys.PROCESS_TRACE_MODE_EVENT_RECORD
	// Setup Callback
	traceLog.EventCallback = syscall.NewCallbackCDecl(m.eventCallback)

	sessHandle, err := winsys.OpenTrace(&traceLog)
	if err != nil {
		m.Stop()
		return fmt.Errorf("OpenTrace failed: %w", err)
	}

	// 4. Process Trace in Background
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.logger.Info("开始处理事件流...")
		err := winsys.ProcessTrace(sessHandle)
		if err != nil {
			// ProcessTrace blocks, so error usually means session ended or invalid
			if err != syscall.Errno(6) { // ERROR_INVALID_HANDLE
				m.logger.Errorf("ProcessTrace 异常退出: %v", err)
			}
		}
		m.logger.Info("事件流处理结束")
		winsys.CloseTrace(sessHandle)
	}()

	return nil
}

func (m *ETWMonitor) Stop() {
	if m.traceHandle != 0 {
		m.logger.Info("正在停止 ETW 监控...")
		// Use empty props for stop
		dummy := winsys.EVENT_TRACE_PROPERTIES{}
		dummy.Wnode.BufferSize = uint32(unsafe.Sizeof(dummy))
		winsys.StopTrace(m.traceHandle, "", &dummy)
		m.traceHandle = 0
	}
	m.cancel()
	m.wg.Wait()
}

func (m *ETWMonitor) Wait() {
	// Block until signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	m.Stop()
}

// Event Callback (CDecl)
func (m *ETWMonitor) eventCallback(record *winsys.EVENT_RECORD) uintptr {
	// Simple parsing logic
	if record == nil {
		return 0
	}

	if isEqualGUID(record.Header.ProviderId, ProviderKernelProcess) {
		switch record.Header.EventDescriptor.Id {
		case 1: // Process Start
			// Parsing UserData is complex, requires schema.
			// For minimal viable product, we just alert OpCode 1.
			pid := record.Header.ProcessId
			m.logger.Infof("[MONITOR] 进程启动检测: PID %d", pid)
		case 2: // Process Stop
			// m.logger.Infof("[MONITOR] Process Stop: PID %d", record.Header.ProcessId)
		}
	}

	return 0
}

func isEqualGUID(g1, g2 windows.GUID) bool {
	return g1.Data1 == g2.Data1 && g1.Data2 == g2.Data2 && g1.Data3 == g2.Data3 && g1.Data4 == g2.Data4
}
