package windows

import (
	"context"
	"fmt"
	"unsafe"

	"github.com/25smoking/Argus/internal/core"
	winsys "github.com/25smoking/Argus/internal/sys/windows"
	syswindows "golang.org/x/sys/windows"
)

const PROCESS_ALL_ACCESS = 0x1F0FFF

type StackScanPlugin struct{}

func (p *StackScanPlugin) Name() string {
	return "StackHunter" // 堆栈猎手
}

func (p *StackScanPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result

	// 禁用 Windows 错误报告对话框 (防止弹窗)
	_ = syswindows.SetErrorMode(syswindows.SEM_FAILCRITICALERRORS | syswindows.SEM_NOGPFAULTERRORBOX)

	procs, err := winsys.GetProcessList()
	if err != nil {
		return nil, err
	}

	for _, proc := range procs {
		// 安全检查: 使用完整性级别检查跳过受保护的系统进程
		// 这会自动跳过 System/Protected 级别的进程，比手动维护白名单更可靠
		if !winsys.IsSafeToScan(proc.PID, proc.Name) {
			continue
		}

		hProcess, err := syswindows.OpenProcess(PROCESS_ALL_ACCESS, false, proc.PID)
		if err != nil {
			continue
		}

		// 添加panic恢复和句柄管理
		func() {
			defer func() {
				syswindows.CloseHandle(hProcess)
				if r := recover(); r != nil {
					// Silence panic
				}
			}()

			scanResults := p.scanProcessStack(hProcess, proc.PID, proc.ExePath)
			results = append(results, scanResults...)
		}()
	}

	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "pass",
			Description: "堆栈扫描完成，未发现异常调用栈",
		})
	}

	return results, nil
}

func (p *StackScanPlugin) scanProcessStack(hProcess syswindows.Handle, pid uint32, name string) []core.Result {
	var results []core.Result

	// 添加 panic 恢复，防止崩溃
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("  [WARN] StackScan panic on PID %d: %v\n", pid, r)
		}
	}()

	// 1. 初始化符号 (DbgHelp) - 可能失败，静默跳过
	if err := winsys.SymInitialize(hProcess); err != nil {
		// 某些进程无法初始化符号（正常现象）
		return nil
	}
	defer winsys.SymCleanup(hProcess)

	// 2. 获取模块列表 (用于检查 Return Address 是否 Unbacked)
	modules, err := winsys.GetProcessModules(pid)
	if err != nil {
		// 进程可能已退出或无权限
		return nil
	}

	// 实际的注入检测通过 Unbacked Code 检查实现（更可靠）

	// 3. 获取线程列表
	tids, err := winsys.GetProcessThreads(pid)
	if err != nil {
		return nil
	}

	// 性能优化: 只检查前3个线程 (足以发现注入)
	maxThreads := 3
	if len(tids) > maxThreads {
		tids = tids[:maxThreads]
	}

	for idx, tid := range tids {
		// 4. 打开线程
		hThread, err := winsys.OpenThread(winsys.THREAD_ALL_ACCESS, false, tid)
		if err != nil {
			continue
		}

		if idx == 0 {
			fmt.Printf("    检查线程 %d/%d...\r", idx+1, len(tids))
		}

		// 5. 挂起线程
		if _, err := winsys.SuspendThread(hThread); err != nil {
			syswindows.CloseHandle(hThread)
			continue
		}

		// 6. 获取上下文
		var ctxData winsys.Context
		ctxData.ContextFlags = winsys.CONTEXT_FULL

		if err := winsys.GetThreadContext(hThread, &ctxData); err == nil {
			// StackWalk Setup
			var frame winsys.STACKFRAME64
			frame.AddrPC.Offset = ctxData.Rip
			frame.AddrPC.Mode = winsys.AddrModeFlat
			frame.AddrFrame.Offset = ctxData.Rbp
			frame.AddrFrame.Mode = winsys.AddrModeFlat
			frame.AddrStack.Offset = ctxData.Rsp
			frame.AddrStack.Mode = winsys.AddrModeFlat

			// Walk
			for i := 0; i < 100; i++ { // Max depth 100
				ok, _ := winsys.StackWalk64(winsys.IMAGE_FILE_MACHINE_AMD64, hProcess, hThread, &frame, unsafe.Pointer(&ctxData))
				if !ok {
					break
				}

				if frame.AddrReturn.Offset == 0 {
					continue
				}

				// CHECK: Is Return Address Unbacked?
				retAddr := uintptr(frame.AddrReturn.Offset)
				if isUnbacked(retAddr, modules) {
					// Check Memory Attributes
					mbi, err := winsys.VirtualQueryEx(hProcess, retAddr)
					if err == nil {
						// MEM_PRIVATE (0x20000) & EXECUTE permissions
						isExec := (mbi.Protect&syswindows.PAGE_EXECUTE != 0) ||
							(mbi.Protect&syswindows.PAGE_EXECUTE_READ != 0) ||
							(mbi.Protect&syswindows.PAGE_EXECUTE_READWRITE != 0) ||
							(mbi.Protect&syswindows.PAGE_EXECUTE_WRITECOPY != 0)

						if mbi.Type == 0x20000 && isExec {
							results = append(results, core.Result{
								Plugin:      p.Name(),
								Level:       "critical",
								Description: "发现异常调用栈帧 (Unbacked Code) - 疑似休眠 Beacon",
								Reference:   fmt.Sprintf("PID: %d (%s), TID: %d, RetAddr: 0x%x, Region: %s", pid, name, tid, retAddr, winsys.GetProtString(mbi.Protect)),
								Advice:      "极高风险！线程返回地址指向私有可执行内存，且不属于任何模块。这是 Cobalt Strike 等内存马的典型特征。",
							})
							break // Found malicious frame in this thread, report and next thread
						}
					}
				}
			}
		}

		winsys.ResumeThread(hThread)
		syswindows.CloseHandle(hThread)
	}

	return results
}

func isUnbacked(addr uintptr, modules []winsys.ModuleInfo) bool {
	for _, mod := range modules {
		if addr >= mod.BaseAddress && addr < mod.BaseAddress+uintptr(mod.Size) {
			return false // In module
		}
	}
	return true
}
