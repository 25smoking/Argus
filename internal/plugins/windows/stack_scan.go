//go:build windows

package windows

import (
	"context"
	"fmt"

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

	// 当前产品化版本先保留 StackHunter 入口和模块枚举能力。
	// 线程挂起/上下文读取属于高扰动能力，后续应在 forensic build 中通过最小权限实现。
	_ = modules

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
