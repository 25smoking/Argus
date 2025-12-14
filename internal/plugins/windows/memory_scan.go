package windows

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/25smoking/Argus/internal/core"
	"github.com/25smoking/Argus/internal/embedded"
	"github.com/25smoking/Argus/internal/pkg/yara_lite"
	winsys "github.com/25smoking/Argus/internal/sys/windows"
	syswindows "golang.org/x/sys/windows"
)

type MemoryScanPlugin struct {
	scanner *yara_lite.Scanner
}

func (p *MemoryScanPlugin) Name() string {
	return "MemoryScan"
}

func (p *MemoryScanPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result

	// 1. 初始化 YARA 规则
	if err := p.initRules(); err != nil {
		return nil, err
	}
	if len(p.scanner.Rules) == 0 {
		return nil, nil // 无规则不扫描
	}

	// 禁用 Windows 错误报告对话框 (防止弹窗)
	_ = syswindows.SetErrorMode(syswindows.SEM_FAILCRITICALERRORS | syswindows.SEM_NOGPFAULTERRORBOX)

	// 2. 获取进程列表
	procs, err := winsys.GetProcessList()
	if err != nil {
		return nil, err
	}

	for _, proc := range procs {
		// 安全检查: 使用完整性级别检查跳过受保护的系统进程
		// 这会跳过 System 级别及以上的进程，避免触发访问违规
		if !winsys.IsSafeToScan(proc.PID, proc.Name) {
			continue
		}

		// 更安全的进程打开 - 添加错误恢复
		hProcess, err := syswindows.OpenProcess(0x0400|0x0010, false, proc.PID) // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
		if err != nil {
			// 进程可能已退出、受保护或权限不足，静默跳过
			continue
		}

		// 使用 defer 确保句柄释放并捕获 panic
		func() {
			defer func() {
				syswindows.CloseHandle(hProcess)
				if r := recover(); r != nil {
					// 捕获任何 panic，防止崩溃
					fmt.Printf("  [WARN] MemoryScan panic on PID %d: %v\n", proc.PID, r)
				}
			}()

			// 获取可执行文件路径
			exePath, err := winsys.GetProcessExePath(proc.PID)
			if err != nil {
				return
			}

			// 3. 数字签名验证 (快速过滤)
			// 虽然签名进程也可能被注入，但我们仍扫描它们（方案3安全优先）
			isSigned := false
			if err := winsys.VerifySignature(exePath); err == nil {
				isSigned = true
			}

			isLoLBin := isKnownLoLBin(proc.Name)

			// 策略:
			// - 如果签名验证失败 (Unsigned or Invalid) -> 扫描内存
			// - 如果是 LoLBin (即使签名有效) -> 扫描内存
			// - 否则 -> 跳过
			if isSigned && !isLoLBin {
				return
			}

			// 4. 扫描进程内存
			detections := p.scanProcessMemory(hProcess, proc.PID, exePath, isSigned)
			results = append(results, detections...)
		}()
	}

	return results, nil
}

func (p *MemoryScanPlugin) initRules() error {
	ruleDir := "assets/malware_rules"
	var err error

	if _, statErr := os.Stat(ruleDir); statErr == nil {
		p.scanner, err = yara_lite.NewScanner(os.DirFS("."), ruleDir)
	} else {
		p.scanner, err = yara_lite.NewScanner(embedded.Content, ruleDir)
	}
	return err
}

func (p *MemoryScanPlugin) scanProcessMemory(hProcess syswindows.Handle, pid uint32, exePath string, isSigned bool) []core.Result {
	var results []core.Result

	regions, err := winsys.ScanMemoryRegions(hProcess)
	if err != nil {
		return nil
	}

	for _, region := range regions {
		// 优化: 只扫描 MEM_PRIVATE (私有内存，常用于存放 Shellcode / 解压的 Payload)
		if region.Type != 0x20000 { // MEM_PRIVATE
			continue
		}

		// 跳过大区域 (>10MB)
		if region.RegionSize > 10*1024*1024 {
			continue
		}

		// 读取内存
		data, err := winsys.ReadProcessMemory(hProcess, region.BaseAddress, int(region.RegionSize))
		if err != nil || len(data) == 0 {
			continue
		}

		// YARA 扫描
		matches := p.scanner.Scan(data)
		if len(matches) > 0 {
			desc := fmt.Sprintf("在进程内存中检测到恶意特征: %s", strings.Join(matches, ", "))
			if isSigned {
				desc += " (注: 进程拥有有效签名，可能是内存注入或 LoLBin)"
			} else {
				desc += " (注: 进程无有效签名)"
			}

			results = append(results, core.Result{
				Plugin:      p.Name(),
				Level:       "critical",
				Description: desc,
				Reference:   fmt.Sprintf("PID=%d, Path=%s, Addr=0x%x, Size=%d bytes", pid, exePath, region.BaseAddress, region.RegionSize),
				Advice:      "进程内存中存在恶意代码特征，可能是无文件攻击或内存注入。建议立即隔离该进程并 dump 内存进行深度分析。",
			})
		}
	}
	return results
}

func isKnownLoLBin(name string) bool {
	upper := strings.ToUpper(name)
	lolbins := []string{
		"POWERSHELL.EXE", "CMD.EXE", "RUNDLL32.EXE", "REGSVR32.EXE",
		"CERTUTIL.EXE", "BITSADMIN.EXE", "MSHTA.EXE", "CSCRIPT.EXE",
		"WSCRIPT.EXE", "WINWORD.EXE", "EXCEL.EXE",
	}
	for _, bin := range lolbins {
		if upper == bin {
			return true
		}
	}
	return false
}
