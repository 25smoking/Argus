//go:build windows

package plugins

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/25smoking/Argus/internal/core"
	winsys "github.com/25smoking/Argus/internal/sys/windows"
)

// checkProcessSignature 检查进程文件签名
func (p *ProcessPlugin) checkProcessSignature(exePath string, pid int32) *core.Result {
	if exePath == "" {
		return nil
	}

	lowerExe := strings.ToLower(exePath)
	// Simplified system dir check for classification
	isSystemDir := strings.Contains(lowerExe, "\\windows\\system32\\") || strings.Contains(lowerExe, "\\windows\\syswow64\\")

	// Determine if we should check this process
	// Policy: Check everything that is NOT in a standard system directory, UNLESS it's a critical system process (anti-masquerading)
	checkIt := !isSystemDir
	if strings.HasPrefix(lowerExe, "c:\\program files") {
		checkIt = true // Check Program Files too, but we will adjust alert level
	}

	// Always check critical system processes to detect masquerading
	baseName := strings.ToLower(filepath.Base(exePath))
	criticals := []string{"svchost.exe", "lsass.exe", "winlogon.exe", "csrss.exe", "cmd.exe", "powershell.exe", "explorer.exe"}
	for _, c := range criticals {
		if baseName == c {
			checkIt = true
			break
		}
	}

	if checkIt {
		err := winsys.VerifySignature(exePath)
		if err != nil {
			errMsg := err.Error()
			level := "high"
			desc := "进程文件数字签名无效"
			advice := "可疑进程未通过微软数字签名验证，可能是恶意软件。"

			// Distinguish between No Signature and Bad Digest
			if strings.Contains(errMsg, "No signature") {
				if isSystemDir {
					// System file with no signature (likely catalog issue or unsigned shim) -> High
					// We keep it High for system files because they SHOULD be verifiable.
					// But user complained about Powershell. We can downgrade to High (from Critical) or Medium?
					// Let's stick to High.
					level = "high"
					desc = "系统进程疑似未签名 (或Catalog验证失败)"
					advice = "系统核心进程未验证通过，可能是Catalog签名问题或已被替换。"
				} else {
					// user application
					level = "info" // Downgrade to Info for general unsigned apps to reduce noise
					desc = "进程可执行文件未签名"
					advice = "该程序没有数字签名，属于常见现象，但需确认其来源。"
				}
			} else if strings.Contains(errMsg, "Bad Digest") || strings.Contains(errMsg, "modified") {
				level = "critical" // Tampering detected!
				desc = "进程文件签名校验失败 (文件被篡改)"
				advice = "严重警告：该文件虽然有签名但校验失败，表明已被篡改！"
			}

			return &core.Result{
				Plugin:      p.Name(),
				Level:       level,
				Description: desc,
				Reference:   fmt.Sprintf("PID: %d, Path: %s, Error: %s", pid, exePath, errMsg),
				Advice:      advice,
			}
		}
	}
	return nil
}

// checkHiddenProcesses 对比快照和 Native API 结果，检测隐藏进程
// visiblePids: 通过 gopsutil/Toolhelp32Snapshot 获取的 PID 列表
func (p *ProcessPlugin) checkHiddenProcesses(visiblePids []int32) []core.Result {
	var results []core.Result

	// 构建 visible set
	visibleMap := make(map[int]bool)
	for _, pid := range visiblePids {
		visibleMap[int(pid)] = true
	}

	// 1. Native API (NtQuerySystemInformation)
	nativeProcs, err := winsys.GetProcessListNative()
	if err == nil {
		for pid, name := range nativeProcs {
			if !visibleMap[pid] && pid != 0 {
				// 忽略早已退出的短暂进程，简单的 double check (if safe)
				// 这里暂时直接报告

				results = append(results, core.Result{
					Plugin:      p.Name(),
					Level:       "critical",
					Description: "发现隐藏进程 (NtQuery 可见，Snapshot 不可见)",
					Reference:   fmt.Sprintf("PID: %d, Name: %s", pid, name),
					Advice:      "进程从标准工具中隐藏，极有可能是 Rootkit。",
				})
			}
		}
	}
	return results
}
