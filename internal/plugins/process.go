package plugins

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/25smoking/Argus/internal/config"
	"github.com/25smoking/Argus/internal/core"
	"github.com/shirou/gopsutil/v3/process"
)

type ProcessPlugin struct {
	rules *config.ProcessRules
}

func (p *ProcessPlugin) Name() string {
	return "ProcessScan"
}

func (p *ProcessPlugin) Run(ctx context.Context, cfg *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result

	// 加载外部规则
	rules, err := config.LoadProcessRules(config.GetConfigPath("process_rules.yaml"))
	if err != nil {
		fmt.Printf("Warning: Failed to load process rules: %v. Using minimal detection.\n", err)
		// 继续运行，但检测能力受限
	} else {
		fmt.Printf("已加载进程检测规则: %d 个反弹Shell特征, %d 个PowerShell特征, %d 个Office父子进程规则, %d 个通用父子进程规则, %d 个命令行行为规则, %d 个系统进程路径规则\n",
			len(rules.ReverseShells), len(rules.MaliciousPowerShell),
			len(rules.OfficeSpawnedShells.ChildProcesses), len(rules.ParentChildPatterns),
			len(rules.CommandPatterns), len(rules.SuspiciousSystemProc))
	}
	p.rules = rules

	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	for _, proc := range procs {
		name, _ := proc.Name()
		exe, _ := proc.Exe()
		cmdline, _ := proc.Cmdline()
		pid := proc.Pid

		// 1. 检查反弹 Shell 特征
		if p.rules != nil {
			if res := p.checkReverseShell(cmdline, pid); res != nil {
				results = append(results, *res)
			}
			results = append(results, p.checkCommandPatterns(name, cmdline, pid)...)
		}

		// 2. Windows: PowerShell 恶意利用
		if p.rules != nil {
			if res := p.checkMaliciousPowershell(cmdline, pid); res != nil {
				results = append(results, *res)
			}
		}

		// 3. Windows: 办公软件启动 Shell
		ppid, _ := proc.Ppid()
		if ppid > 0 && p.rules != nil {
			parent, err := process.NewProcess(ppid)
			if err == nil {
				pName, _ := parent.Name()
				if res := p.checkOfficeSpawning(pName, name, pid); res != nil {
					results = append(results, *res)
				}
				results = append(results, p.checkParentChildPatterns(pName, name, pid)...)
			}
		}

		// 4. Windows: 伪装的系统进程
		if p.rules != nil {
			if res := p.checkFakeSystemProcess(name, exe, pid); res != nil {
				results = append(results, *res)
			}
		}

		// 5. 检查 CPU/内存 占用过高的进程
		cpuPercent, _ := proc.CPUPercent()
		memPercent, _ := proc.MemoryPercent()

		if cpuPercent > 80.0 {
			results = append(results, core.Result{
				Plugin:      p.Name(),
				Level:       "medium",
				Description: "进程 CPU 占用过高 (>80%)",
				Reference:   fmt.Sprintf("%s (PID: %d) - CPU: %.2f%%", name, pid, cpuPercent),
				Advice:      "请确认是否为挖矿病毒。",
			})
		}

		if memPercent > 50.0 {
			results = append(results, core.Result{
				Plugin:      p.Name(),
				Level:       "low",
				Description: "进程内存占用过高 (>50%)",
				Reference:   fmt.Sprintf("%s (PID: %d) - MEM: %.2f%%", name, pid, memPercent),
			})
		}

		// 5.5 数字签名验证 (Windows only)
		if res := p.checkProcessSignature(exe, pid); res != nil {
			results = append(results, *res)
		}

		// 6. 检查已删除的可执行文件
		if strings.Contains(exe, " (deleted)") {
			results = append(results, core.Result{
				Plugin:      p.Name(),
				Level:       "high",
				Description: "进程对应的可执行文件已被删除",
				Reference:   fmt.Sprintf("%s (PID: %d) - EXE: %s", name, pid, exe),
				Advice:      "恶意软件常在运行后删除自身以隐藏痕迹。",
			})
		}
	}

	// 7. 检测隐藏进程 (Windows: NtQuery/BruteForce vs Snapshot)
	var visiblePids []int32
	for _, proc := range procs {
		visiblePids = append(visiblePids, proc.Pid)
	}
	if hiddenResults := p.checkHiddenProcesses(visiblePids); len(hiddenResults) > 0 {
		results = append(results, hiddenResults...)
	}

	// Pass 状态
	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "pass",
			Description: "进程扫描完成，未发现异常进程",
			Reference:   fmt.Sprintf("已检查 %d 个进程", len(procs)),
		})
	}

	return results, nil
}

func (p *ProcessPlugin) checkReverseShell(cmd string, pid int32) *core.Result {
	if p.rules == nil || len(p.rules.ReverseShells) == 0 {
		return nil
	}

	for _, pattern := range p.rules.ReverseShells {
		if matchProcessPattern(pattern.Pattern, cmd) {
			return &core.Result{
				Plugin:      p.Name(),
				Level:       pattern.Level,
				Description: pattern.Description,
				Reference:   fmt.Sprintf("PID: %d, CMD: %s", pid, cmd),
				Advice:      "极高风险！请立即检查并终止该进程。",
				Score:       scoreForProcessLevel(pattern.Level),
				Confidence:  85,
				RuleName:    "reverse_shell/" + pattern.Pattern,
				RuleSource:  "process_rules.yaml",
			}
		}
	}
	return nil
}

func (p *ProcessPlugin) checkMaliciousPowershell(cmd string, pid int32) *core.Result {
	if p.rules == nil || len(p.rules.MaliciousPowerShell) == 0 {
		return nil
	}

	cmdLower := strings.ToLower(cmd)
	hits := 0
	var matchedPatterns []string

	for _, pattern := range p.rules.MaliciousPowerShell {
		// 检查是否是 PowerShell 相关进程
		isPowershell := false
		if len(pattern.Keywords) > 0 {
			for _, kw := range pattern.Keywords {
				if strings.Contains(cmdLower, kw) {
					isPowershell = true
					break
				}
			}
		} else {
			isPowershell = true
		}

		if isPowershell && matchProcessPattern(pattern.Pattern, cmdLower) {
			hits++
			matchedPatterns = append(matchedPatterns, pattern.Description)
		}
	}

	// 命中两个以上关键词视为高危
	if hits >= 2 {
		return &core.Result{
			Plugin:      p.Name(),
			Level:       "critical",
			Description: fmt.Sprintf("发现可疑 PowerShell 攻击行为 (%s)", strings.Join(matchedPatterns, ", ")),
			Reference:   fmt.Sprintf("PID: %d, CMD: %s", pid, cmd),
			Advice:      "检测到多个攻击特征，极有可能是无文件攻击。",
			Score:       92,
			Confidence:  85,
			RuleName:    "powershell/multi_indicator",
			RuleSource:  "process_rules.yaml",
		}
	}

	return nil
}

func (p *ProcessPlugin) checkOfficeSpawning(parentName, childName string, pid int32) *core.Result {
	if p.rules == nil || len(p.rules.OfficeSpawnedShells.ParentProcesses) == 0 {
		return nil
	}

	parent := strings.ToLower(parentName)
	child := strings.ToLower(childName)

	// 检查是否是 Office 应用
	isOffice := false
	for _, officeName := range p.rules.OfficeSpawnedShells.ParentProcesses {
		if parent == strings.ToLower(officeName) {
			isOffice = true
			break
		}
	}

	if !isOffice {
		return nil
	}

	// 检查是否启动了 Shell
	for _, childPattern := range p.rules.OfficeSpawnedShells.ChildProcesses {
		if child == strings.ToLower(childPattern.Process) {
			return &core.Result{
				Plugin:      p.Name(),
				Level:       childPattern.Level,
				Description: childPattern.Description,
				Reference:   fmt.Sprintf("Parent: %s -> Child: %s (PID: %d)", parentName, childName, pid),
				Score:       scoreForProcessLevel(childPattern.Level),
				Confidence:  80,
				RuleName:    "office_spawn/" + childPattern.Process,
				RuleSource:  "process_rules.yaml",
			}
		}
	}

	return nil
}

func (p *ProcessPlugin) checkParentChildPatterns(parentName, childName string, pid int32) []core.Result {
	if p.rules == nil || len(p.rules.ParentChildPatterns) == 0 {
		return nil
	}
	var results []core.Result
	for _, rule := range p.rules.ParentChildPatterns {
		if matchProcessPattern(rule.Parent, parentName) && matchProcessPattern(rule.Child, childName) {
			results = append(results, core.Result{
				Plugin:      p.Name(),
				Level:       defaultLevel(rule.Level, "medium"),
				Description: rule.Description,
				Reference:   fmt.Sprintf("Parent: %s -> Child: %s (PID: %d)", parentName, childName, pid),
				Advice:      "父子进程关系命中可疑行为规则，请结合命令行、网络连接和落地文件复核。",
				Score:       scoreForProcessLevel(rule.Level),
				Confidence:  78,
				RuleName:    "parent_child/" + rule.Parent + "->" + rule.Child,
				RuleSource:  "process_rules.yaml",
				MITRE:       rule.MITRE,
			})
		}
	}
	return results
}

func (p *ProcessPlugin) checkCommandPatterns(processName, cmd string, pid int32) []core.Result {
	if p.rules == nil || len(p.rules.CommandPatterns) == 0 || strings.TrimSpace(cmd) == "" {
		return nil
	}
	var results []core.Result
	for _, rule := range p.rules.CommandPatterns {
		if rule.Process != "" && !matchProcessPattern(rule.Process, processName) {
			continue
		}
		if matchProcessPattern(rule.Pattern, cmd) {
			name := rule.Name
			if name == "" {
				name = rule.Pattern
			}
			results = append(results, core.Result{
				Plugin:      p.Name(),
				Level:       defaultLevel(rule.Level, "medium"),
				Description: rule.Description,
				Reference:   fmt.Sprintf("Process: %s, PID: %d, CMD: %s", processName, pid, cmd),
				Advice:      "命令行命中可疑行为规则，请结合父子进程、网络连接、文件落点和用户会话复核。",
				Score:       scoreForProcessLevel(rule.Level),
				Confidence:  76,
				RuleName:    "command_pattern/" + name,
				RuleSource:  "process_rules.yaml",
				MITRE:       rule.MITRE,
			})
		}
	}
	return results
}

func (p *ProcessPlugin) checkFakeSystemProcess(name, exePath string, pid int32) *core.Result {
	if p.rules == nil || len(p.rules.SuspiciousSystemProc) == 0 {
		return nil
	}

	nameLower := strings.ToLower(name)
	pathLower := strings.ToLower(exePath)

	for _, sysProc := range p.rules.SuspiciousSystemProc {
		if nameLower == strings.ToLower(sysProc.Name) {
			requiredPath := strings.ToLower(sysProc.RequiredPath)
			if !strings.Contains(pathLower, requiredPath) {
				return &core.Result{
					Plugin:      p.Name(),
					Level:       sysProc.Level,
					Description: sysProc.Description,
					Reference:   fmt.Sprintf("%s 运行在 %s", name, exePath),
					Advice:      "系统进程通常位于 C:\\Windows\\System32，其他路径极为可疑。",
					Score:       scoreForProcessLevel(sysProc.Level),
					Confidence:  80,
					RuleName:    "system_process_path/" + sysProc.Name,
					RuleSource:  "process_rules.yaml",
				}
			}
		}
	}

	return nil
}

func matchProcessPattern(pattern, value string) bool {
	if pattern == "" {
		return false
	}
	re, err := regexp.Compile(pattern)
	if err == nil {
		return re.MatchString(value)
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
}

func scoreForProcessLevel(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 95
	case "high":
		return 82
	case "medium":
		return 60
	case "low":
		return 35
	default:
		return 50
	}
}
