package windows

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/25smoking/Argus/internal/config"
	"github.com/25smoking/Argus/internal/core"
	winsys "github.com/25smoking/Argus/internal/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type PersistencePlugin struct {
	rules *config.PersistenceRules
}

func (p *PersistencePlugin) Name() string {
	return "WindowsPersistence"
}

func (p *PersistencePlugin) Run(ctx context.Context, scanConfig *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result

	// 加载规则文件
	rules, err := config.LoadPersistenceRules(config.GetConfigPath("persistence_rules.yaml"))
	if err != nil {
		return nil, fmt.Errorf("加载持久化规则失败: %v", err)
	}
	p.rules = rules

	// 1. 注册表启动项检测
	results = append(results, p.checkRegistryAutoStart()...)

	// 2. 注册表劫持检测
	results = append(results, p.checkRegistryHijack()...)

	// 3. 注册表完整性校验
	results = append(results, p.checkRegistryIntegrity()...)

	// 4. Windows 服务检测
	results = append(results, p.checkServices()...)

	// 5. 文件持久化检测
	results = append(results, p.checkFilePersistence()...)

	// 6. 计划任务文件扫描
	results = append(results, p.checkScheduledTasksFiles()...)

	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "pass",
			Description: "持久化检测通过 (注册表, 服务, 文件)",
			Reference:   "未发现可疑的持久化项。",
		})
	}

	return results, nil
}

// ========================== 注册表逻辑 ==========================

func (p *PersistencePlugin) checkRegistryAutoStart() []core.Result {
	var results []core.Result

	for _, rule := range p.rules.RegistryAutoStart {
		root, subPath, err := parseRegistryPath(rule.GetPath())
		if err != nil {
			continue
		}

		// 读取键下的所有值
		values, err := winsys.ReadRegistryValues(root, subPath)
		if err != nil {
			continue
		}

		for _, val := range values {
			// 检查值内容是否可疑
			if p.isSuspiciousCommand(val.Value) {
				results = append(results, core.Result{
					Plugin:      p.Name(),
					Level:       rule.Severity,
					Description: fmt.Sprintf("%s: 发现可疑启动项", rule.Name),
					Reference:   fmt.Sprintf("%s\\%s -> %s", rule.GetPath(), val.Name, val.Value),
					Advice:      "请核实该启动项是否为合法业务。",
				})
			}
		}
	}
	return results
}

func (p *PersistencePlugin) checkRegistryHijack() []core.Result {
	var results []core.Result

	for _, rule := range p.rules.RegistryHijack {
		root, subPath, err := parseRegistryPath(rule.GetPath())
		if err != nil {
			continue
		}

		// 模式 1: 检查子键 (例如 Image File Execution Options)
		if rule.CheckSubkeys {
			subkeys, err := winsys.EnumRegistrySubkeys(root, subPath)
			if err != nil {
				continue
			}

			// 如果指定了目标值名称 (例如 "Debugger")
			if rule.TargetValue != "" {
				for _, sub := range subkeys {
					// 检查 key\sub -> value
					targetPath := subPath + "\\" + sub
					val, err := winsys.ReadRegistryStringValue(root, targetPath, rule.TargetValue)
					if err == nil && val != "" {
						results = append(results, core.Result{
							Plugin:      p.Name(),
							Level:       rule.Severity,
							Description: fmt.Sprintf("%s: 检测到异常 (%s)", rule.Description, sub),
							Reference:   fmt.Sprintf("%s\\%s -> %s=%s", rule.GetPath(), sub, rule.TargetValue, val),
						})
					}
				}
			} else {
				// 如果没有 TargetValue，遍历子键下的内容
				for _, sub := range subkeys {
					vals, _ := winsys.ReadRegistryValues(root, subPath+"\\"+sub)
					for _, v := range vals {
						if p.isSuspiciousCommand(v.Value) {
							results = append(results, core.Result{
								Plugin:      p.Name(),
								Level:       rule.Severity,
								Description: fmt.Sprintf("%s: 子键中发现可疑值", rule.Name),
								Reference:   fmt.Sprintf("%s\\%s -> %s=%s", rule.GetPath(), sub, v.Name, v.Value),
							})
						}
					}
				}
			}
		} else {
			// 模式 2: 直接在键本身检查值
			if rule.ValueName != "" {
				val, err := winsys.ReadRegistryStringValue(root, subPath, rule.ValueName)
				if err == nil && val != "" {
					results = append(results, core.Result{
						Plugin:      p.Name(),
						Level:       rule.Severity,
						Description: rule.Description,
						Reference:   fmt.Sprintf("%s\\%s -> %s", rule.GetPath(), rule.ValueName, val),
					})
				}
			}
		}
	}
	return results
}

func (p *PersistencePlugin) checkRegistryIntegrity() []core.Result {
	var results []core.Result

	for _, rule := range p.rules.RegistryIntegrity {
		root, subPath, err := parseRegistryPath(rule.GetPath())
		if err != nil {
			continue
		}

		// 情况 1: 检查子键寻找特定值 (例如 Print Monitors -> Driver)
		if rule.CheckSubkeys && rule.TargetValue != "" {
			subkeys, _ := winsys.EnumRegistrySubkeys(root, subPath)
			for _, sub := range subkeys {
				fullPath := subPath + "\\" + sub
				val, err := winsys.ReadRegistryStringValue(root, fullPath, rule.TargetValue)
				if err == nil {
					// 检查驱动/DLL是否可疑
					// 使用黑名单正则
					if rule.BlacklistPattern != "" {
						matched, _ := regexp.MatchString(rule.BlacklistPattern, val)
						if matched {
							results = append(results, core.Result{
								Plugin:      p.Name(),
								Level:       rule.Severity,
								Description: rule.Description,
								Reference:   fmt.Sprintf("%s\\%s -> %s=%s", rule.GetPath(), sub, rule.TargetValue, val),
							})
						}
					}
				}
			}
			continue
		}

		// 情况 2: 直接检查值
		if rule.ValueName != "" {
			val, err := winsys.ReadRegistryStringValue(root, subPath, rule.ValueName)
			if err != nil {
				continue // 值不存在
			}

			// 黑名单检查
			if rule.BlacklistPattern != "" {
				matched, _ := regexp.MatchString(rule.BlacklistPattern, val)
				if matched {
					results = append(results, core.Result{
						Plugin:      p.Name(),
						Level:       rule.Severity,
						Description: rule.Description + " (命中黑名单)",
						Reference:   fmt.Sprintf("%s\\%s -> %s", rule.GetPath(), rule.ValueName, val),
					})
				}
			}

			// 预期完全匹配检查
			if rule.ExpectedExact != "" && !strings.EqualFold(val, rule.ExpectedExact) {
				results = append(results, core.Result{
					Plugin:      p.Name(),
					Level:       rule.Severity,
					Description: rule.Description + " (值被修改)",
					Reference:   fmt.Sprintf("预期: %s, 实际: %s", rule.ExpectedExact, val),
				})
			}

			// 预期包含检查
			if rule.ExpectedContains != "" && !strings.Contains(strings.ToLower(val), strings.ToLower(rule.ExpectedContains)) {
				results = append(results, core.Result{
					Plugin:      p.Name(),
					Level:       rule.Severity,
					Description: rule.Description + " (值异常)",
					Reference:   fmt.Sprintf("预期包含: %s, 实际: %s", rule.ExpectedContains, val),
				})
			}
		}
	}
	return results
}

// ========================== 服务逻辑 ==========================

func (p *PersistencePlugin) checkServices() []core.Result {
	var results []core.Result
	services, err := winsys.EnumServices()
	if err != nil {
		fmt.Printf("服务枚举失败: %v\n", err)
		return nil
	}

	for _, svc := range services {
		if svc.Status != "Running" {
			continue
		}

		pathLower := strings.ToLower(svc.BinaryPath)

		// 去除引号
		pathLower = strings.Trim(pathLower, "\"")

		for _, rule := range p.rules.SuspiciousServices {
			matched, _ := regexp.MatchString(rule.Pattern, pathLower)
			if matched {
				results = append(results, core.Result{
					Plugin:      p.Name(),
					Level:       rule.Severity,
					Description: rule.Description,
					Reference:   fmt.Sprintf("服务名: %s, 路径: %s", svc.Name, svc.BinaryPath),
				})
			}
		}
	}
	return results
}

// ========================== 文件逻辑 ==========================

func (p *PersistencePlugin) checkFilePersistence() []core.Result {
	var results []core.Result

	for _, rule := range p.rules.FilePersistence {
		expandedPath := os.ExpandEnv(rule.Path)

		info, err := os.Stat(expandedPath)
		if err != nil {
			continue
		}

		if info.IsDir() {
			// 遍历目录 (例如启动文件夹)
			files, err := os.ReadDir(expandedPath)
			if err != nil {
				continue
			}

			for _, f := range files {
				if f.IsDir() {
					continue
				}

				results = append(results, core.Result{
					Plugin:      p.Name(),
					Level:       rule.Severity,
					Description: fmt.Sprintf("%s 发现项目", rule.Name),
					Reference:   filepath.Join(expandedPath, f.Name()),
				})
			}
		} else {
			// 具体文件
			results = append(results, core.Result{
				Plugin:      p.Name(),
				Level:       rule.Severity,
				Description: fmt.Sprintf("%s 发现文件", rule.Name),
				Reference:   expandedPath,
			})
		}
	}
	return results
}

// ========================== 计划任务逻辑 ==========================

func (p *PersistencePlugin) checkScheduledTasksFiles() []core.Result {
	var results []core.Result
	taskDir := os.ExpandEnv("C:\\Windows\\System32\\Tasks")

	err := filepath.Walk(taskDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		// 读取 XML 内容
		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(contentBytes)

		// 简单检查 XML 中的可疑命令
		if p.isSuspiciousCommand(content) {
			relPath, _ := filepath.Rel(taskDir, path)
			results = append(results, core.Result{
				Plugin:      p.Name(),
				Level:       "high",
				Description: "发现可疑计划任务",
				Reference:   fmt.Sprintf("任务文件: %s", relPath),
				Advice:      "请在任务计划程序中检查该任务的触发器和操作。",
			})
		}
		return nil
	})

	if err != nil {
		// 忽略遍历错误
	}

	return results
}

// ========================== 辅助函数 ==========================

func parseRegistryPath(fullPath string) (registry.Key, string, error) {
	upper := strings.ToUpper(fullPath)
	var root registry.Key
	var sub string

	if strings.HasPrefix(upper, "HKCU") || strings.HasPrefix(upper, "HKEY_CURRENT_USER") {
		root = registry.CURRENT_USER
		if idx := strings.Index(fullPath, "\\"); idx != -1 {
			sub = fullPath[idx+1:]
		}
	} else if strings.HasPrefix(upper, "HKLM") || strings.HasPrefix(upper, "HKEY_LOCAL_MACHINE") {
		root = registry.LOCAL_MACHINE
		if idx := strings.Index(fullPath, "\\"); idx != -1 {
			sub = fullPath[idx+1:]
		}
	} else if strings.HasPrefix(upper, "HKU") || strings.HasPrefix(upper, "HKEY_USERS") {
		root = registry.USERS
		if idx := strings.Index(fullPath, "\\"); idx != -1 {
			sub = fullPath[idx+1:]
		}
	} else {
		return 0, "", fmt.Errorf("未知根键")
	}

	return root, sub, nil
}

func (p *PersistencePlugin) isSuspiciousCommand(cmd string) bool {
	if p.rules == nil {
		return false
	}
	for _, pattern := range p.rules.SuspiciousCommands {
		matched, _ := regexp.MatchString(pattern.Pattern, cmd)
		if matched {
			return true
		}
	}
	return false
}
