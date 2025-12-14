package linux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/25smoking/Argus/internal/core"
)

type LogScanPlugin struct{}

func (p *LogScanPlugin) Name() string {
	return "LinuxLogScan"
}

func (p *LogScanPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	// 扫描 secure / auth.log
	results := checkAuthLogs()

	// 如果没有发现任何威胁，返回 pass 状态
	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      "LinuxLogScan",
			Level:       "pass",
			Description: "Linux 日志分析完成，未发现 SSH 暴力破解",
			Reference:   "已分析 /var/log/secure 和 /var/log/auth.log",
		})
	}

	return results, nil
}

func checkAuthLogs() []core.Result {
	var results []core.Result
	logFiles := []string{"/var/log/secure", "/var/log/auth.log"}

	failedIPs := make(map[string]int)
	successIPs := make(map[string]bool)

	for _, file := range logFiles {
		f, err := os.Open(file)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()

			// 提取 IP (简化逻辑，假设 IP 在行尾或特定格式)
			// "Failed password for ... from <IP>"
			if strings.Contains(line, "Failed password") {
				ip := extractIP(line)
				if ip != "" {
					failedIPs[ip]++
				}
			} else if strings.Contains(line, "Accepted password") || strings.Contains(line, "Accepted publickey") {
				ip := extractIP(line)
				if ip != "" {
					successIPs[ip] = true
				}
			}
		}
		f.Close()
	}

	// 分析结果
	for ip, count := range failedIPs {
		if count > 20 { // 阈值可调
			results = append(results, core.Result{
				Plugin:      "LinuxLogScan",
				Level:       "high",
				Description: fmt.Sprintf("发现 SSH 暴力破解行为 (失败 %d 次)", count),
				Reference:   fmt.Sprintf("IP: %s", ip),
				Advice:      "请封禁该 IP 或检查防火墙策略。",
			})

			// 检查是否爆破成功
			if successIPs[ip] {
				results = append(results, core.Result{
					Plugin:      "LinuxLogScan",
					Level:       "critical",
					Description: "SSH 暴力破解成功！",
					Reference:   fmt.Sprintf("IP: %s (先失败后成功)", ip),
					Advice:      "极高风险！攻击者已获取访问权限，请立即应急响应。",
				})
			}
		}
	}
	return results
}

func extractIP(line string) string {
	parts := strings.Fields(line)
	for i, part := range parts {
		if part == "from" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
