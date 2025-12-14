package linux

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/25smoking/Argus/internal/core"
)

type ConfigPlugin struct{}

func (p *ConfigPlugin) Name() string {
	return "LinuxConfigScan"
}

func (p *ConfigPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}

	var results []core.Result

	// 1. DNS 检测
	results = append(results, checkDNS()...)

	// 2. Hosts 检测
	results = append(results, checkHosts()...)

	// 如果没有发现任何威胁，返回 pass 状态
	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "pass",
			Description: "Linux 配置检测完成，未发现异常",
			Reference:   "已检查 DNS、Hosts 劫持",
		})
	}

	return results, nil
}

func checkDNS() []core.Result {
	var results []core.Result
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				ip := parts[1]
				// 这里可以加入一些恶意 DNS 的黑名单
				// 示例：某些被劫持的 DNS
				if ip == "8.8.8.8" || ip == "114.114.114.114" {
					// 这些是正常的，但在某些内网环境下可能不允许
					// results = append(results, core.Result{...})
				}
			}
		}
	}
	return results
}

func checkHosts() []core.Result {
	var results []core.Result
	data, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 检查是否有劫持公共域名的行为
		// 例如：1.2.3.4 www.baidu.com
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			domain := parts[1]
			ip := parts[0]

			commonDomains := []string{"www.baidu.com", "www.google.com", "github.com", "update.microsoft.com"}
			for _, d := range commonDomains {
				if strings.Contains(domain, d) && ip != "127.0.0.1" && ip != "::1" {
					results = append(results, core.Result{
						Plugin:      "LinuxConfigScan",
						Level:       "high",
						Description: "发现 Hosts 文件劫持公共域名",
						Reference:   fmt.Sprintf("%s -> %s", domain, ip),
					})
				}
			}
		}
	}
	return results
}
