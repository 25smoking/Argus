package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/25smoking/Argus/internal/config"
	"github.com/25smoking/Argus/internal/core"
	netutil "github.com/shirou/gopsutil/v3/net"
)

type NetworkPlugin struct {
	rules *config.NetworkRules
}

func (p *NetworkPlugin) Name() string {
	return "NetworkScan"
}

func (p *NetworkPlugin) Run(ctx context.Context, cfg *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result

	// 加载外部规则
	rules, err := config.LoadNetworkRules(config.GetConfigPath("network_rules.yaml"))
	if err != nil {
		fmt.Printf("Warning: Failed to load network rules: %v. Using minimal detection.\n", err)
	} else {
		totalRules := len(rules.MaliciousPorts) + len(rules.SuspiciousDomains)
		fmt.Printf("已加载网络检测规则: %d 个恶意端口, %d 个域名规则 (共 %d 条)\n",
			len(rules.MaliciousPorts),
			len(rules.SuspiciousDomains),
			totalRules)
		fmt.Printf("  ⚠️ 注意: unexpected_network_processes 功能未实现\n")
	}
	p.rules = rules

	// 获取网络连接列表
	conns, err := netutil.Connections("all")
	if err != nil {
		return nil, err
	}

	for _, conn := range conns {
		// 关注状态为 ESTABLISHED 的连接
		if conn.Status != "ESTABLISHED" {
			continue
		}

		remoteIP := conn.Raddr.IP
		remotePort := conn.Raddr.Port

		// 忽略本地回环和内网地址
		if isLocalIP(remoteIP) {
			continue
		}

		// 如果开启了离线模式，跳过所有对外部IP的进一步检查
		if cfg.Offline {
			results = append(results, core.Result{
				Plugin:      p.Name(),
				Level:       "INFO",
				Description: "发现外部网络连接 (离线模式不进行归属地查询)",
				Reference:   fmt.Sprintf("PID: %d -> %s:%d", conn.Pid, remoteIP, remotePort),
			})
			continue
		}

		// 在线模式：检查高危端口
		if p.rules != nil {
			if res := p.checkMaliciousPort(conn.Pid, remoteIP, uint32(remotePort)); res != nil {
				results = append(results, *res)
				continue // 已报告，跳过后续检查
			}
		}

		// 普通外部连接
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "low",
			Description: "发现外部网络连接",
			Reference:   fmt.Sprintf("PID: %d -> %s:%d", conn.Pid, remoteIP, remotePort),
			Advice:      "请确认该外部 IP 是否为合法业务地址。",
		})
	}

	// Pass 状态
	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "pass",
			Description: "网络连接扫描完成，未发现可疑连接",
			Reference:   fmt.Sprintf("已检查 %d 个连接", len(conns)),
		})
	}

	return results, nil
}

func (p *NetworkPlugin) checkMaliciousPort(pid int32, remoteIP string, port uint32) *core.Result {
	if p.rules == nil || len(p.rules.MaliciousPorts) == 0 {
		return nil
	}

	for _, portRule := range p.rules.MaliciousPorts {
		if uint32(portRule.Port) == port {
			families := strings.Join(portRule.MalwareFamilies, ", ")
			return &core.Result{
				Plugin:      p.Name(),
				Level:       portRule.Level,
				Description: fmt.Sprintf("连接到恶意软件端口: %s", portRule.Description),
				Reference:   fmt.Sprintf("Port: %d, IP: %s, PID: %d (恶意软件家族: %s)", port, remoteIP, pid, families),
				Advice:      "立即隔离该进程并进行深度分析。",
			}
		}
	}

	return nil
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	// 简单的私有地址检查
	if strings.HasPrefix(ipStr, "10.") || strings.HasPrefix(ipStr, "192.168.") {
		return true
	}
	if strings.HasPrefix(ipStr, "172.") {
		// 简化处理，视为内网
		return true
	}
	return false
}
