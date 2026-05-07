package plugins

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/25smoking/Argus/internal/config"
	"github.com/25smoking/Argus/internal/core"
	netutil "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type NetworkPlugin struct {
	rules *config.NetworkRules
}

type externalConnection struct {
	PID       int32
	Process   string
	Exe       string
	Cmdline   string
	LocalIP   string
	LocalPort uint32
	RemoteIP  string
	Port      uint32
	Protocol  string
	Status    string
	Direction string
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
		totalRules := len(rules.UnexpectedNetworkProcesses) + len(rules.MaliciousPorts) + len(rules.SuspiciousDomains)
		fmt.Printf("已加载网络检测规则: %d 个异常联网进程, %d 个恶意端口, %d 个域名规则 (共 %d 条)\n",
			len(rules.UnexpectedNetworkProcesses),
			len(rules.MaliciousPorts),
			len(rules.SuspiciousDomains),
			totalRules)
	}
	p.rules = rules

	// 获取网络连接列表
	conns, err := netutil.Connections("all")
	if err != nil {
		return nil, err
	}

	var externalConns []externalConnection
	var listeningConns []externalConnection
	reported := make(map[string]bool)
	seenListeners := make(map[string]bool)
	processInfoCache := make(map[int32]processInfo)

	for _, conn := range conns {
		procInfo := p.processInfo(conn.Pid, processInfoCache)
		view := externalConnection{
			PID: conn.Pid, Process: procInfo.Name, Exe: procInfo.Exe, Cmdline: procInfo.Cmdline,
			LocalIP: normalizeListenIP(conn.Laddr.IP), LocalPort: conn.Laddr.Port,
			RemoteIP: conn.Raddr.IP, Port: conn.Raddr.Port,
			Protocol: connType(conn.Type), Status: conn.Status,
		}

		if strings.EqualFold(conn.Status, "LISTEN") {
			view.Direction = "inbound"
			if p.isExposedListener(view) {
				listenKey := fmt.Sprintf("%d:%s:%d:%s", conn.Pid, view.LocalIP, view.LocalPort, view.Protocol)
				if !seenListeners[listenKey] {
					listeningConns = append(listeningConns, view)
					seenListeners[listenKey] = true
				}
				if res := p.checkListeningExposure(view); res != nil {
					key := fmt.Sprintf("listen:%d:%s:%d:%s", conn.Pid, view.LocalIP, view.LocalPort, view.Protocol)
					if !reported[key] {
						results = append(results, *res)
						reported[key] = true
					}
				}
				if p.rules != nil {
					if res := p.checkMaliciousPort(view); res != nil {
						key := fmt.Sprintf("listenport:%d:%s:%d:%s", conn.Pid, view.LocalIP, view.LocalPort, view.Protocol)
						if !reported[key] {
							results = append(results, *res)
							reported[key] = true
						}
					}
				}
			}
			continue
		}

		if !strings.EqualFold(conn.Status, "ESTABLISHED") || conn.Raddr.IP == "" {
			continue
		}
		if isLocalIP(conn.Raddr.IP) {
			continue
		}
		view.Direction = "outbound"
		externalConns = append(externalConns, view)

		if p.rules != nil {
			if res := p.checkUnexpectedNetworkProcess(view); res != nil {
				key := fmt.Sprintf("unexpected:%d:%s:%d", conn.Pid, conn.Raddr.IP, conn.Raddr.Port)
				if !reported[key] {
					results = append(results, *res)
					reported[key] = true
				}
				continue
			}
			if res := p.checkMaliciousPort(view); res != nil {
				key := fmt.Sprintf("port:%d:%s:%d", conn.Pid, conn.Raddr.IP, conn.Raddr.Port)
				if !reported[key] {
					results = append(results, *res)
					reported[key] = true
				}
				continue
			}
		}
	}

	results = append(results, p.checkConnectionPatterns(externalConns)...)
	results = append(results, p.checkSuspiciousDomainArtifacts(processInfoCache)...)

	if len(externalConns) > 0 {
		results = append(results, p.networkSummary(externalConns, listeningConns, cfg))
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

type processInfo struct {
	Name    string
	Exe     string
	Cmdline string
}

func (p *NetworkPlugin) processInfo(pid int32, cache map[int32]processInfo) processInfo {
	if pid <= 0 {
		return processInfo{Name: "unknown"}
	}
	if info, ok := cache[pid]; ok {
		return info
	}
	info := processInfo{Name: "unknown"}
	if proc, err := process.NewProcess(pid); err == nil {
		if got, err := proc.Name(); err == nil && got != "" {
			info.Name = got
		}
		if got, err := proc.Exe(); err == nil {
			info.Exe = got
		}
		if got, err := proc.Cmdline(); err == nil {
			info.Cmdline = got
		}
	}
	cache[pid] = info
	return info
}

func (p *NetworkPlugin) checkUnexpectedNetworkProcess(conn externalConnection) *core.Result {
	if p.rules == nil || len(p.rules.UnexpectedNetworkProcesses) == 0 {
		return nil
	}
	procName := strings.ToLower(conn.Process)
	for _, rule := range p.rules.UnexpectedNetworkProcesses {
		if strings.EqualFold(procName, strings.ToLower(rule.Process)) {
			level := rule.Level
			if level == "" {
				level = "high"
			}
			return &core.Result{
				Plugin:      p.Name(),
				Level:       level,
				Description: "异常进程产生外部网络连接",
				Reference:   fmt.Sprintf("进程: %s, PID: %d -> %s:%d；规则说明: %s", conn.Process, conn.PID, conn.RemoteIP, conn.Port, rule.Description),
				Advice:      "优先核查该进程是否被注入、替换或异常启动；必要时保留内存和进程证据后隔离。",
				Score:       85,
				Confidence:  80,
				Evidence:    compactEvidence(conn),
				RuleName:    "unexpected_network_processes/" + rule.Process,
				RuleSource:  "network_rules.yaml",
			}
		}
	}
	return nil
}

func (p *NetworkPlugin) networkSummary(conns, listeners []externalConnection, cfg *core.ScanConfig) core.Result {
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].Process == conns[j].Process {
			if conns[i].RemoteIP == conns[j].RemoteIP {
				return conns[i].Port < conns[j].Port
			}
			return conns[i].RemoteIP < conns[j].RemoteIP
		}
		return conns[i].Process < conns[j].Process
	})

	byProcess := make(map[string]int)
	byEndpoint := make(map[string]int)
	for _, conn := range conns {
		byProcess[conn.Process]++
		byEndpoint[fmt.Sprintf("%s:%d", conn.RemoteIP, conn.Port)]++
	}

	topProcesses := topCounts(byProcess, 6)
	topEndpoints := topCounts(byEndpoint, 8)
	evidence := make([]string, 0, 20)
	for i, conn := range conns {
		if i >= 20 {
			continue
		}
		evidence = append(evidence, fmt.Sprintf("%s(%d) -> %s:%d", conn.Process, conn.PID, conn.RemoteIP, conn.Port))
	}
	for i, conn := range listeners {
		if i >= 8 {
			break
		}
		evidence = append(evidence, fmt.Sprintf("%s(%d) LISTEN %s:%d", conn.Process, conn.PID, conn.LocalIP, conn.LocalPort))
	}

	advice := "这是联网概览，不等同于恶意结论；请优先核对 Top 进程、非常见端口和未知进程。"
	if cfg.Offline || cfg.NoNetwork {
		advice = "离线/无网络策略下只做本地规则判断，不进行 IP 归属地或威胁情报查询；请结合业务白名单复核。"
	}

	return core.Result{
		Plugin:      p.Name(),
		Level:       "info",
		Description: "外部网络连接概览",
		Reference:   fmt.Sprintf("共 %d 条外部 ESTABLISHED 连接，%d 个对外监听服务；Top 进程: %s；Top 端点: %s", len(conns), len(listeners), strings.Join(topProcesses, "、"), strings.Join(topEndpoints, "、")),
		Advice:      advice,
		Score:       10,
		Confidence:  60,
		Evidence:    evidence,
	}
}

func (p *NetworkPlugin) checkMaliciousPort(conn externalConnection) *core.Result {
	if p.rules == nil || len(p.rules.MaliciousPorts) == 0 {
		return nil
	}

	port := conn.Port
	endpoint := fmt.Sprintf("%s:%d", conn.RemoteIP, conn.Port)
	description := "连接到恶意软件端口"
	advice := "立即隔离该进程并进行深度分析。"
	if conn.Direction == "inbound" {
		port = conn.LocalPort
		endpoint = fmt.Sprintf("%s:%d", conn.LocalIP, conn.LocalPort)
		description = "发现高风险对外监听端口"
		advice = "请确认该监听服务是否为业务必需；未知监听需要保留进程、端口、文件和启动项证据后处置。"
	}

	for _, portRule := range p.rules.MaliciousPorts {
		if uint32(portRule.Port) == port && matchesDirection(portRule.Direction, conn.Direction) && matchesProtocol(portRule.Protocol, conn.Protocol) {
			families := strings.Join(portRule.MalwareFamilies, ", ")
			return &core.Result{
				Plugin:      p.Name(),
				Level:       portRule.Level,
				Description: fmt.Sprintf("%s: %s", description, portRule.Description),
				Reference:   fmt.Sprintf("进程: %s, PID: %d, %s %s/%s (恶意软件家族/用途: %s)", conn.Process, conn.PID, conn.Direction, endpoint, conn.Protocol, families),
				Advice:      advice,
				Score:       scoreForNetworkLevel(portRule.Level),
				Confidence:  80,
				Evidence:    compactEvidence(conn),
				RuleName:    fmt.Sprintf("malicious_ports/%d", port),
				RuleSource:  "network_rules.yaml",
			}
		}
	}

	return nil
}

func (p *NetworkPlugin) checkListeningExposure(conn externalConnection) *core.Result {
	if !isWildcardListenIP(conn.LocalIP) {
		return nil
	}
	level := "info"
	score := 15
	if isRiskyListeningPort(conn.LocalPort) {
		level = "medium"
		score = 60
	}
	return &core.Result{
		Plugin:      p.Name(),
		Level:       level,
		Description: "发现对外监听服务",
		Reference:   fmt.Sprintf("进程: %s, PID: %d LISTEN %s:%d/%s", conn.Process, conn.PID, conn.LocalIP, conn.LocalPort, conn.Protocol),
		Advice:      "请确认监听服务是否为业务必需；非必要服务建议关闭或限制到本地/内网地址。",
		Score:       score,
		Confidence:  70,
		Evidence:    compactEvidence(conn),
		RuleName:    "listening_exposure",
		RuleSource:  "network_runtime",
	}
}

func (p *NetworkPlugin) checkConnectionPatterns(conns []externalConnection) []core.Result {
	if p.rules == nil || len(p.rules.ConnectionPatterns) == 0 {
		return nil
	}
	byProcess := make(map[string][]externalConnection)
	for _, conn := range conns {
		key := fmt.Sprintf("%s/%d", conn.Process, conn.PID)
		byProcess[key] = append(byProcess[key], conn)
	}

	var results []core.Result
	for _, rule := range p.rules.ConnectionPatterns {
		if rule.Threshold <= 0 {
			continue
		}
		for procKey, items := range byProcess {
			if len(items) < rule.Threshold {
				continue
			}
			evidence := make([]string, 0, minInt(len(items), 20))
			for i, item := range items {
				if i >= 20 {
					break
				}
				evidence = append(evidence, fmt.Sprintf("%s(%d) -> %s:%d", item.Process, item.PID, item.RemoteIP, item.Port))
			}
			results = append(results, core.Result{
				Plugin:      p.Name(),
				Level:       defaultLevel(rule.Level, "medium"),
				Description: "单进程大量外部连接",
				Reference:   fmt.Sprintf("%s 维护 %d 条外部连接；规则说明: %s", procKey, len(items), rule.Description),
				Advice:      "请确认是否为浏览器、同步盘、代理或合法高并发客户端；未知进程需要优先排查。",
				Score:       scoreForNetworkLevel(rule.Level),
				Confidence:  70,
				Evidence:    evidence,
				RuleName:    "connection_patterns/" + rule.Name,
				RuleSource:  "network_rules.yaml",
			})
		}
	}
	return results
}

func (p *NetworkPlugin) checkSuspiciousDomainArtifacts(cache map[int32]processInfo) []core.Result {
	if p.rules == nil || len(p.rules.SuspiciousDomains) == 0 {
		return nil
	}
	regexes := make([]struct {
		rule config.SuspiciousDomain
		re   *regexp.Regexp
	}, 0, len(p.rules.SuspiciousDomains))
	for _, rule := range p.rules.SuspiciousDomains {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			continue
		}
		regexes = append(regexes, struct {
			rule config.SuspiciousDomain
			re   *regexp.Regexp
		}{rule: rule, re: re})
	}
	if len(regexes) == 0 {
		return nil
	}

	var results []core.Result
	seen := make(map[string]bool)
	for pid, info := range cache {
		text := strings.Join([]string{info.Name, info.Exe, info.Cmdline}, " ")
		if strings.TrimSpace(text) == "" {
			continue
		}
		for _, item := range regexes {
			if item.re.MatchString(text) {
				key := fmt.Sprintf("cmd:%d:%s", pid, item.rule.Pattern)
				if seen[key] {
					continue
				}
				seen[key] = true
				results = append(results, core.Result{
					Plugin:      p.Name(),
					Level:       defaultLevel(item.rule.Level, "medium"),
					Description: "进程命令行命中可疑域名规则",
					Reference:   fmt.Sprintf("进程: %s, PID: %d；规则说明: %s", info.Name, pid, item.rule.Description),
					Advice:      "请核查该命令行中的域名、URL 或隧道服务是否为合法业务使用。",
					Score:       scoreForNetworkLevel(item.rule.Level),
					Confidence:  65,
					Evidence:    []string{truncateString(text, 500)},
					RuleName:    "suspicious_domains/" + item.rule.Pattern,
					RuleSource:  "network_rules.yaml",
				})
			}
		}
	}

	if hosts, err := os.ReadFile("/etc/hosts"); err == nil {
		text := string(hosts)
		for _, item := range regexes {
			if item.re.MatchString(text) {
				key := "hosts:" + item.rule.Pattern
				if seen[key] {
					continue
				}
				seen[key] = true
				results = append(results, core.Result{
					Plugin:      p.Name(),
					Level:       defaultLevel(item.rule.Level, "medium"),
					Description: "hosts 文件命中可疑域名规则",
					Reference:   fmt.Sprintf("/etc/hosts；规则说明: %s", item.rule.Description),
					Advice:      "请确认 hosts 中的域名映射是否为合法运维配置，排除劫持或持久化痕迹。",
					Score:       scoreForNetworkLevel(item.rule.Level),
					Confidence:  60,
					Evidence:    []string{"/etc/hosts"},
					RuleName:    "suspicious_domains/" + item.rule.Pattern,
					RuleSource:  "network_rules.yaml",
				})
			}
		}
	}
	return results
}

func topCounts(counts map[string]int, limit int) []string {
	type item struct {
		Name  string
		Count int
	}
	items := make([]item, 0, len(counts))
	for name, count := range counts {
		if name == "" {
			name = "unknown"
		}
		items = append(items, item{Name: name, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Name < items[j].Name
		}
		return items[i].Count > items[j].Count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprintf("%s(%d)", item.Name, item.Count))
	}
	if len(out) == 0 {
		return []string{"无"}
	}
	return out
}

func scoreForNetworkLevel(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 60
	default:
		return 35
	}
}

func connType(value uint32) string {
	switch value {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	default:
		return "unknown"
	}
}

func matchesDirection(ruleDirection, actual string) bool {
	ruleDirection = strings.ToLower(strings.TrimSpace(ruleDirection))
	return ruleDirection == "" || ruleDirection == "any" || ruleDirection == strings.ToLower(actual)
}

func matchesProtocol(ruleProtocol, actual string) bool {
	ruleProtocol = strings.ToLower(strings.TrimSpace(ruleProtocol))
	return ruleProtocol == "" || ruleProtocol == "any" || ruleProtocol == strings.ToLower(actual)
}

func defaultLevel(level, fallback string) string {
	if strings.TrimSpace(level) == "" {
		return fallback
	}
	return level
}

func compactEvidence(conn externalConnection) []string {
	if conn.Direction == "inbound" {
		return []string{fmt.Sprintf("%s(%d) LISTEN %s:%d/%s", conn.Process, conn.PID, conn.LocalIP, conn.LocalPort, conn.Protocol)}
	}
	evidence := []string{fmt.Sprintf("%s(%d) -> %s:%d/%s", conn.Process, conn.PID, conn.RemoteIP, conn.Port, conn.Protocol)}
	if conn.Exe != "" {
		evidence = append(evidence, "exe="+conn.Exe)
	}
	if conn.Cmdline != "" {
		evidence = append(evidence, "cmdline="+truncateString(conn.Cmdline, 300))
	}
	return evidence
}

func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (p *NetworkPlugin) isExposedListener(conn externalConnection) bool {
	return isWildcardListenIP(conn.LocalIP) || (!isLocalIP(conn.LocalIP) && isRiskyListeningPort(conn.LocalPort))
}

func isWildcardListenIP(ip string) bool {
	return ip == "" || ip == "0.0.0.0" || ip == "::" || ip == "*"
}

func normalizeListenIP(ip string) string {
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return "*"
	}
	return ip
}

func isRiskyListeningPort(port uint32) bool {
	switch port {
	case 21, 22, 23, 25, 53, 80, 135, 139, 445, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 9300, 11211, 27017:
		return true
	default:
		return false
	}
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
		// 198.18.0.0/15 是基准测试保留网段，也常见于本机代理/TUN fake-ip。
		return true
	}
	return false
}
