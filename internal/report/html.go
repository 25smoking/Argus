package report

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/25smoking/Argus/internal/core"
	"github.com/25smoking/Argus/internal/graph"
)

const reportTemplate = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Argus 安全扫描报告</title>
    <style>
        :root {
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-color: #333;
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --border-color: #dee2e6;
        }
        body { font-family: 'Segoe UI', sans-serif; background: var(--bg-color); color: var(--text-color); margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-card { flex: 1; background: var(--card-bg); padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-num { font-size: 2em; font-weight: bold; }
        .critical { color: var(--critical); }
        .high { color: var(--high); }
        .medium { color: var(--medium); }
        .low { color: var(--low); }

        .finding-card { background: var(--card-bg); border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 15px; border-left: 5px solid #ccc; overflow: hidden; }
        .finding-card.critical { border-left-color: var(--critical); }
        .finding-card.high { border-left-color: var(--high); }
        .finding-card.medium { border-left-color: var(--medium); }
        .finding-card.low { border-left-color: var(--low); }

        .finding-header { padding: 15px; background: rgba(0,0,0,0.02); display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
        .finding-title { font-weight: bold; display: flex; align-items: center; gap: 10px; }
        .badge { padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; text-transform: uppercase; }
        .bg-critical { background: var(--critical); }
        .bg-high { background: var(--high); }
        .bg-medium { background: var(--medium); color: black; }
        .bg-low { background: var(--low); }

        .finding-body { padding: 15px; display: none; border-top: 1px solid var(--border-color); }
        .finding-body.open { display: block; }
        .detail-row { margin-bottom: 10px; }
        .label { font-weight: bold; color: #666; }
        code { background: #eee; padding: 2px 5px; border-radius: 3px; word-break: break-all; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Argus 安全扫描报告</h1>
            <p>生成时间: {{ .GeneratedAt }}</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-num critical">{{ .Stats.Critical }}</div>
                <div>严重</div>
            </div>
            <div class="stat-card">
                <div class="stat-num high">{{ .Stats.High }}</div>
                <div>高危</div>
            </div>
            <div class="stat-card">
                <div class="stat-num medium">{{ .Stats.Medium }}</div>
                <div>中危</div>
            </div>
            <div class="stat-card">
                <div class="stat-num low">{{ .Stats.Low }}</div>
                <div>低危/信息</div>
            </div>
        </div>

        <div id="findings">
            {{ range .Results }}
            <div class="finding-card {{ .Level }}">
                <div class="finding-header" onclick="this.nextElementSibling.classList.toggle('open')">
                    <div class="finding-title">
                        <span class="badge bg-{{ .Level }}">{{ .Level }}</span>
                        [{{ .Plugin }}] {{ .Description }}
                    </div>
                    <div>▼</div>
                </div>
                <div class="finding-body">
                    <div class="detail-row"><span class="label">参考详情:</span> <code>{{ .Reference }}</code></div>
                    {{ if .Advice }}
                    <div class="detail-row"><span class="label">处置建议:</span> {{ .Advice }}</div>
                    {{ end }}
                </div>
            </div>
            {{ else }}
            <div style="text-align: center; padding: 40px; color: #666;">
                未发现安全风险 🎉
            </div>
            {{ end }}
        </div>
    </div>
</body>
</html>
`

type ReportData struct {
	GeneratedAt string
	Stats       map[string]int
	Results     []core.Result
}

func GenerateHTML(results []core.Result, filename string) error {
	stats := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, r := range results {
		l := strings.ToLower(r.Level)
		if _, ok := stats[l]; ok {
			stats[l]++
		} else {
			// fallback/warning -> low
			stats["low"]++
		}
	}

	data := ReportData{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Stats:       stats,
		Results:     results,
	}

	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

const sessionReportTemplate = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Argus 应急响应报告</title>
  <style>
    :root { --ink:#18212f; --muted:#5b6675; --line:#d9e0e8; --panel:#ffffff; --page:#f6f7f9; --red:#b42318; --orange:#c2410c; --amber:#a16207; --green:#166534; --blue:#1d4ed8; }
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; color: var(--ink); background: var(--page); }
    .wrap { max-width: 1240px; margin: 0 auto; padding: 24px; }
    .hero, .panel, .stat, .finding, details { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
    .hero { padding: 22px; margin-bottom: 16px; }
    h1 { margin: 0 0 6px; font-size: 28px; }
    h2 { margin: 24px 0 12px; font-size: 18px; }
    h3 { margin: 0 0 10px; font-size: 15px; }
    .sub { color: var(--muted); margin: 0; }
    .meta, .stats, .two-col, .module-grid { display: grid; gap: 12px; }
    .meta { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-top: 16px; color: var(--muted); }
    .stats { grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); margin: 16px 0; }
    .two-col { grid-template-columns: minmax(0, 1.2fr) minmax(320px, .8fr); }
    .module-grid { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
    .panel, .stat, .finding, details { padding: 14px; }
    .num { font-size: 28px; font-weight: 750; line-height: 1; }
    .label, .muted { color: var(--muted); }
    .critical { color: var(--red); } .high { color: var(--orange); } .medium { color: var(--amber); } .low { color: var(--green); } .info { color: var(--blue); }
    .finding { margin-bottom: 10px; border-left: 5px solid #9aa4b2; }
    .finding.critical { border-left-color: var(--red); } .finding.high { border-left-color: var(--orange); }
    .finding.medium { border-left-color: var(--amber); } .finding.low { border-left-color: var(--green); } .finding.info { border-left-color: var(--blue); }
    .title { font-weight: 750; margin-bottom: 8px; }
    .pill { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 999px; background: #edf2f7; color: #334155; font-size: 12px; margin-right: 6px; }
    code { background: #eef1f4; padding: 2px 5px; border-radius: 4px; word-break: break-word; }
    table { width: 100%; border-collapse: collapse; } td, th { border-bottom: 1px solid #e5e9ef; padding: 8px; text-align: left; vertical-align: top; }
    summary { cursor: pointer; font-weight: 750; }
    ul { margin: 8px 0 0; padding-left: 18px; }
    .empty { padding: 22px; text-align: center; color: var(--muted); }
    .graph-panel { overflow-x: auto; }
    .attack-svg { width: 100%; min-width: 920px; min-height: 360px; display: block; margin-top: 14px; background: #fbfdff; border: 1px solid #e5e9ef; border-radius: 8px; }
    @media (max-width: 860px) { .two-col { grid-template-columns: 1fr; } .wrap { padding: 14px; } }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <h1>Argus 应急响应报告</h1>
      <p class="sub">{{ .RiskText }}。生成时间：{{ .GeneratedAt }}</p>
      <div class="meta">
        <div>主机：<strong>{{ .HostLabel }}</strong></div>
        <div>用户：{{ .UserLabel }}</div>
        <div>系统：{{ .SystemLabel }}</div>
        <div>扫描策略：<strong>{{ .ProfileLabel }}</strong></div>
        <div>规则库：{{ .RuleBundleLabel }}</div>
        <div>任务编号：{{ .CaseLabel }}</div>
        <div>耗时：{{ .DurationLabel }}</div>
        <div>网络策略：{{ .NetworkPolicyLabel }}</div>
      </div>
    </div>

    <div class="stats">
      <div class="stat"><div class="num critical">{{ .Report.Summary.Critical }}</div><div>严重</div></div>
      <div class="stat"><div class="num high">{{ .Report.Summary.High }}</div><div>高危</div></div>
      <div class="stat"><div class="num medium">{{ .Report.Summary.Medium }}</div><div>中危</div></div>
      <div class="stat"><div class="num low">{{ .Report.Summary.Low }}</div><div>低危</div></div>
      <div class="stat"><div class="num info">{{ .Report.Summary.Info }}</div><div>信息</div></div>
      <div class="stat"><div class="num">{{ .Report.Summary.Total }}</div><div>总结果</div></div>
    </div>

    <div class="two-col">
      <div class="panel">
        <h2>优先处理</h2>
        {{ if .TopFindings }}
        {{ range .TopFindings }}
        <div class="finding {{ .Level }}">
          <div class="title"><span class="pill">{{ .Level }}</span><span class="pill">{{ .Plugin }}</span>{{ .Description }}</div>
          <div><code>{{ .Reference }}</code></div>
          {{ if .Advice }}<div class="muted">建议：{{ .Advice }}</div>{{ end }}
        </div>
        {{ end }}
        {{ else }}
        <div class="empty">没有中高危发现，建议查看扫描覆盖和信息类结果。</div>
        {{ end }}
      </div>

      <div class="panel">
        <h2>扫描覆盖</h2>
        <p>规则覆盖：{{ .Report.Coverage.RuleCoverage }}；网络禁用：{{ .Report.Coverage.NetworkDisabled }}；高扰动模式：{{ .Report.Coverage.HighDisturbanceMode }}</p>
        <p>已加载模块：{{ range .Report.Coverage.LoadedPlugins }}<span class="pill">{{ . }}</span>{{ end }}</p>
        {{ if .Report.SkippedModules }}
        <table><thead><tr><th>跳过模块</th><th>原因</th></tr></thead><tbody>
        {{ range .Report.SkippedModules }}<tr><td>{{ .Name }}</td><td>{{ .Reason }}</td></tr>{{ end }}
        </tbody></table>
        {{ end }}
      </div>
    </div>

    {{ if .AttackGraphSVG }}
    <h2>攻击图谱快照</h2>
    <div class="panel graph-panel">
      {{ if .Report.AttackGraph }}<div class="muted">DOT 文件：<code>{{ .Report.AttackGraph.DotPath }}</code>；节点 {{ .Report.AttackGraph.Nodes }}；关系 {{ .Report.AttackGraph.Edges }}</div>{{ end }}
      {{ .AttackGraphSVG }}
    </div>
    {{ end }}

    <h2>模块摘要</h2>
    <div class="module-grid">
      {{ range .ModuleSummaries }}
      <div class="panel">
        <h3>{{ .Plugin }}</h3>
        <div class="muted">总数 {{ .Total }}；严重 {{ .Critical }}；高危 {{ .High }}；中危 {{ .Medium }}；低危 {{ .Low }}；信息 {{ .Info }}；通过 {{ .Pass }}</div>
      </div>
      {{ end }}
    </div>

    <h2>发现明细</h2>
    {{ range .FindingGroups }}
    <details open>
      <summary>{{ .Plugin }}：{{ .Count }} 项</summary>
      {{ range .Findings }}
      <div class="finding {{ .Level }}">
        <div class="title"><span class="pill">{{ .Level }}</span>{{ .Description }}</div>
        <div>证据：<code>{{ .Reference }}</code></div>
        {{ if .Score }}<div class="muted">风险评分：{{ .Score }} / 100；置信度：{{ .Confidence }}%</div>{{ end }}
        {{ if .RuleName }}<div class="muted">规则：{{ .RuleName }} {{ if .RuleSource }}({{ .RuleSource }}){{ end }}</div>{{ end }}
        {{ if .Evidence }}<ul>{{ range .Evidence }}<li><code>{{ . }}</code></li>{{ end }}</ul>{{ end }}
        {{ if .Advice }}<div class="muted">建议：{{ .Advice }}</div>{{ end }}
      </div>
      {{ end }}
    </details>
    {{ else }}
    <div class="panel">未发现显著安全风险。</div>
    {{ end }}

    {{ if .RuleSources }}
    <h2>规则来源</h2>
    <div class="panel">
      <table><thead><tr><th>名称</th><th>许可证</th><th>URL</th></tr></thead><tbody>
      {{ range .RuleSources }}<tr><td>{{ .Name }}</td><td>{{ .License }}</td><td><code>{{ .URL }}</code></td></tr>{{ end }}
      </tbody></table>
    </div>
    {{ end }}
  </div>
</body>
</html>
`

type SessionReportView struct {
	Report             core.ScanReport
	GeneratedAt        string
	RiskText           string
	HostLabel          string
	UserLabel          string
	SystemLabel        string
	ProfileLabel       string
	RuleBundleLabel    string
	CaseLabel          string
	DurationLabel      string
	NetworkPolicyLabel string
	TopFindings        []core.Result
	FindingGroups      []FindingGroup
	ModuleSummaries    []ModuleSummary
	RuleSources        []core.RuleSourceInfo
	AttackGraphSVG     template.HTML
}

type FindingGroup struct {
	Plugin   string
	Count    int
	Findings []core.Result
}

type ModuleSummary struct {
	Plugin   string
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Pass     int
	Total    int
}

func GenerateHTMLReport(scanReport core.ScanReport, filename string) error {
	tmpl, err := template.New("session-report").Parse(sessionReportTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, buildSessionReportView(scanReport))
}

func buildSessionReportView(scanReport core.ScanReport) SessionReportView {
	findings := append([]core.Result(nil), scanReport.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		si, sj := severityRank(findings[i].Level), severityRank(findings[j].Level)
		if si == sj {
			if findings[i].Plugin == findings[j].Plugin {
				return findings[i].Description < findings[j].Description
			}
			return findings[i].Plugin < findings[j].Plugin
		}
		return si > sj
	})

	top := make([]core.Result, 0, 8)
	for _, item := range findings {
		if severityRank(item.Level) >= severityRank("medium") {
			top = append(top, item)
			if len(top) >= 8 {
				break
			}
		}
	}

	groupMap := make(map[string][]core.Result)
	summaryMap := make(map[string]*ModuleSummary)
	for _, item := range findings {
		groupMap[item.Plugin] = append(groupMap[item.Plugin], item)
		ms := summaryMap[item.Plugin]
		if ms == nil {
			ms = &ModuleSummary{Plugin: item.Plugin}
			summaryMap[item.Plugin] = ms
		}
		ms.Total++
		switch strings.ToLower(item.Level) {
		case "critical":
			ms.Critical++
		case "high":
			ms.High++
		case "medium":
			ms.Medium++
		case "low", "warning", "notice":
			ms.Low++
		case "pass":
			ms.Pass++
		default:
			ms.Info++
		}
	}

	plugins := make([]string, 0, len(groupMap))
	for plugin := range groupMap {
		plugins = append(plugins, plugin)
	}
	sort.Strings(plugins)
	groups := make([]FindingGroup, 0, len(plugins))
	for _, plugin := range plugins {
		groups = append(groups, FindingGroup{Plugin: plugin, Count: len(groupMap[plugin]), Findings: groupMap[plugin]})
	}

	moduleNames := make([]string, 0, len(summaryMap))
	for plugin := range summaryMap {
		moduleNames = append(moduleNames, plugin)
	}
	sort.Strings(moduleNames)
	modules := make([]ModuleSummary, 0, len(moduleNames))
	for _, plugin := range moduleNames {
		modules = append(modules, *summaryMap[plugin])
	}

	return SessionReportView{
		Report:             scanReport,
		GeneratedAt:        time.Now().Format("2006-01-02 15:04:05"),
		RiskText:           riskText(scanReport.Summary),
		HostLabel:          hostLabel(scanReport.ScanSession),
		UserLabel:          userLabel(scanReport.ScanSession),
		SystemLabel:        systemLabel(scanReport.ScanSession),
		ProfileLabel:       profileLabel(scanReport.Profile),
		RuleBundleLabel:    ruleBundleLabel(scanReport.RuleBundle),
		CaseLabel:          caseLabel(scanReport.ScanSession.CaseID),
		DurationLabel:      durationLabel(scanReport.ScanSession.Duration),
		NetworkPolicyLabel: networkPolicyLabel(scanReport.ScanSession),
		TopFindings:        top,
		FindingGroups:      groups,
		ModuleSummaries:    modules,
		RuleSources:        ruleSources(scanReport),
		AttackGraphSVG:     template.HTML(graph.RenderSVG(graph.BuildFromReport(scanReport))),
	}
}

func hostLabel(session core.ScanSession) string {
	if strings.TrimSpace(session.Hostname) == "" {
		return "未知"
	}
	return session.Hostname
}

func userLabel(session core.ScanSession) string {
	if strings.TrimSpace(session.User) == "" {
		return "未知"
	}
	return session.User
}

func systemLabel(session core.ScanSession) string {
	osName := map[string]string{
		"darwin":  "macOS",
		"windows": "Windows",
		"linux":   "Linux",
	}[strings.ToLower(session.OS)]
	if osName == "" {
		osName = session.OS
	}
	if strings.TrimSpace(osName) == "" {
		osName = "未知系统"
	}
	if strings.TrimSpace(session.Arch) == "" {
		return osName
	}
	return fmt.Sprintf("%s / %s", osName, session.Arch)
}

func profileLabel(profile string) string {
	labels := map[string]string{
		"quick":    "快速巡检",
		"standard": "标准扫描",
		"deep":     "深度扫描",
		"forensic": "取证扫描",
	}
	if label := labels[strings.ToLower(profile)]; label != "" {
		return fmt.Sprintf("%s（%s）", label, profile)
	}
	if strings.TrimSpace(profile) == "" {
		return "未指定"
	}
	return profile
}

func ruleBundleLabel(info *core.RuleBundleInfo) string {
	if info == nil {
		return "未加载规则库"
	}
	status := map[string]string{
		"external": "外置规则库",
		"minimal":  "最小内置规则",
	}[strings.ToLower(info.Status)]
	if status == "" {
		status = info.Status
	}
	parts := []string{status}
	if strings.TrimSpace(info.Version) != "" {
		parts = append(parts, info.Version)
	}
	if info.Files > 0 {
		parts = append(parts, fmt.Sprintf("%d 个文件", info.Files))
	}
	return strings.Join(parts, " / ")
}

func caseLabel(caseID string) string {
	if strings.TrimSpace(caseID) == "" {
		return "未设置"
	}
	return caseID
}

func durationLabel(duration string) string {
	if strings.TrimSpace(duration) == "" {
		return "未知"
	}
	return duration
}

func networkPolicyLabel(session core.ScanSession) string {
	offline := "关闭"
	if session.Offline {
		offline = "开启"
	}
	network := "允许"
	if session.NoNetwork {
		network = "禁止"
	}
	return fmt.Sprintf("离线模式：%s；扫描联网：%s", offline, network)
}

func ruleSources(scanReport core.ScanReport) []core.RuleSourceInfo {
	if scanReport.RuleBundle == nil {
		return nil
	}
	return scanReport.RuleBundle.Sources
}

func severityRank(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low", "warning", "notice":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func riskText(summary core.Summary) string {
	if summary.Critical > 0 {
		return fmt.Sprintf("需要立即处置：发现 %d 项严重风险", summary.Critical)
	}
	if summary.High > 0 {
		return fmt.Sprintf("建议优先处置：发现 %d 项高危风险", summary.High)
	}
	if summary.Medium > 0 {
		return fmt.Sprintf("建议复核：发现 %d 项中危风险", summary.Medium)
	}
	return "未发现中高危风险"
}
