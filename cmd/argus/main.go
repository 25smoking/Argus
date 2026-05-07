package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/25smoking/Argus/internal/ai"
	"github.com/25smoking/Argus/internal/config"
	"github.com/25smoking/Argus/internal/core"
	"github.com/25smoking/Argus/internal/graph"
	"github.com/25smoking/Argus/internal/plugins"
	"github.com/25smoking/Argus/internal/plugins/webshell"
	"github.com/25smoking/Argus/internal/report"
	rulemgr "github.com/25smoking/Argus/internal/rules"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type pluginSpec struct {
	Plugin          core.Plugin
	Profiles        []string
	HighDisturbance bool
	NeedsNetwork    bool
	NeedsAdmin      bool
	AdminNote       string
}

var (
	log *zap.SugaredLogger

	version   = "3.0.0-dev"
	commit    = "unknown"
	buildTime = "unknown"

	offlineMode bool
	noNetwork   bool
	aiModel     string
	apiKey      string
	modules     string
	profile     string
	rulesDir    string
	outputDir   string
	caseID      string
	jsonlOutput bool
)

func init() {
	logger, _ := zap.NewProduction()
	log = logger.Sugar()
}

var rootCmd = &cobra.Command{
	Use:   "argus",
	Short: "Argus - 单机专业版应急响应与威胁检测工具",
	Long:  "Argus 是面向离线应急响应、威胁狩猎和主机取证的单机安全检测工具，默认采用低扰动扫描策略。",
	Run: func(cmd *cobra.Command, args []string) {
		runScan()
	},
}

func init() {
	defaultCfg, _ := config.LoadArgusConfig("")
	profile = defaultCfg.Argus.DefaultProfile
	rulesDir = defaultCfg.Argus.RulesDir
	outputDir = defaultCfg.Argus.OutputDir
	noNetwork = defaultCfg.Argus.Network.DefaultNoNetwork
	jsonlOutput = defaultCfg.Argus.Reports.JSONL

	rootCmd.PersistentFlags().BoolVarP(&offlineMode, "offline", "o", false, "离线模式（禁用 AI、威胁情报和更新类网络请求）")
	rootCmd.PersistentFlags().BoolVar(&noNetwork, "no-network", noNetwork, "禁用扫描期间的外部网络请求")
	rootCmd.PersistentFlags().StringVar(&aiModel, "ai", "", "启用 AI 辅助研判（可选: deepseek, gemini；需要显式允许网络）")
	rootCmd.PersistentFlags().StringVar(&apiKey, "key", "", "AI API 密钥")
	rootCmd.PersistentFlags().StringVarP(&modules, "module", "m", "", "指定扫描模块，all 表示当前平台可用全部本地模块 (e.g. all,process,network,memory)")
	rootCmd.PersistentFlags().StringVar(&profile, "profile", profile, "扫描策略 (quick, standard, deep, forensic)")
	rootCmd.PersistentFlags().StringVar(&rulesDir, "rules-dir", rulesDir, "离线规则库目录")
	rootCmd.PersistentFlags().StringVar(&outputDir, "output-dir", outputDir, "报告输出目录")
	rootCmd.PersistentFlags().StringVar(&caseID, "case-id", "", "案件或任务编号")
	rootCmd.PersistentFlags().BoolVar(&jsonlOutput, "jsonl", jsonlOutput, "额外输出 JSONL 发现明细")

	scanCmd := &cobra.Command{
		Use:   "scan [all]",
		Short: "执行主机扫描",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 && strings.EqualFold(args[0], "all") {
				modules = "all"
				profile = "forensic"
			}
			runScan()
		},
	}
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(&cobra.Command{
		Use:   "all",
		Short: "执行当前平台可用全部本地模块扫描",
		Run: func(cmd *cobra.Command, args []string) {
			modules = "all"
			profile = "forensic"
			runScan()
		},
	})

	graphCmd := &cobra.Command{
		Use:   "graph",
		Short: "生成系统攻击图谱",
		Run: func(cmd *cobra.Command, args []string) {
			runGraph()
		},
	}
	rootCmd.AddCommand(graphCmd)
	rootCmd.AddCommand(newRulesCommand())
	rootCmd.AddCommand(&cobra.Command{
		Use:   "modules",
		Short: "列出当前平台模块和权限要求",
		Run: func(cmd *cobra.Command, args []string) {
			printModules(buildPluginSpecs())
		},
	})
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "显示版本和构建信息",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Argus %s\ncommit: %s\nbuild_time: %s\n", version, commit, buildTime)
		},
	})
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("程序发生 panic: %v", r)
			os.Exit(1)
		}
		_ = log.Sync()
	}()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan() {
	start := time.Now()
	if offlineMode {
		noNetwork = true
	}
	rulesDir = resolveRulesDir(rulesDir)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("无法创建输出目录: %v", err)
	}

	ruleInfo, _ := rulemgr.Status(rulesDir)
	core.GlobalConfig = &core.ScanConfig{
		Output:          "argus_report.json",
		Offline:         offlineMode,
		NoNetwork:       noNetwork,
		OutputDir:       outputDir,
		CaseID:          caseID,
		Profile:         normalizeProfile(profile),
		RulesDir:        rulesDir,
		JSONL:           jsonlOutput,
		ExplicitModules: explicitModuleMap(modules),
		RuleBundle:      ruleInfo,
	}

	fmt.Print(report.Banner)
	checkPrivileges()
	initOS()

	hostname, username := collectIdentity()
	fmt.Printf("主机名: %s\n", hostname)
	fmt.Printf("用户: %s\n", username)
	fmt.Printf("操作系统: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("扫描时间: %s\n", start.Format("2006-01-02 15:04:05"))
	fmt.Printf("扫描策略: %s\n", core.GlobalConfig.Profile)
	fmt.Printf("规则库: %s (%s)\n", ruleInfo.RulesDir, ruleInfo.Status)
	if offlineMode || noNetwork {
		fmt.Printf("%s离线/无网络策略已启用，扫描期间不会发起外部网络请求%s\n", report.ColorYellow, report.ColorReset)
	}
	if isAllModules(core.GlobalConfig.ExplicitModules) {
		fmt.Printf("%sall 模式已启用：将运行当前平台可用全部本地模块；外部威胁情报仍受 --no-network 控制%s\n", report.ColorYellow, report.ColorReset)
	}

	specs := selectPlugins(buildPluginSpecs(), core.GlobalConfig)
	addUnavailableModuleHints(core.GlobalConfig)
	printPrivilegeHints(specs)
	core.GlobalConfig.Coverage.LoadedPlugins = pluginNames(specs)
	core.GlobalConfig.Coverage.Profile = core.GlobalConfig.Profile
	core.GlobalConfig.Coverage.NetworkDisabled = noNetwork || offlineMode
	core.GlobalConfig.Coverage.HighDisturbanceMode = core.GlobalConfig.Profile == "deep" || core.GlobalConfig.Profile == "forensic"
	core.GlobalConfig.Coverage.RuleCoverage = ruleInfo.Status

	beautifulReport := report.NewBeautifulReporter()
	beautifulReport.PrintSection("开始扫描")

	var allResults []core.Result
	ctx := context.Background()
	for _, spec := range specs {
		p := spec.Plugin
		pluginStart := time.Now()
		beautifulReport.PrintPluginStart(p.Name(), 0)
		results, err := core.SafeRun(p, ctx, core.GlobalConfig)
		if err != nil {
			log.Errorf("插件 %s 运行失败: %v", p.Name(), err)
		}
		results = normalizeResults(results)
		allResults = append(allResults, results...)
		for _, r := range results {
			beautifulReport.AddResult(r)
		}
		beautifulReport.PrintPluginComplete(p.Name(), time.Since(pluginStart), len(results))
	}

	summary := core.Summarize(allResults)
	printSummary(summary)
	scanReport := buildScanReport(start, hostname, username, allResults)
	writeReports(scanReport)
	runAIIfRequested(allResults)
}

func buildPluginSpecs() []pluginSpec {
	processAdminNote := ""
	if runtime.GOOS == "windows" {
		processAdminNote = "Windows 签名/隐藏进程检查在管理员权限下更完整"
	}
	specs := []pluginSpec{
		{Plugin: &plugins.HostInfoPlugin{}, Profiles: []string{"quick", "standard", "deep", "forensic"}},
		{Plugin: &plugins.ProcessPlugin{}, Profiles: []string{"quick", "standard", "deep", "forensic"}, NeedsAdmin: runtime.GOOS == "windows", AdminNote: processAdminNote},
		{Plugin: &plugins.NetworkPlugin{}, Profiles: []string{"quick", "standard", "deep", "forensic"}},
		{Plugin: &plugins.FileScanPlugin{}, Profiles: []string{"standard", "deep", "forensic"}},
		{Plugin: &webshell.WebshellPlugin{}, Profiles: []string{"standard", "deep", "forensic"}},
		{Plugin: &plugins.MalwareScanPlugin{}, Profiles: []string{"standard", "deep", "forensic"}},
	}
	return append(specs, getOSPluginSpecs()...)
}

func selectPlugins(specs []pluginSpec, cfg *core.ScanConfig) []pluginSpec {
	var selected []pluginSpec
	allMode := isAllModules(cfg.ExplicitModules)
	for _, spec := range specs {
		name := spec.Plugin.Name()
		if spec.NeedsNetwork && (cfg.Offline || cfg.NoNetwork) {
			cfg.SkippedModules = append(cfg.SkippedModules, core.SkippedModule{Name: name, Reason: "离线或无网络策略禁用外部请求"})
			cfg.Coverage.SkippedPlugins = append(cfg.Coverage.SkippedPlugins, name)
			continue
		}
		if allMode {
			selected = append(selected, spec)
			continue
		}
		if len(cfg.ExplicitModules) > 0 {
			if matchesModule(cfg.ExplicitModules, name) {
				selected = append(selected, spec)
			}
			continue
		}
		if spec.HighDisturbance && cfg.Profile != "deep" && cfg.Profile != "forensic" {
			cfg.SkippedModules = append(cfg.SkippedModules, core.SkippedModule{Name: name, Reason: "standard/quick 默认跳过高扰动模块"})
			cfg.Coverage.SkippedPlugins = append(cfg.Coverage.SkippedPlugins, name)
			continue
		}
		if contains(spec.Profiles, cfg.Profile) {
			selected = append(selected, spec)
		} else {
			cfg.SkippedModules = append(cfg.SkippedModules, core.SkippedModule{Name: name, Reason: "当前 profile 不包含该模块"})
			cfg.Coverage.SkippedPlugins = append(cfg.Coverage.SkippedPlugins, name)
		}
	}
	return selected
}

func buildScanReport(start time.Time, hostname, username string, findings []core.Result) core.ScanReport {
	end := time.Now()
	return core.ScanReport{
		ScanSession: core.ScanSession{
			CaseID: caseID, Hostname: hostname, User: username, OS: runtime.GOOS, Arch: runtime.GOARCH,
			StartedAt: start.Format(time.RFC3339), EndedAt: end.Format(time.RFC3339),
			Duration: end.Sub(start).String(), Offline: offlineMode, NoNetwork: noNetwork,
			NetworkPolicyText: networkPolicyText(offlineMode, noNetwork),
		},
		RuleBundle:     core.GlobalConfig.RuleBundle,
		Profile:        core.GlobalConfig.Profile,
		Coverage:       core.GlobalConfig.Coverage,
		Summary:        core.Summarize(findings),
		Findings:       findings,
		Evidence:       buildEvidence(findings),
		Timeline:       buildTimeline(findings),
		SkippedModules: core.GlobalConfig.SkippedModules,
	}
}

func writeReports(scanReport core.ScanReport) {
	stamp := time.Now().Format("20060102_150405")
	writeAttackGraph(&scanReport, stamp)

	jsonFile := filepath.Join(outputDir, fmt.Sprintf("argus_report_%s.json", stamp))
	data, err := json.MarshalIndent(scanReport, "", "  ")
	if err != nil {
		log.Errorf("序列化 JSON 报告失败: %v", err)
		return
	}
	if err := os.WriteFile(jsonFile, data, 0644); err != nil {
		log.Errorf("写入 JSON 报告失败: %v", err)
	} else {
		fmt.Printf("\n✓ JSON 报告已生成: %s\n", jsonFile)
	}

	htmlFile := filepath.Join(outputDir, fmt.Sprintf("argus_report_%s.html", stamp))
	if err := report.GenerateHTMLReport(scanReport, htmlFile); err != nil {
		log.Errorf("HTML 报告生成失败: %v", err)
	} else {
		fmt.Printf("✓ HTML 报告已生成: %s\n", htmlFile)
	}

	if jsonlOutput {
		jsonlFile := filepath.Join(outputDir, fmt.Sprintf("argus_findings_%s.jsonl", stamp))
		if err := writeJSONL(jsonlFile, scanReport.Findings); err != nil {
			log.Errorf("JSONL 写入失败: %v", err)
		} else {
			fmt.Printf("✓ JSONL 明细已生成: %s\n", jsonlFile)
		}
	}
}

func writeAttackGraph(scanReport *core.ScanReport, stamp string) {
	g := graph.BuildFromReport(*scanReport)
	if g == nil {
		return
	}
	dotFile := filepath.Join(outputDir, fmt.Sprintf("attack_graph_%s.dot", stamp))
	var buf bytes.Buffer
	if err := g.ExportDOT(&buf); err != nil {
		log.Errorf("攻击图谱 DOT 生成失败: %v", err)
		return
	}
	if err := os.WriteFile(dotFile, buf.Bytes(), 0644); err != nil {
		log.Errorf("攻击图谱 DOT 写入失败: %v", err)
		return
	}
	scanReport.AttackGraph = &core.GraphSnapshot{
		DotPath: dotFile,
		Nodes:   len(g.Nodes),
		Edges:   len(g.Edges),
	}
	fmt.Printf("✓ DOT 攻击图谱已生成: %s\n", dotFile)
}

func runAIIfRequested(results []core.Result) {
	if offlineMode || noNetwork {
		if aiModel != "" || apiKey != "" {
			log.Warn("已启用离线/无网络策略，AI 分析被跳过")
		}
		return
	}
	aiCfg, _ := config.LoadAIConfig("")
	useModel, useKey := aiModel, apiKey
	if aiCfg != nil {
		if useModel == "" && aiCfg.AI.Enabled {
			useModel = aiCfg.AI.Model
		}
		if useKey == "" {
			useKey = aiCfg.AI.APIKey
		}
	}
	if useModel == "" || useKey == "" || len(results) == 0 {
		return
	}
	filtered := filterAIResults(results)
	aiBytes, _ := json.MarshalIndent(filtered, "", "  ")
	analysis, err := ai.AnalyzeReport(useModel, useKey, string(aiBytes))
	if err != nil {
		log.Errorf("AI 分析失败: %v", err)
		return
	}
	fmt.Println("\n================ [AI 辅助研判] ================")
	fmt.Println(analysis)
	fmt.Println("==============================================")
	_ = os.WriteFile(filepath.Join(outputDir, "argus_ai_report.txt"), []byte(analysis), 0644)
}

func newRulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rules",
		Aliases: []string{"rule"},
		Short:   "管理离线规则库",
	}
	updateSource := "upstream"
	cmd.AddCommand(&cobra.Command{
		Use: "status", Short: "查看规则库状态",
		Run: func(cmd *cobra.Command, args []string) {
			rulesDir = resolveRulesDir(rulesDir)
			info, _ := rulemgr.Status(rulesDir)
			fmt.Printf("规则目录: %s\n状态: %s\n版本: %s\n更新时间: %s\n文件数: %d\n",
				info.RulesDir, info.Status, info.Version, info.UpdatedAt, info.Files)
		},
	})
	updateCmd := &cobra.Command{
		Use: "update", Short: "从上游更新规则库",
		Run: func(cmd *cobra.Command, args []string) {
			if offlineMode {
				log.Fatal("离线模式已启用，不能执行 rules update；请使用 --offline=false")
			}
			if updateSource != "upstream" {
				log.Fatalf("暂不支持的规则源通道: %s", updateSource)
			}
			rulesDir = resolveRulesDir(rulesDir)
			srcCfg, err := config.LoadRuleSources("")
			if err != nil {
				log.Fatalf("加载规则源配置失败: %v", err)
			}
			lock, err := rulemgr.Update(context.Background(), rulesDir, srcCfg)
			if err != nil {
				log.Fatalf("规则更新失败，旧规则已保留: %v", err)
			}
			fmt.Printf("规则更新完成: %s，文件数: %d\n", lock.Version, len(lock.Files))
		},
	}
	updateCmd.Flags().StringVar(&updateSource, "source", "upstream", "规则更新通道（当前支持 upstream）")
	cmd.AddCommand(updateCmd)
	cmd.AddCommand(&cobra.Command{
		Use: "verify", Short: "校验规则库完整性和兼容性",
		Run: func(cmd *cobra.Command, args []string) {
			rulesDir = resolveRulesDir(rulesDir)
			result := rulemgr.Verify(rulesDir)
			for _, warn := range result.Warnings {
				fmt.Printf("WARN: %s\n", warn)
			}
			if !result.OK {
				for _, e := range result.Errors {
					fmt.Printf("ERROR: %s\n", e)
				}
				os.Exit(1)
			}
			fmt.Println("规则库校验通过")
		},
	})
	var showLicense, showSource bool
	listCmd := &cobra.Command{
		Use: "list", Short: "列出规则文件",
		Run: func(cmd *cobra.Command, args []string) {
			rulesDir = resolveRulesDir(rulesDir)
			if err := rulemgr.PrintList(os.Stdout, rulesDir, showLicense, showSource); err != nil {
				log.Fatalf("读取规则列表失败: %v", err)
			}
		},
	}
	listCmd.Flags().BoolVar(&showLicense, "license", false, "显示许可证")
	listCmd.Flags().BoolVar(&showSource, "source", false, "显示来源")
	cmd.AddCommand(listCmd)
	return cmd
}

func normalizeProfile(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "quick", "standard", "deep", "forensic":
		return p
	default:
		return "standard"
	}
}

func normalizeResults(results []core.Result) []core.Result {
	for i := range results {
		results[i].Level = strings.ToLower(results[i].Level)
		if results[i].Score == 0 {
			results[i].Score = scoreForLevel(results[i].Level)
		}
		if results[i].Confidence == 0 && results[i].Level != "pass" {
			results[i].Confidence = confidenceForLevel(results[i].Level)
		}
	}
	return results
}

func scoreForLevel(level string) int {
	switch level {
	case "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 60
	case "low", "warning", "notice":
		return 35
	case "error":
		return 20
	default:
		return 0
	}
}

func confidenceForLevel(level string) int {
	switch level {
	case "critical", "high":
		return 85
	case "medium":
		return 70
	case "low", "warning", "notice":
		return 55
	default:
		return 0
	}
}

func explicitModuleMap(value string) map[string]bool {
	m := make(map[string]bool)
	for _, item := range strings.Split(strings.ToLower(value), ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			m[item] = true
		}
	}
	return m
}

func isAllModules(mods map[string]bool) bool {
	return mods["all"] || mods["*"]
}

func matchesModule(keywords map[string]bool, pluginName string) bool {
	name := strings.ToLower(pluginName)
	for k := range keywords {
		if strings.Contains(name, k) || canMapModule(k, name) {
			return true
		}
	}
	return false
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func pluginNames(specs []pluginSpec) []string {
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.Plugin.Name())
	}
	return names
}

func collectIdentity() (string, string) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	username := "unknown"
	if u, ok := os.LookupEnv("USERNAME"); ok {
		username = u
	} else if u, ok := os.LookupEnv("USER"); ok {
		username = u
	}
	return hostname, username
}

func networkPolicyText(offline, noNetwork bool) string {
	offlineText := "关闭"
	if offline {
		offlineText = "开启"
	}
	networkText := "允许"
	if noNetwork {
		networkText = "禁止"
	}
	return fmt.Sprintf("离线模式：%s；扫描联网：%s", offlineText, networkText)
}

func resolveRulesDir(path string) string {
	if path == "" {
		path = ".rule"
	}
	if filepath.IsAbs(path) {
		return path
	}
	if path == ".rule" {
		exe, err := os.Executable()
		if err == nil {
			return filepath.Join(filepath.Dir(exe), ".rule")
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func buildEvidence(results []core.Result) []core.EvidenceItem {
	items := make([]core.EvidenceItem, 0)
	for i, r := range results {
		if r.Level == "pass" || r.Reference == "" {
			continue
		}
		items = append(items, core.EvidenceItem{ID: fmt.Sprintf("E%04d", i+1), Plugin: r.Plugin, Summary: r.Reference})
	}
	return items
}

func buildTimeline(results []core.Result) []core.TimelineItem {
	now := time.Now().Format(time.RFC3339)
	items := make([]core.TimelineItem, 0)
	for _, r := range results {
		if r.Level == "pass" {
			continue
		}
		items = append(items, core.TimelineItem{Time: now, Plugin: r.Plugin, Level: r.Level, Summary: r.Description})
	}
	return items
}

func writeJSONL(path string, findings []core.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, finding := range findings {
		if err := enc.Encode(finding); err != nil {
			return err
		}
	}
	return nil
}

func printModules(specs []pluginSpec) {
	fmt.Println("模块列表:")
	for _, spec := range specs {
		admin := "否"
		if spec.NeedsAdmin {
			admin = "建议/需要"
		}
		network := "否"
		if spec.NeedsNetwork {
			network = "是"
		}
		disturbance := "低"
		if spec.HighDisturbance {
			disturbance = "高"
		}
		note := spec.AdminNote
		if note == "" {
			note = "-"
		}
		fmt.Printf("- %-22s 管理员/root: %-8s 联网: %-2s 扰动: %-2s 说明: %s\n",
			spec.Plugin.Name(), admin, network, disturbance, note)
	}
	fmt.Println("\n快捷用法:")
	fmt.Println("  argus all              # 当前平台可用全部本地模块")
	fmt.Println("  argus scan all         # 同上")
	fmt.Println("  argus scan -m all      # 同上")
	fmt.Println("  argus scan -m memory   # 只跑内存/堆栈相关模块")

	unavailable := getUnavailableModuleHints()
	if len(unavailable) > 0 {
		fmt.Println("\n当前平台不可用模块:")
		for _, item := range unavailable {
			fmt.Printf("- %-22s %s\n", item.Name, item.Reason)
		}
	}
}

func printPrivilegeHints(specs []pluginSpec) {
	if isElevated() {
		return
	}
	var names []string
	for _, spec := range specs {
		if spec.NeedsAdmin {
			if spec.AdminNote != "" {
				names = append(names, fmt.Sprintf("%s（%s）", spec.Plugin.Name(), spec.AdminNote))
			} else {
				names = append(names, spec.Plugin.Name())
			}
		}
	}
	if len(names) == 0 {
		return
	}
	fmt.Printf("%s权限提示：以下模块在管理员/root 下结果更完整：%s%s\n",
		report.ColorYellow, strings.Join(names, "、"), report.ColorReset)
}

func addUnavailableModuleHints(cfg *core.ScanConfig) {
	hints := getUnavailableModuleHints()
	if len(hints) == 0 || len(cfg.ExplicitModules) == 0 {
		return
	}

	allMode := isAllModules(cfg.ExplicitModules)
	var added []core.SkippedModule
	for _, item := range hints {
		if !allMode && !matchesModule(cfg.ExplicitModules, item.Name) {
			continue
		}
		cfg.SkippedModules = append(cfg.SkippedModules, item)
		cfg.Coverage.SkippedPlugins = append(cfg.Coverage.SkippedPlugins, item.Name)
		added = append(added, item)
	}
	if len(added) == 0 {
		return
	}

	var parts []string
	for _, item := range added {
		parts = append(parts, fmt.Sprintf("%s（%s）", item.Name, item.Reason))
	}
	fmt.Printf("%s当前平台不可用模块：%s%s\n", report.ColorYellow, strings.Join(parts, "、"), report.ColorReset)
}

func filterAIResults(results []core.Result) []core.Result {
	var filtered []core.Result
	for _, r := range results {
		if r.Level == "critical" || r.Level == "high" || r.Level == "medium" {
			if len(r.Reference) > 500 {
				r.Reference = r.Reference[:500] + "...[已截断]"
			}
			filtered = append(filtered, r)
		}
	}
	if len(filtered) > 0 {
		return filtered
	}
	if len(results) > 10 {
		return results[:10]
	}
	return results
}

func printSummary(summary core.Summary) {
	fmt.Printf("\n%s扫描结果摘要：%s\n", report.ColorBold, report.ColorReset)
	if summary.Critical > 0 {
		fmt.Printf("%s严重: %d 项%s\n", report.ColorRed, summary.Critical, report.ColorReset)
	}
	if summary.High > 0 {
		fmt.Printf("%s高危: %d 项%s\n", report.ColorYellow, summary.High, report.ColorReset)
	}
	if summary.Medium > 0 {
		fmt.Printf("%s中危: %d 项%s\n", report.ColorYellow, summary.Medium, report.ColorReset)
	}
	if summary.Low > 0 {
		fmt.Printf("%s低危: %d 项%s\n", report.ColorCyan, summary.Low, report.ColorReset)
	}
	if summary.Info > 0 {
		fmt.Printf("%s信息: %d 项%s\n", report.ColorGreen, summary.Info, report.ColorReset)
	}
	if summary.Critical == 0 && summary.High == 0 && summary.Medium == 0 {
		log.Info("扫描完成，未发现中高危风险。")
	}
}

func canMapModule(keyword, pluginName string) bool {
	switch keyword {
	case "user", "account":
		return strings.Contains(pluginName, "account")
	case "proc", "process":
		return strings.Contains(pluginName, "process")
	case "net", "network":
		return strings.Contains(pluginName, "network") || strings.Contains(pluginName, "conn") || strings.Contains(pluginName, "threatintel")
	case "file":
		return strings.Contains(pluginName, "file")
	case "malware":
		return strings.Contains(pluginName, "malware")
	case "mem", "memory", "stack":
		return strings.Contains(pluginName, "memory") || strings.Contains(pluginName, "stack")
	case "persist":
		return strings.Contains(pluginName, "persistence")
	case "webshell":
		return strings.Contains(pluginName, "webshell")
	}
	return false
}
