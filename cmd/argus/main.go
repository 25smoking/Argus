package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/25smoking/Argus/internal/ai"
	"github.com/25smoking/Argus/internal/config"
	"github.com/25smoking/Argus/internal/core"
	"github.com/25smoking/Argus/internal/plugins"
	"github.com/25smoking/Argus/internal/plugins/webshell"
	"github.com/25smoking/Argus/internal/report"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	log *zap.SugaredLogger

	// Command line flags
	offlineMode bool
	aiModel     string
	apiKey      string
	modules     string
)

func init() {
	logger, _ := zap.NewProduction()
	log = logger.Sugar()
}

var rootCmd = &cobra.Command{
	Use:   "argus",
	Short: "Argus - 智能化跨平台应急响应与威胁检测系统",
	Long: `Argus 取名自希腊神话中的“百眼巨人” (Argus Panoptes)，寓意以永不闭合的眼睛时刻守护系统安全。
这是一款专为红蓝对抗设计的现代化应急响应与取证工具，旨在提供更隐蔽、更强大、更自动化的威胁狩猎能力。`,
	Run: func(cmd *cobra.Command, args []string) {
		runScan()
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&offlineMode, "offline", "o", false, "离线模式（跳过网络检查）")
	rootCmd.PersistentFlags().StringVar(&aiModel, "ai", "", "启用 AI 分析 (可选: deepseek, gemini)")
	rootCmd.PersistentFlags().StringVar(&apiKey, "key", "", "AI API 密钥")
	rootCmd.PersistentFlags().StringVarP(&modules, "module", "m", "", "指定扫描模块 (e.g. user,process,network)")

	// Register graph command
	var graphCmd = &cobra.Command{
		Use:   "graph",
		Short: "生成系统攻击图谱",
		Run: func(cmd *cobra.Command, args []string) {
			runGraph()
		},
	}
	rootCmd.AddCommand(graphCmd)
}

func main() {
	// Ensure proper cleanup on exit
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("程序发生 panic: %v", r)
			os.Exit(1)
		}
		log.Sync()
	}()

	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func runScan() {
	// Global configuration
	core.GlobalConfig = &core.ScanConfig{
		Output:  "argus_report.json",
		Offline: offlineMode,
	}

	// Print banner
	fmt.Println(report.Banner)
	fmt.Println()

	// Check privileges
	checkPrivileges()

	// Initialize beautiful report
	beautifulReport := report.NewBeautifulReporter()

	// Print system info
	var hostname string
	if h, err := os.Hostname(); err == nil {
		hostname = h
	} else {
		hostname = "unknown"
	}

	var username string
	if u, ok := os.LookupEnv("USERNAME"); ok {
		username = u
	} else if u, ok := os.LookupEnv("USER"); ok {
		username = u
	} else {
		username = "unknown"
	}

	fmt.Printf("主机名: %s\n", hostname)
	fmt.Printf("用户: %s\n", username)
	fmt.Printf("操作系统: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("扫描时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))

	// Offline mode warning
	if offlineMode {
		fmt.Printf("%s  离线模式已启用，将跳过网络检查%s\n\n", report.ColorYellow, report.ColorReset)
	}

	// 初始化系统
	initOS()

	// 加载插件 (智能根据操作系统选择)
	var pluginsList []core.Plugin

	// 通用插件
	pluginsList = append(pluginsList,
		&plugins.HostInfoPlugin{},
		&plugins.ProcessPlugin{},
		&plugins.NetworkPlugin{},
		&plugins.FileScanPlugin{},
		&webshell.WebshellPlugin{},
		&plugins.MalwareScanPlugin{}, // 恶意软件/黑客工具检测
	)

	// 根据操作系统加载专属插件
	// 根据操作系统加载专属插件
	osInfo := getOSInfo()
	if list := getOSPlugins(); list != nil {
		pluginsList = append(pluginsList, list...)
	}

	// Filter plugins if -m specified
	if modules != "" {
		var filtered []core.Plugin
		keywords := strings.Split(strings.ToLower(modules), ",")
		for _, p := range pluginsList {
			name := strings.ToLower(p.Name())
			for _, k := range keywords {
				k = strings.TrimSpace(k)
				if k != "" && (strings.Contains(name, k) || canMapModule(k, name)) {
					filtered = append(filtered, p)
					break
				}
			}
		}
		if len(filtered) > 0 {
			pluginsList = filtered
		} else {
			log.Warnf("未找到匹配模块 '%s' 的插件，将运行所有插件", modules)
		}
	}

	// 美化输出系统信息
	fmt.Printf("\n%s 📋 载入当前系统信息: %s%s\n", report.ColorCyan, osInfo, report.ColorReset)

	// 运行插件
	var allResults []core.Result
	ctx := context.Background()

	beautifulReport.PrintSection("开始扫描")

	for _, p := range pluginsList {
		pluginStart := time.Now()
		beautifulReport.PrintPluginStart(p.Name(), 0)

		// 使用 SafeRun 保护插件执行
		results, err := core.SafeRun(p, ctx, core.GlobalConfig)
		if err != nil {
			log.Errorf("插件 %s 运行失败: %v", p.Name(), err)
		}

		// 收集结果
		if len(results) > 0 {
			allResults = append(allResults, results...)
			for _, r := range results {
				beautifulReport.AddResult(r)
			}
		}

		// 显示插件完成状态
		elapsed := time.Since(pluginStart)
		beautifulReport.PrintPluginComplete(p.Name(), elapsed, len(results))
	}

	beautifulReport.PrintSection("扫描完成")
	// 输出报告
	fmt.Printf("\n%s扫描结果摘要：%s\n", report.ColorBold, report.ColorReset)

	// 按严重级别统计
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0

	for _, r := range allResults {
		switch r.Level {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		default:
			infoCount++
		}
	}

	if criticalCount > 0 {
		fmt.Printf("%s   严重: %d 项%s\n", report.ColorRed, criticalCount, report.ColorReset)
	}
	if highCount > 0 {
		fmt.Printf("%s   高危: %d 项%s\n", report.ColorYellow, highCount, report.ColorReset)
	}
	if mediumCount > 0 {
		fmt.Printf("%s   中危: %d 项%s\n", report.ColorYellow, mediumCount, report.ColorReset)
	}
	if lowCount > 0 {
		fmt.Printf("%s   低危: %d 项%s\n", report.ColorCyan, lowCount, report.ColorReset)
	}
	if infoCount > 0 {
		fmt.Printf("%s  ℹ 信息: %d 项%s\n", report.ColorGreen, infoCount, report.ColorReset)
	}

	// 保存 JSON 报告
	jsonBytes, _ := json.MarshalIndent(allResults, "", "  ")
	jsonFile := fmt.Sprintf("argus_report_%s.json", time.Now().Format("20060102_150405"))
	os.WriteFile(jsonFile, jsonBytes, 0644)

	// 生成 HTML 报告
	htmlFile := fmt.Sprintf("argus_report_%s.html", time.Now().Format("20060102_150405"))
	if err := report.GenerateHTML(allResults, htmlFile); err == nil {
		fmt.Printf("\n✓  HTML 报告已生成: %s\n", htmlFile)
	}

	if len(allResults) == 0 || (criticalCount == 0 && highCount == 0 && mediumCount == 0) {
		log.Info("扫描完成，系统干净，未发现风险。")
	}

	// AI 分析 - 从配置文件自动加载
	aiCfg, err := config.LoadAIConfig("")
	if err != nil {
		log.Debugf("AI配置加载失败: %v (将尝试使用命令行参数)", err)
	}
	useModel, useKey := aiModel, apiKey

	// 配置文件作为后备
	if aiCfg != nil {
		if useModel == "" && aiCfg.AI.Enabled {
			useModel = aiCfg.AI.Model
		}
		if useKey == "" {
			useKey = aiCfg.AI.APIKey
		}
	}

	if useModel != "" && useKey != "" && len(allResults) > 0 {
		log.Infof("正在请求 %s 进行智能分析...", useModel)

		// 优化数据：只发送重要级别的结果，减少数据量
		var filteredResults []core.Result
		for _, r := range allResults {
			// 只发送 critical, high, medium 级别的告警
			if r.Level == "critical" || r.Level == "high" || r.Level == "medium" {
				// 截断过长的 Reference 字段（保留前500字符）
				if len(r.Reference) > 500 {
					r.Reference = r.Reference[:500] + "...[已截断]"
				}
				filteredResults = append(filteredResults, r)
			}
		}

		// 如果过滤后没有重要结果，至少发送前10条
		if len(filteredResults) == 0 && len(allResults) > 0 {
			limit := 10
			if len(allResults) < limit {
				limit = len(allResults)
			}
			filteredResults = allResults[:limit]
		}

		log.Debugf("AI分析: 总结果 %d 条，发送 %d 条重要结果", len(allResults), len(filteredResults))

		// 序列化过滤后的结果供 AI 分析
		aiJsonBytes, _ := json.MarshalIndent(filteredResults, "", "  ")
		reportStr := string(aiJsonBytes)

		// 保存发送给AI的数据（调试用）
		aiInputFile := "argus_ai_input.json"
		if err := os.WriteFile(aiInputFile, aiJsonBytes, 0644); err == nil {
			log.Debugf("已保存AI输入数据到: %s (大小: %d bytes, %.2f KB)",
				aiInputFile, len(aiJsonBytes), float64(len(aiJsonBytes))/1024)
		}

		// 调用 AI
		analysis, err := ai.AnalyzeReport(useModel, useKey, reportStr)
		if err != nil {
			log.Errorf("AI 分析失败: %v", err)
		} else {
			fmt.Println("\n================ [AI 智能分析报告] ================")
			fmt.Println(analysis)
			fmt.Println("===================================================")

			// 保存 AI 报告
			os.WriteFile("argus_ai_report.txt", []byte(analysis), 0644)
		}
	}
}

// canMapModule 处理简写映射
func canMapModule(keyword, pluginName string) bool {
	switch keyword {
	case "user", "account":
		return strings.Contains(pluginName, "account")
	case "proc", "process":
		return strings.Contains(pluginName, "process")
	case "net", "network":
		return strings.Contains(pluginName, "network") || strings.Contains(pluginName, "conn")
	case "file":
		return strings.Contains(pluginName, "file")
	case "mem", "memory":
		return strings.Contains(pluginName, "memory") || strings.Contains(pluginName, "stack")
	case "persist":
		return strings.Contains(pluginName, "persistence")
	}
	return false
}
