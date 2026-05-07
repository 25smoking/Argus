package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/25smoking/Argus/internal/core"
)

// ANSI 颜色代码
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorBold    = "\033[1m"
	ColorDim     = "\033[2m"
)

// 图标
const (
	IconSuccess  = "✓"
	IconWarning  = "⚠"
	IconError    = "✗"
	IconInfo     = "ℹ"
	IconCritical = "☠"
	IconScan     = "🔍"
	IconShield   = "🛡"
)

type BeautifulReporter struct {
	startTime time.Time
	results   []core.Result
}

func NewBeautifulReporter() *BeautifulReporter {
	return &BeautifulReporter{
		startTime: time.Now(),
		results:   make([]core.Result, 0),
	}
}

func (r *BeautifulReporter) PrintBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗                ║
║    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝                ║
║    ███████║██████╔╝██║  ███╗██║   ██║███████╗                ║
║    ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║                ║
║    ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║                ║
║    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝                ║
║                                                               ║
║          智能化跨平台应急响应与威胁检测系统                    ║
║               Intelligent APT Scanner v2.0                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
`
	fmt.Println(ColorCyan + banner + ColorReset)
}

func (r *BeautifulReporter) PrintSection(title string) {
	line := strings.Repeat("─", 65)
	fmt.Printf("\n%s┌%s┐%s\n", ColorBlue, line, ColorReset)
	fmt.Printf("%s│ %s%-63s%s │%s\n", ColorBlue, ColorBold+ColorWhite, title, ColorReset+ColorBlue, ColorReset)
	fmt.Printf("%s└%s┘%s\n\n", ColorBlue, line, ColorReset)
}

func (r *BeautifulReporter) PrintPluginStart(pluginName string, ruleCount int) {
	icon := IconScan
	if ruleCount > 0 {
		fmt.Printf("%s %s[%s]%s 加载 %s%d%s 条规则\n",
			icon, ColorCyan, pluginName, ColorReset, ColorYellow, ruleCount, ColorReset)
	} else {
		fmt.Printf("%s %s[%s]%s 启动扫描...\n",
			icon, ColorCyan, pluginName, ColorReset)
	}
}

func (r *BeautifulReporter) PrintPluginComplete(pluginName string, duration time.Duration, findingCount int) {
	icon := IconSuccess
	color := ColorGreen

	if findingCount > 0 {
		icon = IconWarning
		color = ColorYellow
	}

	fmt.Printf("%s %s[%s]%s 完成 - 用时 %s%.2fs%s - 发现 %s%d%s 项\n",
		icon, color, pluginName, ColorReset,
		ColorDim, duration.Seconds(), ColorReset,
		color, findingCount, ColorReset)
}

func (r *BeautifulReporter) AddResult(result core.Result) {
	r.results = append(r.results, result)
}

func (r *BeautifulReporter) PrintResults() {
	if len(r.results) == 0 {
		r.PrintSection("扫描结果")
		fmt.Printf("%s %s 未发现安全威胁，系统健康！%s\n\n",
			IconShield, ColorGreen+"[CLEAN]"+ColorReset, ColorGreen+ColorReset)
		return
	}

	// 按级别分类
	critical := 0
	high := 0
	medium := 0
	low := 0
	info := 0

	for _, res := range r.results {
		switch strings.ToLower(res.Level) {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		default:
			info++
		}
	}

	// 打印统计
	r.PrintSection("威胁统计")
	fmt.Printf("  %s Critical: %s%-3d%s  %s High: %s%-3d%s  %s Medium: %s%-3d%s  %s Low: %s%-3d%s\n\n",
		IconCritical, ColorRed+ColorBold, critical, ColorReset,
		IconError, ColorRed, high, ColorReset,
		IconWarning, ColorYellow, medium, ColorReset,
		IconInfo, ColorCyan, low, ColorReset)

	// 打印详细结果
	r.PrintSection("威胁详情")

	for i, res := range r.results {
		if strings.ToLower(res.Level) == "pass" || strings.ToLower(res.Level) == "info" {
			continue
		}

		icon, color := r.getLevelStyle(res.Level)

		fmt.Printf("%s%s (%d/%d) [%s]%s %s\n",
			ColorBold, icon, i+1, len(r.results), res.Plugin, ColorReset, res.Description)
		fmt.Printf("  %s级别:%s %s%s%s\n", ColorDim, ColorReset, color, res.Level, ColorReset)
		if res.Reference != "" {
			fmt.Printf("  %s位置:%s %s\n", ColorDim, ColorReset, res.Reference)
		}
		if res.Advice != "" {
			fmt.Printf("  %s建议:%s %s%s%s\n", ColorDim, ColorReset, ColorYellow, res.Advice, ColorReset)
		}
		fmt.Println()
	}
}

func (r *BeautifulReporter) getLevelStyle(level string) (string, string) {
	switch strings.ToLower(level) {
	case "critical":
		return IconCritical, ColorRed + ColorBold
	case "high":
		return IconError, ColorRed
	case "medium":
		return IconWarning, ColorYellow
	case "low":
		return IconInfo, ColorCyan
	default:
		return IconInfo, ColorWhite
	}
}

func (r *BeautifulReporter) PrintSummary() {
	duration := time.Since(r.startTime)

	r.PrintSection("扫描摘要")
	fmt.Printf("  %s开始时间:%s %s\n", ColorDim, ColorReset, r.startTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("  %s总耗时:%s   %s%.2f 秒%s\n", ColorDim, ColorReset, ColorGreen, duration.Seconds(), ColorReset)
	fmt.Printf("  %s总发现:%s   %s%d 项%s\n\n", ColorDim, ColorReset, ColorYellow, len(r.results), ColorReset)
}

func (r *BeautifulReporter) PrintFooter() {
	footer := `
╔═══════════════════════════════════════════════════════════════╗
║  感谢使用 Argus - 让安全检测变得简单而强大                     ║
║  GitHub: https://github.com/25smoking/Argus                   ║
╚═══════════════════════════════════════════════════════════════╝
`
	fmt.Println(ColorCyan + footer + ColorReset)
}
