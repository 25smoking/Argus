package core

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
)

// SaveResults 导出结果
func SaveResults(results []Result, format string) error {
	timestamp := time.Now().Format("20060102_150405")

	switch format {
	case "json":
		filename := fmt.Sprintf("argus_report_%s.json", timestamp)
		return saveJSON(results, filename)
	case "csv", "excel": // Excel 也是用 CSV 格式兼容
		filename := fmt.Sprintf("argus_report_%s.csv", timestamp)
		return saveCSV(results, filename)
	default:
		// 默认两个都保存
		saveJSON(results, fmt.Sprintf("argus_report_%s.json", timestamp))
		saveCSV(results, fmt.Sprintf("argus_report_%s.csv", timestamp))
		return nil
	}
}

func saveJSON(results []Result, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return err
	}
	fmt.Printf("[+] 报告已保存: %s\n", filename)
	return nil
}

func saveCSV(results []Result, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// 写入 BOM 以防止 Excel 打开中文乱码
	f.Write([]byte("\xEF\xBB\xBF"))

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	w.Write([]string{"Level", "Plugin", "Description", "Reference", "Advice"})

	// Data
	for _, r := range results {
		w.Write([]string{r.Level, r.Plugin, r.Description, r.Reference, r.Advice})
	}

	fmt.Printf("[+] 报告已保存: %s\n", filename)
	return nil
}

func PrintResults(logger *zap.SugaredLogger, results []Result) {
	if len(results) == 0 {
		logger.Info("未发现显著的安全风险。")
		return
	}

	logger.Warnf("=== 扫描完成，共发现 %d 个风险项 ===", len(results))
	for _, res := range results {
		logger.Warnf("[%s] [%s] %s | %s", res.Plugin, res.Level, res.Description, res.Reference)
		if res.Advice != "" {
			logger.Infof("    -> 建议: %s", res.Advice)
		}
	}
}
