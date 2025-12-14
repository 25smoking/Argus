package report

import (
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/25smoking/Argus/internal/core"
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
