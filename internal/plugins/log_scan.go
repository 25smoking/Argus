package plugins

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/25smoking/Argus/internal/core"
)

type LogScanPlugin struct{}

func (p *LogScanPlugin) Name() string {
	return "LogScan"
}

func (p *LogScanPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result
	sysDir := os.Getenv("SystemRoot") + "\\System32\\winevt\\Logs"

	// 1. 分析 Security (4625, 4720, 1102, 4624)
	if res := p.analyzeLog(filepath.Join(sysDir, "Security.evtx"), "Security"); len(res) > 0 {
		results = append(results, res...)
	}

	// 2. 分析 System (7045)
	if res := p.analyzeLog(filepath.Join(sysDir, "System.evtx"), "System"); len(res) > 0 {
		results = append(results, res...)
	}

	// 3. 分析 PowerShell (4104)
	if res := p.analyzeLog(filepath.Join(sysDir, "Microsoft-Windows-PowerShell%4Operational.evtx"), "PowerShell"); len(res) > 0 {
		results = append(results, res...)
	}

	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "pass",
			Description: "日志分析完成",
			Reference:   "未发现异常事件。",
		})
	}

	return results, nil
}

func (p *LogScanPlugin) analyzeLog(path string, logType string) []core.Result {
	var results []core.Result

	f, err := evtx.Open(path)
	if err != nil {
		fmt.Printf("警告: 无法打开日志 %s: %v\n", path, err)
		return nil
	}
	defer f.Close()

	failedLogonCount := 0

	// FastEvents 返回的是 *evtx.GoEvtxMap (map[string]interface{})
	for e := range f.FastEvents() {
		// 获取 EventID
		eventID := getMapInt(e, "Event", "System", "EventID")

		switch logType {
		case "Security":
			if eventID == 4625 {
				failedLogonCount++
			} else if eventID == 4720 {
				user := getMapString(e, "Event", "EventData", "TargetUserName")
				results = append(results, core.Result{
					Plugin:      "LogScan",
					Level:       "high",
					Description: "检测到新用户创建 (Event 4720)",
					Reference:   fmt.Sprintf("用户: %s", user),
					Advice:      "请确认该账号创建操作是否经过授权。",
				})
			} else if eventID == 1102 {
				results = append(results, core.Result{
					Plugin:      "LogScan",
					Level:       "critical",
					Description: "安全日志被清除 (Event 1102)",
					Reference:   "日志清除通常是攻击者为了掩盖痕迹。",
				})
			} else if eventID == 4624 {
				// RDP 登录 (Type 10)
				lType := getMapString(e, "Event", "EventData", "LogonType")
				if lType == "10" {
					user := getMapString(e, "Event", "EventData", "TargetUserName")
					ip := getMapString(e, "Event", "EventData", "IpAddress")
					results = append(results, core.Result{
						Plugin:      "LogScan",
						Level:       "notice",
						Description: "检测到 RDP 远程登录成功",
						Reference:   fmt.Sprintf("用户: %s, 源IP: %s", user, ip),
					})
				}
			}

		case "System":
			if eventID == 7045 {
				svc := getMapString(e, "Event", "EventData", "ServiceName")
				img := getMapString(e, "Event", "EventData", "ImagePath")
				results = append(results, core.Result{
					Plugin:      "LogScan",
					Level:       "medium",
					Description: "检测到新服务安装 (Event 7045)",
					Reference:   fmt.Sprintf("服务: %s, 路径: %s", svc, img),
					Advice:      "请检查服务路径是否可疑 (如 Temp 目录)。",
				})
			}

		case "PowerShell":
			// PowerShell日志结构可能略有不同，ScriptBlockText通常在EventData中
			if eventID == 4104 {
				script := getMapString(e, "Event", "EventData", "ScriptBlockText")
				if isSuspiciousScript(script) {
					results = append(results, core.Result{
						Plugin:      "LogScan",
						Level:       "high",
						Description: "发现可疑 PowerShell 脚本块 (Event 4104)",
						Reference:   fmt.Sprintf("内容关键词匹配"),
					})
				}
			}
		}
	}

	if failedLogonCount > 10 {
		results = append(results, core.Result{
			Plugin:      "LogScan",
			Level:       "medium",
			Description: "检测到多次登录失败 (疑似爆破)",
			Reference:   fmt.Sprintf("失败次数: %d", failedLogonCount),
		})
	}

	return results
}

// getMapInt 从嵌套 map 中获取 int 值
func getMapInt(m *evtx.GoEvtxMap, path ...string) int {
	val := getMapValue(m, path...)
	if val == nil {
		return 0
	}
	// 处理可能的类型 (json unmarshal 默认为 float64, evtx 可能是 uint64/int64)
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case uint64:
		return int(v)
	case float64:
		return int(v)
	case string:
		// 某些情况下 EventID 如果是 string
		var i int
		fmt.Sscanf(v, "%d", &i)
		return i
	}
	return 0
}

// getMapString 从嵌套 map 中获取 string 值
func getMapString(m *evtx.GoEvtxMap, path ...string) string {
	val := getMapValue(m, path...)
	if val == nil {
		return ""
	}
	return fmt.Sprintf("%v", val)
}

// getMapValue 通用递归查找
func getMapValue(m *evtx.GoEvtxMap, path ...string) interface{} {
	if m == nil {
		return nil
	}
	// 将 GoEvtxMap 转换为 map[string]interface{} 处理
	current := map[string]interface{}(*m)

	for i, key := range path {
		val, ok := current[key]
		if !ok {
			return nil
		}

		// 如果是路径的最后一个元素，返回该值
		if i == len(path)-1 {
			return val
		}

		// 否则继续深入
		// 下一层可能是 map[string]interface{} 或 *GoEvtxMap
		// 注意: golang-evtx 使用 GoEvtxMap 类型
		if nested, ok := val.(map[string]interface{}); ok {
			current = nested
		} else if nested, ok := val.(*evtx.GoEvtxMap); ok {
			current = map[string]interface{}(*nested)
		} else if nested, ok := val.(evtx.GoEvtxMap); ok {
			current = map[string]interface{}(nested)
		} else {
			return nil
		}
	}
	return nil
}

func isSuspiciousScript(script string) bool {
	keywords := []string{
		"Net.WebClient", "DownloadString", "Invoke-Expression",
		"Base64String", "-enc", "bypass",
	}
	for _, kw := range keywords {
		if strings.Contains(script, kw) {
			return true
		}
	}
	return false
}
