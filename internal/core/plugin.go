package core

import (
	"context"
)

// ScanConfig 保存扫描会话的全局配置
type ScanConfig struct {
	Debug      bool
	Offline    bool
	Output     string
	ReportPath string
	// 在此处添加其他全局设置
}

var GlobalConfig *ScanConfig

func InitConfig(debug, offline bool, output string) {
	GlobalConfig = &ScanConfig{
		Debug:   debug,
		Offline: offline,
		Output:  output,
	}
}

// Result 代表扫描器的一个发现结果
type Result struct {
	Plugin      string // 插件名称
	Level       string // "INFO", "low", "medium", "high", "critical"
	Description string // 描述
	Reference   string // 引用 (文件路径, 进程ID 等)
	Advice      string // 建议
}

// Plugin 是所有扫描模块必须实现的接口
type Plugin interface {
	Name() string
	Run(ctx context.Context, config *ScanConfig) ([]Result, error)
}
