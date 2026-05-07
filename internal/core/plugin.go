package core

import (
	"context"
)

// ScanConfig 保存扫描会话的全局配置
type ScanConfig struct {
	Debug      bool
	Offline    bool
	NoNetwork  bool
	Output     string
	OutputDir  string
	ReportPath string
	CaseID     string
	Profile    string
	RulesDir   string
	JSONL      bool

	ExplicitModules map[string]bool
	SkippedModules  []SkippedModule
	Coverage        Coverage
	RuleBundle      *RuleBundleInfo
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
	Plugin      string   `json:"plugin"`      // 插件名称
	Level       string   `json:"level"`       // "INFO", "low", "medium", "high", "critical"
	Description string   `json:"description"` // 描述
	Reference   string   `json:"reference"`   // 引用 (文件路径, 进程ID 等)
	Advice      string   `json:"advice"`      // 建议
	Score       int      `json:"score,omitempty"`
	Confidence  int      `json:"confidence,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	RuleSource  string   `json:"rule_source,omitempty"`
	RuleName    string   `json:"rule_name,omitempty"`
	MITRE       []string `json:"mitre,omitempty"`
}

// Plugin 是所有扫描模块必须实现的接口
type Plugin interface {
	Name() string
	Run(ctx context.Context, config *ScanConfig) ([]Result, error)
}

type SkippedModule struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type Coverage struct {
	Profile             string   `json:"profile"`
	LoadedPlugins       []string `json:"loaded_plugins"`
	SkippedPlugins      []string `json:"skipped_plugins"`
	RuleCoverage        string   `json:"rule_coverage"`
	NetworkDisabled     bool     `json:"network_disabled"`
	HighDisturbanceMode bool     `json:"high_disturbance_mode"`
}

type RuleBundleInfo struct {
	RulesDir  string           `json:"rules_dir"`
	LockPath  string           `json:"lock_path"`
	Version   string           `json:"version"`
	UpdatedAt string           `json:"updated_at"`
	Status    string           `json:"status"`
	Sources   []RuleSourceInfo `json:"sources"`
	Files     int              `json:"files"`
}

type RuleSourceInfo struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	License string `json:"license"`
	Commit  string `json:"commit,omitempty"`
	Enabled bool   `json:"enabled"`
}
