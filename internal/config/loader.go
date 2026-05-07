package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/25smoking/Argus/internal/embedded"
	"gopkg.in/yaml.v3"
)

type ArgusConfig struct {
	Argus struct {
		DefaultProfile string `yaml:"default_profile"`
		RulesDir       string `yaml:"rules_dir"`
		OutputDir      string `yaml:"output_dir"`
		Network        struct {
			DefaultNoNetwork bool `yaml:"default_no_network"`
		} `yaml:"network"`
		Reports struct {
			JSON  bool `yaml:"json"`
			HTML  bool `yaml:"html"`
			JSONL bool `yaml:"jsonl"`
		} `yaml:"reports"`
	} `yaml:"argus"`
}

type RuleSourcesConfig struct {
	RuleSources []RuleSource `yaml:"rule_sources"`
}

type RuleSource struct {
	Name        string   `yaml:"name"`
	URL         string   `yaml:"url"`
	Destination string   `yaml:"destination"`
	License     string   `yaml:"license"`
	Group       string   `yaml:"group"`
	Enabled     bool     `yaml:"enabled"`
	Source      string   `yaml:"source"`
	AllowPaths  []string `yaml:"allow_paths"`
}

// ========== Process Rules ==========

type ProcessRules struct {
	ReverseShells        []ReverseShellPattern     `yaml:"reverse_shells"`
	MaliciousPowerShell  []PowerShellPattern       `yaml:"malicious_powershell"`
	OfficeSpawnedShells  OfficeSpawnPattern        `yaml:"office_spawned_shells"`
	ParentChildPatterns  []ParentChildPattern      `yaml:"parent_child_patterns"`
	CommandPatterns      []ProcessCommandPattern   `yaml:"command_patterns"`
	SuspiciousSystemProc []SuspiciousSystemProcess `yaml:"suspicious_system_processes"`
}

type ReverseShellPattern struct {
	Pattern     string   `yaml:"pattern"`
	Level       string   `yaml:"level"`
	Description string   `yaml:"description"`
	References  []string `yaml:"references"`
}

type PowerShellPattern struct {
	Pattern     string   `yaml:"pattern"`
	Keywords    []string `yaml:"keywords"`
	Level       string   `yaml:"level"`
	Description string   `yaml:"description"`
	References  []string `yaml:"references"`
}

type OfficeSpawnPattern struct {
	ParentProcesses []string              `yaml:"parent_processes"`
	ChildProcesses  []ChildProcessPattern `yaml:"child_processes"`
}

type ChildProcessPattern struct {
	Process     string   `yaml:"process"`
	Level       string   `yaml:"level"`
	Description string   `yaml:"description"`
	References  []string `yaml:"references"`
}

type ParentChildPattern struct {
	Parent      string   `yaml:"parent"`
	Child       string   `yaml:"child"`
	Level       string   `yaml:"level"`
	Description string   `yaml:"description"`
	MITRE       []string `yaml:"mitre"`
	References  []string `yaml:"references"`
}

type ProcessCommandPattern struct {
	Name        string   `yaml:"name"`
	Process     string   `yaml:"process"`
	Pattern     string   `yaml:"pattern"`
	Level       string   `yaml:"level"`
	Description string   `yaml:"description"`
	MITRE       []string `yaml:"mitre"`
	References  []string `yaml:"references"`
}

type SuspiciousSystemProcess struct {
	Name         string   `yaml:"name"`
	RequiredPath string   `yaml:"required_path"`
	Level        string   `yaml:"level"`
	Description  string   `yaml:"description"`
	References   []string `yaml:"references"`
}

// ========== Network Rules ==========

type NetworkRules struct {
	UnexpectedNetworkProcesses []UnexpectedNetworkProcess `yaml:"unexpected_network_processes"`
	MaliciousPorts             []MaliciousPort            `yaml:"malicious_ports"`
	SuspiciousDomains          []SuspiciousDomain         `yaml:"suspicious_domains"`
	ConnectionPatterns         []ConnectionPattern        `yaml:"connection_patterns"`
}

type UnexpectedNetworkProcess struct {
	Process          string `yaml:"process"`
	Description      string `yaml:"description"`
	Level            string `yaml:"level"`
	AllowLocalSubnet bool   `yaml:"allow_local_subnet"`
}

type MaliciousPort struct {
	Port            int      `yaml:"port"`
	Protocol        string   `yaml:"protocol"`
	Direction       string   `yaml:"direction"`
	Description     string   `yaml:"description"`
	MalwareFamilies []string `yaml:"malware_families"`
	Level           string   `yaml:"level"`
	References      []string `yaml:"references"`
}

type SuspiciousDomain struct {
	Pattern     string   `yaml:"pattern"`
	Description string   `yaml:"description"`
	Level       string   `yaml:"level"`
	References  []string `yaml:"references"`
}

type ConnectionPattern struct {
	Name                string   `yaml:"name"`
	Description         string   `yaml:"description"`
	Level               string   `yaml:"level"`
	Threshold           int      `yaml:"threshold,omitempty"`
	TimeWindow          string   `yaml:"time_window,omitempty"`
	TimeRange           []string `yaml:"time_range,omitempty"`
	SuspiciousCountries []string `yaml:"suspicious_countries,omitempty"`
}

// ========== File Rules ==========

type FileRules struct {
	ScanRoots              map[string][]string `yaml:"scan_roots"`
	ExcludeDirs            []string            `yaml:"exclude_dirs"`
	MaxFiles               int                 `yaml:"max_files"`
	LargeFileMB            int64               `yaml:"large_file_mb"`
	RecentDays             int                 `yaml:"recent_days"`
	TempScriptExtensions   []string            `yaml:"temp_script_extensions"`
	ExecutableExtensions   []string            `yaml:"executable_extensions"`
	SuspiciousNames        []FileNameRule      `yaml:"suspicious_names"`
	SuspiciousPathPatterns []FilePathRule      `yaml:"suspicious_path_patterns"`
	SensitiveFiles         []FilePathRule      `yaml:"sensitive_files"`
	SmallFileContentMaxKB  int64               `yaml:"small_file_content_max_kb"`
	SuspiciousContent      []FileContentRule   `yaml:"suspicious_content"`
	AllowedSUIDPaths       []string            `yaml:"allowed_suid_paths"`
}

type FileNameRule struct {
	Pattern     string `yaml:"pattern"`
	Level       string `yaml:"level"`
	Description string `yaml:"description"`
}

type FilePathRule struct {
	Pattern     string `yaml:"pattern"`
	Level       string `yaml:"level"`
	Description string `yaml:"description"`
}

type FileContentRule struct {
	Pattern     string   `yaml:"pattern"`
	Level       string   `yaml:"level"`
	Description string   `yaml:"description"`
	Extensions  []string `yaml:"extensions"`
	Paths       []string `yaml:"paths"`
}

// ========== Persistence Rules (v2.2) ==========

type PersistenceRules struct {
	RegistryAutoStart  []RegistryRule          `yaml:"registry_autostart_keys"`
	RegistryHijack     []RegistryRule          `yaml:"registry_hijack_rules"`
	RegistryIntegrity  []RegistryIntegrityRule `yaml:"registry_integrity_checks"`
	SuspiciousServices []SuspiciousServiceRule `yaml:"suspicious_service_paths"`
	FilePersistence    []FilePersistenceRule   `yaml:"file_persistence_paths"`
	WMISubscriptions   []WMISubscriptionRule   `yaml:"wmi_subscriptions"`
	SuspiciousCommands []SuspiciousCommandRule `yaml:"suspicious_command_patterns"`
}

type RegistryRule struct {
	Name         string `yaml:"name"`
	Path         string `yaml:"path"`
	Root         string `yaml:"root"` // Some rules use 'root' instead of 'path'
	ValueName    string `yaml:"value_name"`
	TargetValue  string `yaml:"target_value"`
	CheckSubkeys bool   `yaml:"check_subkeys"`
	Severity     string `yaml:"severity"`
	Description  string `yaml:"description"`
}

func (r RegistryRule) GetPath() string {
	if r.Root != "" {
		return r.Root
	}
	return r.Path
}

type RegistryIntegrityRule struct {
	Name             string `yaml:"name"`
	Path             string `yaml:"path"`
	Root             string `yaml:"root"`
	ValueName        string `yaml:"value_name"`
	ExpectedExact    string `yaml:"expected_exact"`
	ExpectedContains string `yaml:"expected_contains"`
	BlacklistPattern string `yaml:"blacklist_pattern"`
	CheckSubkeys     bool   `yaml:"check_subkeys"`
	TargetValue      string `yaml:"target_value"` // For Print Monitors
	Severity         string `yaml:"severity"`
	Description      string `yaml:"description"`
}

func (r RegistryIntegrityRule) GetPath() string {
	if r.Root != "" {
		return r.Root
	}
	return r.Path
}

type SuspiciousServiceRule struct {
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
}

type FilePersistenceRule struct {
	Name     string `yaml:"name"`
	Path     string `yaml:"path"`
	Severity string `yaml:"severity"`
}

type WMISubscriptionRule struct {
	Namespace       string   `yaml:"namespace"`
	Class           string   `yaml:"class"`
	CheckProperties []string `yaml:"check_properties"`
	Severity        string   `yaml:"severity"`
	Description     string   `yaml:"description"`
}

type SuspiciousCommandRule struct {
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	Threshold   int    `yaml:"threshold"`
}

// ========== Loader Functions ==========

// ========== Loader Functions ==========

func loadConfigData(configPath, defaultName string) ([]byte, error) {
	// 1. 尝试从文件系统加载
	if configPath == "" {
		configPath = filepath.Join("config", defaultName)
	}

	// 尝试解析路径，如果文件存在则使用
	if _, err := os.Stat(configPath); err == nil {
		return os.ReadFile(configPath)
	}

	// 2. 回退到内嵌配置
	// 注意: embed总是使用正斜杠
	embedPath := "config/" + defaultName
	return embedded.Content.ReadFile(embedPath)
}

func LoadProcessRules(configPath string) (*ProcessRules, error) {
	data, err := loadConfigData(configPath, "process_rules.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read process rules: %w", err)
	}

	var rules ProcessRules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse process rules: %w", err)
	}

	return &rules, nil
}

func LoadNetworkRules(configPath string) (*NetworkRules, error) {
	data, err := loadConfigData(configPath, "network_rules.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read network rules: %w", err)
	}

	var rules NetworkRules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse network rules: %w", err)
	}

	return &rules, nil
}

func LoadFileRules(configPath string) (*FileRules, error) {
	data, err := loadConfigData(configPath, "file_rules.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read file rules: %w", err)
	}

	var rules FileRules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse file rules: %w", err)
	}

	return &rules, nil
}

func LoadPersistenceRules(configPath string) (*PersistenceRules, error) {
	data, err := loadConfigData(configPath, "persistence_rules.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read persistence rules: %w", err)
	}

	var rules PersistenceRules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse persistence rules: %w", err)
	}

	return &rules, nil
}

func LoadArgusConfig(configPath string) (*ArgusConfig, error) {
	data, err := loadConfigData(configPath, "argus.yaml")
	if err != nil {
		return defaultArgusConfig(), nil
	}

	cfg := defaultArgusConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse argus config: %w", err)
	}
	return cfg, nil
}

func defaultArgusConfig() *ArgusConfig {
	cfg := &ArgusConfig{}
	cfg.Argus.DefaultProfile = "standard"
	cfg.Argus.RulesDir = ".rule"
	cfg.Argus.OutputDir = "reports"
	cfg.Argus.Network.DefaultNoNetwork = true
	cfg.Argus.Reports.JSON = true
	cfg.Argus.Reports.HTML = true
	return cfg
}

func LoadRuleSources(configPath string) (*RuleSourcesConfig, error) {
	data, err := loadConfigData(configPath, "rule_sources.yaml")
	if err != nil {
		return defaultRuleSources(), nil
	}

	cfg := defaultRuleSources()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse rule sources: %w", err)
	}
	return cfg, nil
}

func defaultRuleSources() *RuleSourcesConfig {
	return &RuleSourcesConfig{RuleSources: []RuleSource{
		{
			Name:        "neo23x0-thor-hacktools",
			URL:         "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-hacktools.yar",
			Destination: "malware_rules/thor-hacktools.yar",
			License:     "Detection Rule License (DRL) 1.1",
			Group:       "malware",
			Enabled:     true,
			Source:      "Neo23x0/signature-base",
		},
		{
			Name:        "neo23x0-thor-webshells",
			URL:         "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar",
			Destination: "webshell_rules/thor-webshells.yar",
			License:     "Detection Rule License (DRL) 1.1",
			Group:       "webshell",
			Enabled:     true,
			Source:      "Neo23x0/signature-base",
		},
		{
			Name:        "elastic-cobalt",
			URL:         "https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_CobaltStrike.yar",
			Destination: "malware_rules/elastic-cobalt.yar",
			License:     "Elastic License v2",
			Group:       "malware",
			Enabled:     true,
			Source:      "elastic/protections-artifacts",
		},
	}}
}

// GetConfigPath 获取配置文件的绝对路径（兼容不同运行环境）
func GetConfigPath(filename string) string {
	// 尝试多个可能的路径
	candidates := []string{
		filepath.Join("config", filename),
		filepath.Join(".", "config", filename),
		filepath.Join("..", "config", filename),
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// 默认返回第一个路径
	return candidates[0]
}

// ========== Threat Intel Config ==========

type ThreatIntelConfig struct {
	ThreatIntel struct {
		Enabled          bool `yaml:"enabled"`
		Timeout          int  `yaml:"timeout"`
		MaxHashesPerScan int  `yaml:"max_hashes_per_scan"`
		MaxIPsPerScan    int  `yaml:"max_ips_per_scan"`

		Sources struct {
			VirusTotal struct {
				Enabled   bool   `yaml:"enabled"`
				APIKey    string `yaml:"api_key"`
				CheckHash bool   `yaml:"check_hash"`
				CheckIP   bool   `yaml:"check_ip"`
			} `yaml:"virustotal"`

			AbuseIPDB struct {
				Enabled bool   `yaml:"enabled"`
				APIKey  string `yaml:"api_key"`
				CheckIP bool   `yaml:"check_ip"`
			} `yaml:"abuseipdb"`
		} `yaml:"sources"`

		WhitelistProcesses []string `yaml:"whitelist_processes"`
	} `yaml:"threat_intel"`
}

func LoadThreatIntelConfig(configPath string) (*ThreatIntelConfig, error) {
	// Note: defaultName logic matches other loaders
	data, err := loadConfigData(configPath, "threat_intel.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read threat intel config: %w", err)
	}

	var cfg ThreatIntelConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse threat intel config: %w", err)
	}

	return &cfg, nil
}

// ========== AI Config ==========

type AIConfig struct {
	AI struct {
		Enabled        bool   `yaml:"enabled"`
		Model          string `yaml:"model"`
		APIKey         string `yaml:"api_key"`
		APIBase        string `yaml:"api_base"`
		Language       string `yaml:"language"`
		PromptTemplate string `yaml:"prompt_template"`
	} `yaml:"ai"`
}

func LoadAIConfig(configPath string) (*AIConfig, error) {
	data, err := loadConfigData(configPath, "ai.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read AI config: %w", err)
	}

	var cfg AIConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse AI config: %w", err)
	}

	return &cfg, nil
}
