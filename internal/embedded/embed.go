package embedded

import (
	"embed"
)

// Content 只包含默认配置和最小安全规则。
// 完整 YARA 规则库应通过外部 .rule/ 目录提供，避免主程序携带大规模恶意规则文本。
//
//go:embed config/*.yaml
//go:embed min_rules
var Content embed.FS
