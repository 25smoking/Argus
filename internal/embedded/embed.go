package embedded

import (
	"embed"
)

// Content 包含内嵌的配置文件和规则库
// 这些文件作为默认配置，当外部文件不存在或用户选择离线模式时使用。
//
//go:embed config/*.yaml
//go:embed assets
var Content embed.FS
