//go:build !windows

package forensics

import (
	"fmt"
	"time"
)

// PrefetchInfo 包含解析后的 Prefetch 信息
type PrefetchInfo struct {
	ExecutableName string
	RunCount       uint32
	LastRunTimes   []time.Time
	FilesLoaded    []string // 依赖的文件列表
	Hash           uint32
}

// ParsePrefetch is a stub for non-Windows systems
func ParsePrefetch(path string) (*PrefetchInfo, error) {
	return nil, fmt.Errorf("prefetch parsing is only supported on Windows")
}
