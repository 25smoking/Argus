package plugins

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/25smoking/Argus/internal/core"
	"github.com/shirou/gopsutil/v3/host"
)

type HostInfoPlugin struct{}

func (p *HostInfoPlugin) Name() string {
	return "HostInfo"
}

func (p *HostInfoPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result

	// 获取主机信息
	info, err := host.Info()
	if err != nil {
		return nil, err
	}

	// 1. 操作系统信息
	osInfo := fmt.Sprintf("系统名称: %s, 版本: %s", info.Platform, info.PlatformVersion)
	results = append(results, core.Result{
		Plugin:      p.Name(),
		Level:       "INFO",
		Description: "操作系统信息",
		Reference:   osInfo,
	})

	// 2. 内核版本
	results = append(results, core.Result{
		Plugin:      p.Name(),
		Level:       "INFO",
		Description: "内核版本",
		Reference:   info.KernelVersion,
	})

	// 3. 主机名称
	results = append(results, core.Result{
		Plugin:      p.Name(),
		Level:       "INFO",
		Description: "主机名称",
		Reference:   info.Hostname,
	})

	// 4. 系统运行时间
	uptime := time.Duration(info.Uptime) * time.Second
	results = append(results, core.Result{
		Plugin:      p.Name(),
		Level:       "INFO",
		Description: "系统运行时间",
		Reference:   uptime.String(),
	})

	// 5. 当前登录用户 (稍微简化，只列出总数，具体用户在 UserAnalysis 插件详查)
	users, _ := host.Users()
	var userList []string
	for _, u := range users {
		userList = append(userList, fmt.Sprintf("%s (终端: %s, 主要自: %s)", u.User, u.Terminal, u.Host))
	}
	if len(userList) > 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "INFO",
			Description: "当前登录用户",
			Reference:   strings.Join(userList, "; "),
		})
	}

	return results, nil
}
