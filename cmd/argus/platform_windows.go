//go:build windows

package main

import (
	"fmt"
	"runtime"

	"github.com/25smoking/Argus/internal/core"
	wplugins "github.com/25smoking/Argus/internal/plugins/windows"
	"github.com/25smoking/Argus/internal/report"
	winsys "github.com/25smoking/Argus/internal/sys/windows"
)

func checkPrivileges() {
	if !winsys.IsAdmin() {
		fmt.Printf("%s  警告: 未以管理员身份运行，部分功能可能无法正常工作%s\n", report.ColorYellow, report.ColorReset)
	}
}

func getOSInfo() string {
	var osVersion string
	if info, err := winsys.GetOSVersion(); err == nil {
		osVersion = info
	} else {
		osVersion = "Unknown"
	}
	return fmt.Sprintf("Windows %s (%s)", osVersion, runtime.GOARCH)
}

func getOSPlugins() []core.Plugin {
	return []core.Plugin{
		&wplugins.StackScanPlugin{},  // 堆栈扫描 - 检测内存注入
		&wplugins.MemoryScanPlugin{}, // 内存扫描
		&wplugins.AccountPlugin{},
		&wplugins.ForensicsPlugin{},
		&wplugins.PersistencePlugin{}, // 持久化检测 - 注册表/服务/计划任务
		&wplugins.ThreatIntelPlugin{},
	}
}

func initOS() {
	// Windows-specific initialization if needed
}
