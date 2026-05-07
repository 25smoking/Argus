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

func getOSPluginSpecs() []pluginSpec {
	return []pluginSpec{
		{Plugin: &wplugins.AccountPlugin{}, Profiles: []string{"standard", "deep", "forensic"}, NeedsAdmin: true, AdminNote: "枚举本地账户和管理员组建议管理员权限"},
		{Plugin: &wplugins.ForensicsPlugin{}, Profiles: []string{"standard", "deep", "forensic"}, NeedsAdmin: true, AdminNote: "读取 Prefetch、注册表取证痕迹建议管理员权限"},
		{Plugin: &wplugins.PersistencePlugin{}, Profiles: []string{"standard", "deep", "forensic"}, NeedsAdmin: true, AdminNote: "HKLM、服务、计划任务检查建议管理员权限"},
		{Plugin: &wplugins.StackScanPlugin{}, Profiles: []string{"deep", "forensic"}, HighDisturbance: true, NeedsAdmin: true, AdminNote: "堆栈/线程类深度检查需要管理员权限更完整"},
		{Plugin: &wplugins.MemoryScanPlugin{}, Profiles: []string{"deep", "forensic"}, HighDisturbance: true, NeedsAdmin: true, AdminNote: "读取其他进程内存需要管理员权限更完整"},
		{Plugin: &wplugins.ThreatIntelPlugin{}, Profiles: []string{"deep", "forensic"}, NeedsNetwork: true, AdminNote: "需要 API Key 和外部网络，不要求管理员权限"},
	}
}

func initOS() {
	// Windows-specific initialization if needed
}

func isElevated() bool {
	return winsys.IsAdmin()
}

func getUnavailableModuleHints() []core.SkippedModule {
	return []core.SkippedModule{
		{Name: "LinuxAccountScan", Reason: "Linux 专属账户模块"},
		{Name: "LinuxBackdoorScan", Reason: "Linux 专属后门模块"},
		{Name: "LinuxLogScan", Reason: "Linux 专属日志模块"},
	}
}
