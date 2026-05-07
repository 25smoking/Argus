//go:build !windows && !linux

package main

import (
	"fmt"
	"runtime"

	"github.com/25smoking/Argus/internal/core"
)

func checkPrivileges() {
}

func getOSInfo() string {
	return fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH)
}

func getOSPluginSpecs() []pluginSpec {
	return nil
}

func initOS() {
}

func isElevated() bool {
	return false
}

func getUnavailableModuleHints() []core.SkippedModule {
	if runtime.GOOS == "darwin" {
		return []core.SkippedModule{
			{Name: "MemoryScan", Reason: "当前仅 Windows 实现；macOS 内存扫描尚未实现"},
			{Name: "StackHunter", Reason: "当前仅 Windows 实现；macOS 堆栈扫描尚未实现"},
			{Name: "WindowsAccountScan", Reason: "Windows 专属账户模块"},
			{Name: "WindowsPersistence", Reason: "Windows 专属持久化模块"},
			{Name: "WindowsForensics", Reason: "Windows 专属取证模块"},
			{Name: "LinuxAccountScan", Reason: "Linux 专属账户模块"},
			{Name: "LinuxBackdoorScan", Reason: "Linux 专属后门模块"},
			{Name: "LinuxLogScan", Reason: "Linux 专属日志模块"},
		}
	}
	return nil
}
