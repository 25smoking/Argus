//go:build linux

package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/25smoking/Argus/internal/core"
	lplugins "github.com/25smoking/Argus/internal/plugins/linux"
	"github.com/25smoking/Argus/internal/sys/pkg_mgr"
)

func checkPrivileges() {
	// Linux typically handles privileges via checking euid, implemented in plugins or core if needed
}

func getOSInfo() string {
	return fmt.Sprintf("Linux %s", runtime.GOARCH)
}

func getOSPluginSpecs() []pluginSpec {
	return []pluginSpec{
		{Plugin: &lplugins.BackdoorPlugin{}, Profiles: []string{"standard", "deep", "forensic"}, NeedsAdmin: true, AdminNote: "SUID、系统目录和部分后门检查建议 root 权限"},
		{Plugin: &lplugins.AccountPlugin{}, Profiles: []string{"standard", "deep", "forensic"}, NeedsAdmin: true, AdminNote: "读取 /etc/shadow 需要 root 权限"},
		{Plugin: &lplugins.ConfigPlugin{}, Profiles: []string{"standard", "deep", "forensic"}, NeedsAdmin: true, AdminNote: "系统配置完整读取建议 root 权限"},
		{Plugin: &lplugins.LogScanPlugin{}, Profiles: []string{"standard", "deep", "forensic"}, NeedsAdmin: true, AdminNote: "读取 /var/log/auth.log、journal 等建议 root 权限"},
	}
}

func initOS() {
	// Initialize system adapter (Package Manager only for Linux)
	pkgMgr := pkg_mgr.NewPackageManager()
	if pkgMgr != nil {
		log.Debugf("检测到包管理器: %s", pkgMgr.Name())
	} else {
		log.Warn("未检测到支持的包管理器 (rpm/dpkg)，系统文件校验将跳过")
	}
}

func isElevated() bool {
	return os.Geteuid() == 0
}

func getUnavailableModuleHints() []core.SkippedModule {
	return []core.SkippedModule{
		{Name: "MemoryScan", Reason: "当前仅 Windows 实现"},
		{Name: "StackHunter", Reason: "当前仅 Windows 实现"},
		{Name: "WindowsAccountScan", Reason: "Windows 专属账户模块"},
		{Name: "WindowsPersistence", Reason: "Windows 专属持久化模块"},
		{Name: "WindowsForensics", Reason: "Windows 专属取证模块"},
	}
}
