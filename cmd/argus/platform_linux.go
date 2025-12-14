//go:build linux

package main

import (
	"fmt"
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

func getOSPlugins() []core.Plugin {
	return []core.Plugin{
		&lplugins.BackdoorPlugin{},
		&lplugins.AccountPlugin{},
		&lplugins.ConfigPlugin{},
		&lplugins.LogScanPlugin{},
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
