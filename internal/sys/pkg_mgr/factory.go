package pkg_mgr

import (
	"os/exec"
)

// NewPackageManager 自动检测系统环境并返回合适的包管理器实现
func NewPackageManager() PackageManager {
	// 优先检测 rpm (CentOS/RHEL/Fedora)
	if _, err := exec.LookPath("rpm"); err == nil {
		return NewRpmManager()
	}

	// 其次检测 dpkg (Ubuntu/Debian/Kali)
	if _, err := exec.LookPath("dpkg"); err == nil {
		return NewDpkgManager()
	}

	// 如果都找不到，返回 nil
	return nil
}
