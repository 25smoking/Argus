package pkg_mgr

import (
	"os/exec"
	"strings"
)

type DpkgManager struct{}

func NewDpkgManager() *DpkgManager {
	return &DpkgManager{}
}

func (m *DpkgManager) Name() string {
	return "dpkg"
}

func (m *DpkgManager) ListPackages() ([]string, error) {
	// dpkg-query -f '${Package}\n' -W
	cmd := exec.Command("dpkg-query", "-f", "${Package}\n", "-W")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

func (m *DpkgManager) VerifyFile(path string) (bool, string, error) {
	// 1. 先找到文件属于哪个包
	pkg, err := m.GetFileOwner(path)
	if err != nil {
		// dpkg -S 失败通常意味着文件不属于任何包
		return false, "不属于任何包 (未知文件)", nil
	}

	// 2. 验证该包
	// dpkg --verify <package>
	// 输出: "??5?????? c /etc/passwd"
	cmd := exec.Command("dpkg", "--verify", pkg)
	out, _ := cmd.CombinedOutput() // dpkg -V 在发现变动时会返回非0，所以忽略 err

	output := string(out)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		// 如果输出行包含了我们的文件路径，说明该文件校验失败
		if strings.Contains(line, path) {
			return false, "文件校验失败: " + strings.TrimSpace(line), nil
		}
	}

	return true, "验证通过", nil
}

func (m *DpkgManager) GetFileOwner(path string) (string, error) {
	// dpkg -S /bin/ls -> "coreutils: /bin/ls"
	cmd := exec.Command("dpkg", "-S", path)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	// 解析输出 "pkgname: /path/to/file"
	parts := strings.Split(string(out), ":")
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0]), nil
	}
	return "", nil
}
