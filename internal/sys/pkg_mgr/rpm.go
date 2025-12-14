package pkg_mgr

import (
	"os/exec"
	"strings"
)

type RpmManager struct{}

func NewRpmManager() *RpmManager {
	return &RpmManager{}
}

func (m *RpmManager) Name() string {
	return "rpm"
}

func (m *RpmManager) ListPackages() ([]string, error) {
	cmd := exec.Command("rpm", "-qa")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

func (m *RpmManager) VerifyFile(path string) (bool, string, error) {
	// rpm -Vf <file>
	// 输出格式: "S.5....T.  c /etc/passwd"
	// S: 大小, 5: MD5, T: 修改时间, ...
	cmd := exec.Command("rpm", "-Vf", path)
	out, err := cmd.CombinedOutput()

	output := string(out)
	// 如果命令执行成功且无输出，说明文件完整
	if err == nil && strings.TrimSpace(output) == "" {
		return true, "验证通过", nil
	}

	// rpm 返回 1 表示发现不一致
	// 如果是文件未被 rpm 管理，会报错 "file ... is not owned by any package"
	if strings.Contains(output, "not owned by any package") {
		return false, "不属于任何包 (未知文件)", nil
	}

	if output != "" {
		// 解析具体的修改项
		// 简单起见，直接返回原始输出，后续可以做更细致的解析
		return false, "文件校验失败: " + strings.TrimSpace(output), nil
	}

	return true, "验证通过", nil
}

func (m *RpmManager) GetFileOwner(path string) (string, error) {
	cmd := exec.Command("rpm", "-qf", "--qf", "%{NAME}", path)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
