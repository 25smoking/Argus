package linux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/25smoking/Argus/internal/core"
)

type AccountPlugin struct{}

func (p *AccountPlugin) Name() string {
	return "LinuxAccountScan"
}

func (p *AccountPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result

	// 1. 检查 /etc/passwd (UID=0, 可登录的非系统用户)
	results = append(results, checkPasswd()...)

	// 2. 检查 /etc/shadow (空口令) - 需要 Root 权限
	results = append(results, checkShadow()...)

	// 3. 检查历史命令 (.bash_history)
	results = append(results, checkHistory()...)

	// 如果没有发现任何威胁，返回 pass 状态
	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "pass",
			Description: "Linux 账户安全检测完成，未发现异常",
			Reference:   "已检查特权账号、空口令、历史命令",
		})
	}

	return results, nil
}

func checkPasswd() []core.Result {
	var results []core.Result
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		user := parts[0]
		uid := parts[2]
		// shell := parts[6]

		// 检查 UID=0 的非 root 用户
		if uid == "0" && user != "root" {
			results = append(results, core.Result{
				Plugin:      "LinuxAccountScan",
				Level:       "critical",
				Description: "发现非 root 用户的 UID 为 0 (特权账号)",
				Reference:   fmt.Sprintf("User: %s", user),
				Advice:      "这通常是黑客留下的后门账号，请立即删除。",
			})
		}
	}
	return results
}

func checkShadow() []core.Result {
	var results []core.Result
	// 只有 root 能读 shadow
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		user := parts[0]
		hash := parts[1]

		// 检查空口令 (hash 为空 或 :: )
		// 注意: * 或 ! 表示锁定，不算空口令
		if hash == "" || hash == "::" {
			results = append(results, core.Result{
				Plugin:      "LinuxAccountScan",
				Level:       "high",
				Description: "发现空口令用户",
				Reference:   fmt.Sprintf("User: %s", user),
				Advice:      "请立即为该用户设置强密码或锁定该账户。",
			})
		}
	}
	return results
}

func checkHistory() []core.Result {
	var results []core.Result

	// 收集所有用户的 history 文件
	files := []string{"/root/.bash_history"}
	if dirs, err := os.ReadDir("/home"); err == nil {
		for _, d := range dirs {
			if d.IsDir() {
				files = append(files, filepath.Join("/home", d.Name(), ".bash_history"))
			}
		}
	}

	suspiciousCmds := []string{
		"wget -q -O -", "curl -fsSL", "| sh", "| bash", // 下载执行
		"nc -e", "/dev/tcp/", // 反弹 shell
		"base64 -d", "openssl enc", // 编码/加密
		"rm -rf /", ":(){ :|:& };:", // 破坏/Fork炸弹
	}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			cmd := scanner.Text()
			if len(cmd) > 200 {
				continue
			} // 忽略过长行

			for _, key := range suspiciousCmds {
				if strings.Contains(cmd, key) {
					results = append(results, core.Result{
						Plugin:      "LinuxAccountScan",
						Level:       "medium",
						Description: "历史命令中发现可疑操作",
						Reference:   fmt.Sprintf("%s: %s", file, cmd),
					})
					break
				}
			}
		}
		f.Close()
	}
	return results
}
