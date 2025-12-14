package linux

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/25smoking/Argus/internal/core"
	"github.com/shirou/gopsutil/v3/process"
)

type BackdoorPlugin struct{}

func (p *BackdoorPlugin) Name() string {
	return "LinuxBackdoorScan"
}

func (p *BackdoorPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}

	var results []core.Result

	// 1. LD_PRELOAD & 环境变量后门
	results = append(results, checkEnvBackdoors()...)

	// 2. SSH 后门 (进程端口 & 文件篡改)
	results = append(results, checkSSHBackdoor()...)

	// 3. Cron 定时任务后门
	results = append(results, checkCron()...)

	// 4. SetUID 后门
	results = append(results, checkSetUID()...)

	// 5. Inetd/Xinetd 后门
	results = append(results, checkInetd()...)

	// 如果没有发现任何威胁，返回 pass 状态
	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "pass",
			Description: "Linux 后门检测完成，未发现异常",
			Reference:   "已检查 LD_PRELOAD、SSH、Cron、SetUID、Inetd",
		})
	}

	return results, nil
}

// 1. 检查环境变量后门 (LD_PRELOAD, PROMPT_COMMAND 等)
func checkEnvBackdoors() []core.Result {
	var results []core.Result

	// 检查 /etc/ld.so.preload
	if content, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		str := strings.TrimSpace(string(content))
		if str != "" && !strings.HasPrefix(str, "#") {
			results = append(results, core.Result{
				Plugin:      "LinuxBackdoorScan",
				Level:       "critical",
				Description: "发现 ld.so.preload 全局预加载库后门",
				Reference:   str,
				Advice:      "极高风险！黑客可通过此文件劫持所有系统命令。请检查文件内容并删除。",
			})
		}
	}

	// 检查 shell 配置文件
	configFiles := []string{
		"/etc/profile", "/etc/bashrc", "/etc/csh.login", "/etc/csh.cshrc",
		"/root/.bashrc", "/root/.bash_profile", "/root/.cshrc", "/root/.tcshrc",
	}
	// 遍历普通用户目录
	if dirs, err := os.ReadDir("/home"); err == nil {
		for _, d := range dirs {
			if d.IsDir() {
				home := filepath.Join("/home", d.Name())
				configFiles = append(configFiles,
					filepath.Join(home, ".bashrc"),
					filepath.Join(home, ".bash_profile"),
				)
			}
		}
	}

	suspiciousTags := []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "PROMPT_COMMAND", "alias sudo"}

	for _, file := range configFiles {
		f, err := os.Open(file)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, tag := range suspiciousTags {
				if strings.Contains(line, tag) {
					results = append(results, core.Result{
						Plugin:      "LinuxBackdoorScan",
						Level:       "high",
						Description: fmt.Sprintf("发现可疑环境变量配置 (%s)", tag),
						Reference:   fmt.Sprintf("%s: %s", file, strings.TrimSpace(line)),
						Advice:      "请检查该配置是否为恶意插入。",
					})
				}
			}
		}
		f.Close()
	}
	return results
}

// 2. 检查 SSH 后门
func checkSSHBackdoor() []core.Result {
	var results []core.Result

	// 2.1 检查 sshd 进程端口 (netstat 替代方案: 遍历 proc)
	procs, err := process.Processes()
	if err == nil {
		for _, p := range procs {
			name, _ := p.Name()
			if name == "sshd" {
				// 检查连接
				conns, _ := p.Connections()
				for _, c := range conns {
					if c.Status == "LISTEN" && c.Laddr.Port != 22 {
						results = append(results, core.Result{
							Plugin:      "LinuxBackdoorScan",
							Level:       "high",
							Description: "发现 SSHD 服务监听在非标准端口 (疑似后门)",
							Reference:   fmt.Sprintf("PID: %d, Port: %d", p.Pid, c.Laddr.Port),
						})
					}
				}
			}
		}
	}

	// 2.2 检查 SSH Wrapper (sshd 文件是否被篡改)
	sshdPath := "/usr/sbin/sshd"
	info, err := os.Lstat(sshdPath)
	if err == nil {
		// 如果是符号链接，可能是后门
		if info.Mode()&os.ModeSymlink != 0 {
			link, _ := os.Readlink(sshdPath)
			results = append(results, core.Result{
				Plugin:      "LinuxBackdoorScan",
				Level:       "critical",
				Description: "SSHD 二进制文件是符号链接 (SSH Wrapper 后门)",
				Reference:   fmt.Sprintf("%s -> %s", sshdPath, link),
			})
		} else {
			// 简单的文件类型检查 (读取头几个字节判读是否是 ELF)
			f, err := os.Open(sshdPath)
			if err == nil {
				buf := make([]byte, 4)
				f.Read(buf)
				f.Close()
				if string(buf[1:]) != "ELF" {
					results = append(results, core.Result{
						Plugin:      "LinuxBackdoorScan",
						Level:       "critical",
						Description: "SSHD 二进制文件头部异常 (非 ELF 文件)",
						Reference:   sshdPath,
						Advice:      "SSHD 可能被脚本替换，请立即检查。",
					})
				}
			}
		}
	}

	return results
}

// 3. 检查 Cron 后门
func checkCron() []core.Result {
	var results []core.Result
	cronDirs := []string{
		"/var/spool/cron", "/var/spool/cron/crontabs",
		"/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.hourly",
	}

	for _, dir := range cronDirs {
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}

			// 简单读文件查恶意关键词
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			str := string(data)

			// 常见的反弹 Shell 关键词
			keywords := []string{"/bin/sh -i", "/bin/bash -i", "nc -e", "exec ", "socket", "base64"}
			for _, kw := range keywords {
				if strings.Contains(str, kw) {
					results = append(results, core.Result{
						Plugin:      "LinuxBackdoorScan",
						Level:       "high",
						Description: "发现可疑 Cron 任务 (包含反弹 Shell 特征)",
						Reference:   fmt.Sprintf("%s: %s", path, kw),
					})
					break // 发现一个特征就报告
				}
			}
			return nil
		})
	}
	return results
}

// 4. 检查 SetUID 后门
func checkSetUID() []core.Result {
	// 此操作可能比较耗时，只检查关键目录或跳过
	// 简单实现：使用 find 命令 (Go 遍历其实也快)
	// 既然用户请求了，我们只检查 /usr/bin, /usr/sbin, /bin, /sbin
	var results []core.Result
	targetDirs := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"}

	for _, dir := range targetDirs {
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, _ := d.Info()
			// 检查是否设置了 SUID 位 (ModeSetuid = 0x800000)
			if info.Mode()&os.ModeSetuid != 0 {
				// 检查是否是已知的合法 SUID 程序
				if !isSafeSUID(d.Name()) {
					results = append(results, core.Result{
						Plugin:      "LinuxBackdoorScan",
						Level:       "medium",
						Description: "发现未知 SetUID 程序",
						Reference:   path,
						Advice:      "请确认该程序是否应该具有 Root 权限。",
					})
				}
			}
			return nil
		})
	}
	return results
}

// 白名单 (简化版)
func isSafeSUID(name string) bool {
	safe := map[string]bool{
		"sudo": true, "su": true, "passwd": true, "ping": true, "mount": true, "umount": true,
		"crontab": true, "pkexec": true, "chfn": true, "chsh": true, "gpasswd": true,
		"newgrp": true, "ssh-keysign": true,
	}
	return safe[name]
}

// 5. 检查 Inetd/Xinetd
func checkInetd() []core.Result {
	var results []core.Result
	files := []string{"/etc/inetd.conf"}
	if dir, err := os.ReadDir("/etc/xinetd.d"); err == nil {
		for _, d := range dir {
			files = append(files, filepath.Join("/etc/xinetd.d", d.Name()))
		}
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err == nil {
			if strings.Contains(string(data), "/bin/sh") || strings.Contains(string(data), "/bin/bash") {
				results = append(results, core.Result{
					Plugin:      "LinuxBackdoorScan",
					Level:       "high",
					Description: "发现 Inetd/Xinetd 配置文件中包含 Shell 启动项",
					Reference:   f,
				})
			}
		}
	}
	return results
}
