package plugins

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/25smoking/Argus/internal/core"
)

type FileScanPlugin struct{}

func (p *FileScanPlugin) Name() string {
	return "FileScan"
}

// 扫描任务
type scanTask struct {
	path string
	info fs.DirEntry
}

func (p *FileScanPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result
	var mu sync.Mutex

	// 定义要扫描的根目录
	rootDirs := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc", "/tmp", "/var/tmp"}
	// 排除目录，避免死循环或扫描无用文件
	excludeDirs := map[string]bool{
		"/proc": true, "/sys": true, "/dev": true, "/run": true,
	}

	// 任务通道
	tasks := make(chan scanTask, 1000)
	// 结果通道
	resChan := make(chan core.Result, 1000)

	// 启动 Worker 池 (并发数为 20)
	var wg sync.WaitGroup
	workerCount := 20
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				res := p.analyzeFile(task.path, task.info)
				if res != nil {
					resChan <- *res
				}
			}
		}()
	}

	// 结果收集协程
	go func() {
		for res := range resChan {
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}
	}()

	// 遍历文件系统
	for _, root := range rootDirs {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if excludeDirs[path] {
					return filepath.SkipDir
				}
				return nil
			}
			// 发送任务
			tasks <- scanTask{path: path, info: d}
			return nil
		})
	}

	close(tasks)
	wg.Wait()
	close(resChan)

	// 如果没有发现任何威胁，返回 pass 状态
	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "pass",
			Description: "文件系统扫描完成，未发现异常权限或可疑文件",
			Reference:   "已扫描关键系统目录",
		})
	}

	return results, nil
}

func (p *FileScanPlugin) analyzeFile(path string, d fs.DirEntry) *core.Result {
	info, err := d.Info()
	if err != nil {
		return nil
	}

	// 检查 SUID/SGID 权限
	// 这是一个非常经典的提权检测点
	mode := info.Mode()
	if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
		return &core.Result{
			Plugin:      p.Name(),
			Level:       "medium",
			Description: "发现设置了 SUID/SGID 的文件",
			Reference:   path,
			Advice:      "请确认该文件是否需要 SUID 权限，这可能导致权限提升漏洞。",
		}
	}

	// 检查是否是大文件 (大于 100MB), 可能是隐藏的备份或数据包
	if info.Size() > 100*1024*1024 {
		return &core.Result{
			Plugin:      p.Name(),
			Level:       "low",
			Description: "发现超大文件 (>100MB)",
			Reference:   fmt.Sprintf("%s (大小: %.2f MB)", path, float64(info.Size())/1024/1024),
			Advice:      "请确认该文件是否为正常业务数据。",
		}
	}

	// 简单的恶意后缀检查 (Linux 下后缀虽不决定执行，但仍有参考价值)
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".sh" || ext == ".py" || ext == ".pl" || ext == ".php" {
		if strings.HasPrefix(path, "/tmp") || strings.HasPrefix(path, "/var/tmp") {
			return &core.Result{
				Plugin:      p.Name(),
				Level:       "high",
				Description: "临时目录下发现脚本文件",
				Reference:   path,
				Advice:      "临时目录下的脚本极有可能是攻击者上传的工具。",
			}
		}
	}

	return nil
}

// 计算文件 MD5 (辅助函数，暂未在 analyzeFile 全量使用，避免 I/O 过高)
func calcMD5(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
