package windows

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/25smoking/Argus/internal/core"
	"github.com/25smoking/Argus/internal/forensics"
	"golang.org/x/sys/windows/registry"
)

type ForensicsPlugin struct{}

func (p *ForensicsPlugin) Name() string {
	return "ForensicsScan"
}

func (p *ForensicsPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result

	// 1. Prefetch 分析
	pfResults := p.analyzePrefetch()
	results = append(results, pfResults...)

	// 2. ShimCache 分析
	scResults := p.analyzeShimCache()
	results = append(results, scResults...)

	// 3. LNK 快捷方式分析
	lnkResults := p.analyzeLNK()
	results = append(results, lnkResults...)

	return results, nil
}

func (p *ForensicsPlugin) analyzeLNK() []core.Result {
	var results []core.Result
	userHome, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	recentDir := filepath.Join(userHome, "AppData", "Roaming", "Microsoft", "Windows", "Recent")

	files, err := os.ReadDir(recentDir)
	if err != nil {
		return nil
	}

	for _, f := range files {
		if strings.HasSuffix(strings.ToLower(f.Name()), ".lnk") {
			info, err := forensics.ParseLnk(filepath.Join(recentDir, f.Name()))
			if err != nil {
				continue
			}

			// Check targets for suspicious executables
			targetUpper := strings.ToUpper(info.TargetPath)
			suspicious := []string{"CMD.EXE", "POWERSHELL.EXE", "MSHTA.EXE", "RUNDLL32.EXE", "WCRIPT.EXE", "CSCRIPT.EXE"}

			for _, kw := range suspicious {
				if strings.Contains(targetUpper, kw) {
					results = append(results, core.Result{
						Plugin:      p.Name(),
						Level:       "low", // Recent execution is less critical than Prefetch/ShimCache usually, unless explicitly malicious
						Description: fmt.Sprintf("Recent LNK: 最近访问了敏感程序 %s", kw),
						Reference:   fmt.Sprintf("LNK: %s -> %s (Access: %s)", f.Name(), info.TargetPath, info.HeaderTimes[1].Format(time.RFC3339)),
					})
					break
				}
			}
		}
	}
	return results
}

func (p *ForensicsPlugin) analyzePrefetch() []core.Result {
	var results []core.Result
	pfDir := os.Getenv("SystemRoot") + "\\Prefetch"

	// 定义关注的高危进程列表
	suspiciousBins := map[string]bool{
		"POWERSHELL.EXE": true, "CMD.EXE": true, "CERTUTIL.EXE": true,
		"BITSADMIN.EXE": true, "RUNDLL32.EXE": true, "REGSVR32.EXE": true,
		"MSHTA.EXE": true, "MIMIKATZ.EXE": true, "CS.EXE": true,
		"COBALTSTRIKE.EXE": true,
	}

	files, err := os.ReadDir(pfDir)
	if err != nil {
		return nil
	}

	for _, f := range files {
		if strings.HasSuffix(strings.ToLower(f.Name()), ".pf") {
			info, err := forensics.ParsePrefetch(filepath.Join(pfDir, f.Name()))
			if err != nil {
				continue
			}

			// 检查是否为高危进程
			exeName := strings.ToUpper(info.ExecutableName)
			// Prefetch 文件名通常是 EXE-HASH.pf，解析出的 ExecutableName 才是准的
			// 不过有时 ParsePrefetch 失败的话，文件名也能参考

			if suspiciousBins[exeName] {
				// 获取最近一次运行时间
				lastRun := time.Time{}
				if len(info.LastRunTimes) > 0 {
					lastRun = info.LastRunTimes[0]
				}

				results = append(results, core.Result{
					Plugin:      p.Name(),
					Level:       "high",
					Description: fmt.Sprintf("Prefetch: 发现高危程序执行记录 %s", exeName),
					Reference:   fmt.Sprintf("运行次数: %d, 最近运行: %s, Hash: %x", info.RunCount, lastRun.Format(time.RFC3339), info.Hash),
				})
			}
		}
	}
	return results
}

func (p *ForensicsPlugin) analyzeShimCache() []core.Result {
	var results []core.Result

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`, registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()

	data, _, err := k.GetBinaryValue("AppCompatCache")
	if err != nil {
		return nil
	}

	entries, err := forensics.ParseShimCache(data)
	if err != nil {
		return nil
	}

	// 简单的关键词匹配检测
	for _, entry := range entries {
		pathLower := strings.ToLower(entry.Path)
		if strings.Contains(pathLower, "\\temp\\") ||
			strings.Contains(pathLower, "\\users\\public\\") {

			// 如果是 .exe/.dll/.sys
			if strings.HasSuffix(pathLower, ".exe") || strings.HasSuffix(pathLower, ".dll") {
				results = append(results, core.Result{
					Plugin:      p.Name(),
					Level:       "medium",
					Description: "ShimCache: 发现临时目录下的可执行文件记录",
					Reference:   fmt.Sprintf("路径: %s, 修改时间: %s", entry.Path, entry.LastModified.Format(time.RFC3339)),
				})
			}
		}
	}

	return results
}
