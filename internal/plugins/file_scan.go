package plugins

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/25smoking/Argus/internal/config"
	"github.com/25smoking/Argus/internal/core"
)

type FileScanPlugin struct {
	rules *config.FileRules
}

func (p *FileScanPlugin) Name() string {
	return "FileScan"
}

// 扫描任务
type scanTask struct {
	path string
	info fs.DirEntry
}

func (p *FileScanPlugin) Run(ctx context.Context, cfg *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result
	var mu sync.Mutex

	rules, err := config.LoadFileRules(config.GetConfigPath("file_rules.yaml"))
	if err != nil {
		fmt.Printf("Warning: Failed to load file rules: %v. Using built-in minimal detection.\n", err)
		rules = defaultFileRules()
	}
	p.rules = rules

	rootDirs := p.scanRoots()
	excludeDirs := p.excludeDirMap()
	maxFiles := rules.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 20000
	}

	fmt.Printf("已加载文件检测规则: %d 个可疑文件名, %d 个可疑路径, %d 个敏感文件, %d 个内容特征\n",
		len(rules.SuspiciousNames), len(rules.SuspiciousPathPatterns), len(rules.SensitiveFiles), len(rules.SuspiciousContent))
	fmt.Printf("文件扫描范围: %s；文件上限: %d\n", strings.Join(rootDirs, ", "), maxFiles)

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
				for _, res := range p.analyzeFile(task.path, task.info) {
					resChan <- res
				}
			}
		}()
	}

	// 结果收集协程
	done := make(chan struct{})
	go func() {
		defer close(done)
		for res := range resChan {
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}
	}()

	// 遍历文件系统
	fileCount := 0
	for _, root := range rootDirs {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if shouldExcludeDir(path, excludeDirs) {
					return filepath.SkipDir
				}
				return nil
			}
			if fileCount >= maxFiles {
				return filepath.SkipAll
			}
			// 发送任务
			fileCount++
			tasks <- scanTask{path: path, info: d}
			return nil
		})
	}

	close(tasks)
	wg.Wait()
	close(resChan)
	<-done

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

func (p *FileScanPlugin) scanRoots() []string {
	if p.rules != nil && len(p.rules.ScanRoots) > 0 {
		if roots := p.rules.ScanRoots[runtime.GOOS]; len(roots) > 0 {
			return roots
		}
		if roots := p.rules.ScanRoots["default"]; len(roots) > 0 {
			return roots
		}
	}
	switch runtime.GOOS {
	case "windows":
		return []string{`C:\Windows\Temp`, `C:\Users\Public`, `C:\ProgramData`, `C:\Temp`}
	case "darwin":
		return []string{"/etc", "/tmp", "/var/tmp", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/Users"}
	default:
		return []string{"/etc", "/tmp", "/var/tmp", "/dev/shm", "/usr/local/bin", "/var/spool/cron", "/home", "/root"}
	}
}

func (p *FileScanPlugin) excludeDirMap() map[string]bool {
	excludes := []string{"/proc", "/sys", "/dev", "/run", "/Volumes", "/System/Volumes/Data/System", "node_modules", ".git"}
	if p.rules != nil && len(p.rules.ExcludeDirs) > 0 {
		excludes = append(excludes, p.rules.ExcludeDirs...)
	}
	out := make(map[string]bool)
	for _, item := range excludes {
		out[filepath.Clean(item)] = true
	}
	return out
}

func shouldExcludeDir(path string, excludes map[string]bool) bool {
	clean := filepath.Clean(path)
	if excludes[clean] {
		return true
	}
	base := filepath.Base(clean)
	if excludes[base] {
		return true
	}

	slashPath := filepath.ToSlash(clean)
	for item := range excludes {
		slashItem := filepath.ToSlash(item)
		if strings.Contains(slashItem, "/") && (strings.HasSuffix(slashPath, slashItem) || strings.Contains(slashPath, "/"+slashItem+"/")) {
			return true
		}
	}
	return false
}

func (p *FileScanPlugin) analyzeFile(path string, d fs.DirEntry) []core.Result {
	info, err := d.Info()
	if err != nil {
		return nil
	}

	var results []core.Result
	pathLower := strings.ToLower(path)
	nameLower := strings.ToLower(d.Name())
	ext := strings.ToLower(filepath.Ext(path))
	mode := info.Mode()

	// 检查 SUID/SGID 权限
	// 这是一个非常经典的提权检测点
	if runtime.GOOS != "windows" && (mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0) && !p.allowedSUID(path) {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "medium",
			Description: "发现设置了 SUID/SGID 的文件",
			Reference:   path,
			Advice:      "请确认该文件是否需要 SUID 权限，这可能导致权限提升漏洞。",
			Score:       55,
			Confidence:  65,
			Evidence:    []string{fmt.Sprintf("mode=%s", mode.String())},
			RuleName:    "file_permissions/suid_sgid",
			RuleSource:  "file_rules.yaml",
		})
	}

	// 检查是否是大文件 (大于 100MB), 可能是隐藏的备份或数据包
	largeFileMB := int64(100)
	if p.rules != nil && p.rules.LargeFileMB > 0 {
		largeFileMB = p.rules.LargeFileMB
	}
	if info.Size() > largeFileMB*1024*1024 && inSuspiciousDropDir(pathLower) {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "low",
			Description: fmt.Sprintf("可疑落点发现超大文件 (>%dMB)", largeFileMB),
			Reference:   fmt.Sprintf("%s (大小: %.2f MB)", path, float64(info.Size())/1024/1024),
			Advice:      "请确认该文件是否为正常业务数据。",
			Score:       35,
			Confidence:  55,
			RuleName:    "file_size/large_file_in_drop_dir",
			RuleSource:  "file_rules.yaml",
		})
	}

	if p.isTempScript(pathLower, ext) {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "high",
			Description: "临时目录下发现脚本文件",
			Reference:   path,
			Advice:      "临时目录下的脚本可能是攻击者上传或落地的工具，请结合创建时间、父进程和 YARA 结果复核。",
			Score:       78,
			Confidence:  75,
			Evidence:    []string{fmt.Sprintf("mtime=%s", info.ModTime().Format(time.RFC3339))},
			RuleName:    "file_drop/temp_script",
			RuleSource:  "file_rules.yaml",
		})
	}

	if isExecutable(mode, ext, p.rules) && inSuspiciousDropDir(pathLower) {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "high",
			Description: "可疑落点发现可执行文件",
			Reference:   path,
			Advice:      "攻击工具常落在临时目录、公共目录或用户目录隐藏路径，建议做哈希、签名和 YARA 复核。",
			Score:       80,
			Confidence:  75,
			Evidence:    []string{fmt.Sprintf("mode=%s", mode.String())},
			RuleName:    "file_drop/executable_in_drop_dir",
			RuleSource:  "file_rules.yaml",
		})
	}

	for _, rule := range p.rules.SuspiciousNames {
		if matchPattern(rule.Pattern, nameLower) {
			results = append(results, p.ruleResult(rule.Level, rule.Description, path, "file_name/"+rule.Pattern, nil))
		}
	}

	for _, rule := range p.rules.SuspiciousPathPatterns {
		if matchPattern(rule.Pattern, pathLower) {
			results = append(results, p.ruleResult(rule.Level, rule.Description, path, "file_path/"+rule.Pattern, nil))
		}
	}

	for _, rule := range p.rules.SensitiveFiles {
		if matchPattern(rule.Pattern, pathLower) {
			results = append(results, p.ruleResult(rule.Level, rule.Description, path, "sensitive_file/"+rule.Pattern, nil))
		}
	}

	if info.Size() > 0 && shouldReadSmallContent(info, p.rules) {
		if contentResults := p.scanSmallFileContent(path, ext); len(contentResults) > 0 {
			results = append(results, contentResults...)
		}
	}

	return results
}

func (p *FileScanPlugin) ruleResult(level, description, path, ruleName string, evidence []string) core.Result {
	return core.Result{
		Plugin:      p.Name(),
		Level:       defaultLevel(level, "medium"),
		Description: description,
		Reference:   path,
		Advice:      "发现可疑文件特征，请结合文件来源、修改时间、签名、哈希和 YARA 命中情况复核。",
		Score:       scoreForFileLevel(level),
		Confidence:  70,
		Evidence:    evidence,
		RuleName:    ruleName,
		RuleSource:  "file_rules.yaml",
	}
}

func (p *FileScanPlugin) allowedSUID(path string) bool {
	if p.rules == nil {
		return false
	}
	for _, allowed := range p.rules.AllowedSUIDPaths {
		if filepath.Clean(path) == filepath.Clean(allowed) {
			return true
		}
	}
	return false
}

func (p *FileScanPlugin) isTempScript(pathLower, ext string) bool {
	if !inTempDir(pathLower) {
		return false
	}
	extensions := []string{".sh", ".py", ".pl", ".php", ".jsp", ".js", ".rb", ".lua", ".command"}
	if p.rules != nil && len(p.rules.TempScriptExtensions) > 0 {
		extensions = p.rules.TempScriptExtensions
	}
	for _, item := range extensions {
		if strings.EqualFold(ext, item) {
			return true
		}
	}
	return false
}

func inTempDir(pathLower string) bool {
	return strings.HasPrefix(pathLower, "/tmp/") ||
		strings.HasPrefix(pathLower, "/var/tmp/") ||
		strings.Contains(pathLower, `\temp\`) ||
		strings.Contains(pathLower, `/temporaryitems/`)
}

func inSuspiciousDropDir(pathLower string) bool {
	return inTempDir(pathLower) ||
		strings.Contains(pathLower, "/dev/shm/") ||
		strings.Contains(pathLower, "/users/shared/") ||
		strings.Contains(pathLower, `\users\public\`) ||
		strings.Contains(pathLower, `\programdata\`)
}

func isExecutable(mode fs.FileMode, ext string, rules *config.FileRules) bool {
	if runtime.GOOS != "windows" && mode&0111 != 0 {
		return true
	}
	extensions := []string{".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".dylib", ".so"}
	if rules != nil && len(rules.ExecutableExtensions) > 0 {
		extensions = rules.ExecutableExtensions
	}
	for _, item := range extensions {
		if strings.EqualFold(ext, item) {
			return true
		}
	}
	return false
}

func matchPattern(pattern, value string) bool {
	if pattern == "" {
		return false
	}
	re, err := regexp.Compile(pattern)
	if err == nil {
		return re.MatchString(value)
	}
	return strings.Contains(value, strings.ToLower(pattern))
}

func shouldReadSmallContent(info fs.FileInfo, rules *config.FileRules) bool {
	limitKB := int64(256)
	if rules != nil && rules.SmallFileContentMaxKB > 0 {
		limitKB = rules.SmallFileContentMaxKB
	}
	return info.Size() <= limitKB*1024
}

func (p *FileScanPlugin) scanSmallFileContent(path, ext string) []core.Result {
	if p.rules == nil || len(p.rules.SuspiciousContent) == 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := strings.ToLower(string(data))
	pathLower := strings.ToLower(filepath.ToSlash(path))
	var results []core.Result
	for _, rule := range p.rules.SuspiciousContent {
		if len(rule.Extensions) > 0 && !stringInFold(ext, rule.Extensions) {
			continue
		}
		if len(rule.Paths) > 0 && !matchesAnyPattern(rule.Paths, pathLower) {
			continue
		}
		if matchPattern(rule.Pattern, content) {
			results = append(results, p.ruleResult(rule.Level, rule.Description, path, "file_content/"+rule.Pattern, []string{"content_pattern=" + rule.Pattern}))
		}
	}
	return results
}

func matchesAnyPattern(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if matchPattern(pattern, value) {
			return true
		}
	}
	return false
}

func stringInFold(value string, items []string) bool {
	for _, item := range items {
		if strings.EqualFold(value, item) {
			return true
		}
	}
	return false
}

func scoreForFileLevel(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 95
	case "high":
		return 82
	case "medium":
		return 60
	case "low":
		return 35
	default:
		return 50
	}
}

func defaultFileRules() *config.FileRules {
	return &config.FileRules{
		ScanRoots: map[string][]string{
			"default": {"/etc", "/tmp", "/var/tmp"},
		},
		MaxFiles:              20000,
		LargeFileMB:           100,
		SmallFileContentMaxKB: 256,
		TempScriptExtensions:  []string{".sh", ".py", ".pl", ".php", ".jsp", ".js"},
	}
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
