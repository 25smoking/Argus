package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/25smoking/Argus/internal/config"
	"github.com/25smoking/Argus/internal/core"
	"github.com/25smoking/Argus/internal/embedded"
)

const LockFileName = "rules.lock.json"

type LockFile struct {
	Version   string       `json:"version"`
	UpdatedAt string       `json:"updated_at"`
	Sources   []LockSource `json:"sources"`
	Files     []LockEntry  `json:"files"`
}

type LockSource struct {
	Name        string `json:"name"`
	Source      string `json:"source"`
	URL         string `json:"url"`
	License     string `json:"license"`
	Destination string `json:"destination"`
	ETag        string `json:"etag,omitempty"`
	Enabled     bool   `json:"enabled"`
}

type LockEntry struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	License    string `json:"license"`
	SourceName string `json:"source_name"`
	Compatible bool   `json:"compatible"`
}

type VerifyResult struct {
	OK       bool
	Errors   []string
	Warnings []string
	Lock     *LockFile
}

type Scanner interface {
	Scan(content []byte) []string
	ScanFile(path string, content []byte) []string
	Count() int
	Engine() string
	Stats() []RuleLoadStat
}

type RuleLoadStat struct {
	Category     string
	Files        int
	Rules        int
	SkippedFiles int
}

type downloadedRule struct {
	Destination string
	Body        []byte
	ETag        string
}

type githubContentEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Type        string `json:"type"`
	DownloadURL string `json:"download_url"`
}

func LoadScanner(rulesDir, group string) (Scanner, string, error) {
	if rulesDir == "" {
		rulesDir = "rules"
	}
	groupDir := group + "_rules"
	externalDir := filepath.Join(rulesDir, groupDir)
	if _, err := os.Stat(externalDir); err == nil {
		scanner, err := loadNativeScannerFromDir(externalDir, group)
		if err != nil {
			return nil, "yara-x:external:" + externalDir, err
		}
		return scanner, scanner.Engine() + ":external:" + externalDir, nil
	}

	minDir := "min_rules/" + groupDir
	scanner, err := loadNativeScannerFromFS(embedded.Content, minDir, group)
	if err != nil {
		return nil, "yara-x:embedded:minimal/" + groupDir, err
	}
	return scanner, scanner.Engine() + ":embedded:minimal/" + groupDir, nil
}

func FormatLoadStats(scanner Scanner) []string {
	if scanner == nil {
		return nil
	}
	var lines []string
	skipped := make(map[string]int)
	otherRules := make(map[string]int)
	otherFiles := make(map[string]int)
	for _, stat := range scanner.Stats() {
		if stat.Rules > 0 {
			if stat.Rules < 10 {
				platform := skippedPlatform(stat.Category)
				otherRules[platform] += stat.Rules
				otherFiles[platform] += stat.Files
				continue
			}
			lines = append(lines, fmt.Sprintf("%s加载成功 %d 条（%d 个文件）", stat.Category, stat.Rules, stat.Files))
			continue
		}
		if stat.SkippedFiles > 0 {
			skipped[skippedPlatform(stat.Category)] += stat.SkippedFiles
		}
	}
	for _, platform := range []string{"Windows", "Linux", "macOS", "通用/跨平台", "未知平台"} {
		if rules := otherRules[platform]; rules > 0 {
			lines = append(lines, fmt.Sprintf("%s其他规则加载成功 %d 条（%d 个文件）", platform, rules, otherFiles[platform]))
		}
	}
	for _, platform := range []string{"Windows", "Linux", "macOS", "未知平台"} {
		if count := skipped[platform]; count > 0 {
			lines = append(lines, fmt.Sprintf("%s非当前平台规则已跳过 %d 个文件", platform, count))
		}
	}
	return lines
}

func skippedPlatform(category string) string {
	switch {
	case strings.HasPrefix(category, "Windows"):
		return "Windows"
	case strings.HasPrefix(category, "Linux"):
		return "Linux"
	case strings.HasPrefix(category, "macOS"):
		return "macOS"
	case strings.HasPrefix(category, "通用/跨平台"):
		return "通用/跨平台"
	default:
		return "未知平台"
	}
}

func Status(rulesDir string) (*core.RuleBundleInfo, error) {
	if rulesDir == "" {
		rulesDir = "rules"
	}
	lock, err := ReadLock(rulesDir)
	info := &core.RuleBundleInfo{
		RulesDir: rulesDir,
		LockPath: filepath.Join(rulesDir, LockFileName),
		Status:   "minimal",
		Version:  "minimal",
	}
	if err != nil {
		return info, nil
	}
	info.Version = lock.Version
	info.UpdatedAt = lock.UpdatedAt
	info.Status = "external"
	info.Files = len(lock.Files)
	for _, src := range lock.Sources {
		info.Sources = append(info.Sources, core.RuleSourceInfo{
			Name:    src.Name,
			URL:     src.URL,
			License: src.License,
			Commit:  src.ETag,
			Enabled: src.Enabled,
		})
	}
	return info, nil
}

func ReadLock(rulesDir string) (*LockFile, error) {
	data, err := os.ReadFile(filepath.Join(rulesDir, LockFileName))
	if err != nil {
		return nil, err
	}
	var lock LockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	return &lock, nil
}

func Verify(rulesDir string) VerifyResult {
	result := VerifyResult{OK: true}
	lock, err := ReadLock(rulesDir)
	if err != nil {
		result.OK = false
		result.Errors = append(result.Errors, fmt.Sprintf("缺少或无法读取 %s: %v", LockFileName, err))
		return result
	}
	result.Lock = lock

	for _, entry := range lock.Files {
		path := filepath.Join(rulesDir, filepath.FromSlash(entry.Path))
		sum, size, err := fileSHA256(path)
		if err != nil {
			result.OK = false
			result.Errors = append(result.Errors, fmt.Sprintf("规则文件缺失: %s", entry.Path))
			continue
		}
		if sum != entry.SHA256 || size != entry.Size {
			result.OK = false
			result.Errors = append(result.Errors, fmt.Sprintf("规则文件校验失败: %s", entry.Path))
		}
	}

	for _, group := range []string{"malware", "webshell"} {
		scanner, source, err := LoadScanner(rulesDir, group)
		if err != nil {
			result.OK = false
			result.Errors = append(result.Errors, fmt.Sprintf("%s 规则解析失败: %v", group, err))
			continue
		}
		if strings.HasPrefix(source, "embedded:") {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s 使用最小内置规则，覆盖不足", group))
			continue
		}
		if scanner == nil || scanner.Count() == 0 {
			result.OK = false
			result.Errors = append(result.Errors, fmt.Sprintf("%s 没有可用规则", group))
		}
	}

	if len(result.Errors) > 0 {
		result.OK = false
	}
	return result
}

func Update(ctx context.Context, rulesDir string, sources *config.RuleSourcesConfig) (*LockFile, error) {
	if rulesDir == "" {
		rulesDir = "rules"
	}
	if sources == nil {
		var err error
		sources, err = config.LoadRuleSources("")
		if err != nil {
			return nil, err
		}
	}

	parent := filepath.Dir(rulesDir)
	if parent == "." || parent == "" {
		parent = "."
	}
	if err := os.MkdirAll(parent, 0755); err != nil {
		return nil, err
	}
	tempDir, err := os.MkdirTemp(parent, ".argus-rules-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	client := &http.Client{Timeout: 60 * time.Second}
	lock := &LockFile{
		Version:   "upstream-" + time.Now().UTC().Format("20060102T150405Z"),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	downloaded := 0
	for _, src := range sources.RuleSources {
		if !src.Enabled {
			lock.Sources = append(lock.Sources, LockSource{
				Name: src.Name, Source: src.Source, URL: src.URL, License: src.License,
				Destination: src.Destination, Enabled: false,
			})
			continue
		}
		if src.URL == "" || src.Destination == "" {
			return nil, fmt.Errorf("规则源 %s 缺少 URL 或 destination", src.Name)
		}
		files, err := downloadRuleSource(ctx, client, src)
		if err != nil {
			return nil, fmt.Errorf("下载规则源 %s 失败: %w", src.Name, err)
		}
		lock.Sources = append(lock.Sources, LockSource{
			Name: src.Name, Source: src.Source, URL: src.URL, License: src.License,
			Destination: src.Destination, Enabled: true,
		})
		for _, file := range files {
			dst := filepath.Join(tempDir, filepath.FromSlash(file.Destination))
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(dst, file.Body, 0644); err != nil {
				return nil, err
			}
			downloaded++
			sum := sha256.Sum256(file.Body)
			lock.Files = append(lock.Files, LockEntry{
				Path: filepath.ToSlash(file.Destination), SHA256: hex.EncodeToString(sum[:]),
				Size: int64(len(file.Body)), License: src.License, SourceName: src.Name, Compatible: true,
			})
		}
	}
	if downloaded == 0 {
		return nil, errors.New("没有启用的规则源")
	}

	if err := writeLock(tempDir, lock); err != nil {
		return nil, err
	}
	if verify := Verify(tempDir); !verify.OK {
		return nil, fmt.Errorf("下载后的规则校验失败: %s", strings.Join(verify.Errors, "; "))
	}

	backupDir := rulesDir + ".bak"
	os.RemoveAll(backupDir)
	if _, err := os.Stat(rulesDir); err == nil {
		if err := os.Rename(rulesDir, backupDir); err != nil {
			return nil, fmt.Errorf("备份旧规则失败: %w", err)
		}
	}
	if err := os.Rename(tempDir, rulesDir); err != nil {
		if _, statErr := os.Stat(backupDir); statErr == nil {
			_ = os.Rename(backupDir, rulesDir)
		}
		return nil, fmt.Errorf("替换规则目录失败: %w", err)
	}
	os.RemoveAll(backupDir)
	if err := WriteLicenseSummary(rulesDir, lock); err != nil {
		return nil, err
	}
	return lock, nil
}

func WriteLicenseSummary(rulesDir string, lock *LockFile) error {
	var b strings.Builder
	b.WriteString("# Argus 规则库许可证说明\n\n")
	b.WriteString("本文件由 Argus rules update 生成。规则来源沿用上游许可证，使用前请确认符合你的部署和商业化场景。\n\n")
	b.WriteString("| 规则源 | 上游 | 许可证 | 目标文件 |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, src := range lock.Sources {
		if !src.Enabled {
			continue
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", src.Name, src.Source, src.License, src.Destination))
	}
	return os.WriteFile(filepath.Join(rulesDir, "RULES_LICENSE.md"), []byte(b.String()), 0644)
}

func writeLock(rulesDir string, lock *LockFile) error {
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(rulesDir, LockFileName), data, 0644)
}

func download(ctx context.Context, client *http.Client, url string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Argus-Rules-Updater/3.0")
	if strings.Contains(url, "github.com") || strings.Contains(url, "api.github.com") {
		if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		} else if token := strings.TrimSpace(os.Getenv("GH_TOKEN")); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	return data, resp.Header.Get("ETag"), err
}

func downloadRuleSource(ctx context.Context, client *http.Client, src config.RuleSource) ([]downloadedRule, error) {
	if len(src.AllowPaths) > 0 && strings.Contains(src.URL, "api.github.com/repos/") {
		return downloadGitHubDirectory(ctx, client, src)
	}
	body, etag, err := download(ctx, client, src.URL)
	if err != nil {
		return nil, err
	}
	return []downloadedRule{{Destination: src.Destination, Body: body, ETag: etag}}, nil
}

func downloadGitHubDirectory(ctx context.Context, client *http.Client, src config.RuleSource) ([]downloadedRule, error) {
	body, _, err := download(ctx, client, src.URL)
	if err != nil {
		return nil, err
	}
	var entries []githubContentEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("解析 GitHub contents 响应失败: %w", err)
	}

	baseDest := strings.TrimSuffix(src.Destination, "/")
	if baseDest == "" {
		baseDest = "."
	}

	var targets []githubContentEntry
	for _, entry := range entries {
		if entry.Type != "file" || entry.DownloadURL == "" {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(entry.Name), ".yar") && !strings.HasSuffix(strings.ToLower(entry.Name), ".yara") {
			continue
		}
		if !matchesAnyAllowPath(entry.Name, entry.Path, src.AllowPaths) {
			continue
		}
		targets = append(targets, entry)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("没有匹配 allow_paths 的规则文件")
	}
	fmt.Printf("规则源 %s 匹配 %d 个文件，开始并发下载...\n", src.Name, len(targets))

	var (
		files    []downloadedRule
		mu       sync.Mutex
		wg       sync.WaitGroup
		firstErr error
		errOnce  sync.Once
		done     atomic.Int32
		sem      = make(chan struct{}, 12)
	)
	for _, entry := range targets {
		entry := entry
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				errOnce.Do(func() { firstErr = ctx.Err() })
				return
			}
			ruleBody, etag, err := download(ctx, client, entry.DownloadURL)
			if err != nil {
				errOnce.Do(func() { firstErr = fmt.Errorf("下载 %s 失败: %w", entry.Name, err) })
				return
			}
			mu.Lock()
			files = append(files, downloadedRule{
				Destination: filepath.ToSlash(filepath.Join(baseDest, entry.Name)),
				Body:        ruleBody,
				ETag:        etag,
			})
			mu.Unlock()
			current := done.Add(1)
			if current == 1 || int(current)%50 == 0 || int(current) == len(targets) {
				fmt.Printf("规则源 %s 下载进度: %d/%d\n", src.Name, current, len(targets))
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("没有匹配 allow_paths 的规则文件")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Destination < files[j].Destination })
	return files, nil
}

func matchesAnyAllowPath(name, fullPath string, patterns []string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if ok, _ := filepath.Match(pattern, name); ok {
			return true
		}
		if ok, _ := filepath.Match(pattern, fullPath); ok {
			return true
		}
		if strings.EqualFold(pattern, name) || strings.EqualFold(pattern, fullPath) {
			return true
		}
	}
	return false
}

func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

func PrintList(w io.Writer, rulesDir string, showLicense, showSource bool) error {
	lock, err := ReadLock(rulesDir)
	if err != nil {
		return err
	}
	sort.Slice(lock.Files, func(i, j int) bool { return lock.Files[i].Path < lock.Files[j].Path })
	for _, entry := range lock.Files {
		parts := []string{entry.Path}
		if showSource {
			parts = append(parts, "source="+entry.SourceName)
		}
		if showLicense {
			parts = append(parts, "license="+entry.License)
		}
		fmt.Fprintln(w, strings.Join(parts, " | "))
	}
	return nil
}
