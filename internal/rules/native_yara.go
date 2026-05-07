package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	yara "github.com/hillu/go-yara/v4"
)

type nativeScanner struct {
	rulesets []*yara.Rules
	count    int
	stats    map[string]*RuleLoadStat
}

func (s *nativeScanner) Count() int {
	return s.count
}

func (s *nativeScanner) Engine() string {
	return "libyara"
}

func (s *nativeScanner) Stats() []RuleLoadStat {
	if s == nil || len(s.stats) == 0 {
		return nil
	}
	out := make([]RuleLoadStat, 0, len(s.stats))
	for _, stat := range s.stats {
		out = append(out, *stat)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rules == out[j].Rules {
			return out[i].Category < out[j].Category
		}
		return out[i].Rules > out[j].Rules
	})
	return out
}

func (s *nativeScanner) Scan(content []byte) []string {
	return s.scan("", content)
}

func (s *nativeScanner) ScanFile(path string, content []byte) []string {
	return s.scan(path, content)
}

func (s *nativeScanner) scan(path string, content []byte) []string {
	var matches []string
	seen := make(map[string]bool)
	for _, ruleset := range s.rulesets {
		scanner, err := yara.NewScanner(ruleset)
		if err != nil {
			continue
		}
		defineScanVariables(scanner, path)
		var matched yara.MatchRules
		if err := scanner.SetCallback(&matched).ScanMem(content); err != nil {
			continue
		}
		for _, item := range matched {
			name := item.Rule
			if item.Namespace != "" && item.Namespace != "default" {
				name = item.Namespace + "." + item.Rule
			}
			if !seen[name] {
				matches = append(matches, name)
				seen[name] = true
			}
		}
	}
	return matches
}

func loadNativeScannerFromDir(root, group string) (Scanner, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var compiled []*yara.Rules
	var count int
	var skipped int
	stats := make(map[string]*RuleLoadStat)

	err = filepath.WalkDir(rootAbs, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !isYARAFile(entry.Name()) {
			return nil
		}
		category, load := classifyRuleFile(entry.Name(), group)
		if !load {
			addSkippedStat(stats, category, 1)
			return nil
		}
		compiler, err := newNativeCompiler(rootAbs, path)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			skipped++
			addSkippedStat(stats, category, 1)
			return nil
		}
		err = compiler.AddFile(f, namespaceFromPath(rootAbs, path))
		_ = f.Close()
		if err != nil {
			skipped++
			addSkippedStat(stats, category, 1)
			return nil
		}
		rules, err := compiler.GetRules()
		if err != nil {
			skipped++
			addSkippedStat(stats, category, 1)
			return nil
		}
		compiled = append(compiled, rules)
		ruleCount := len(rules.GetRules())
		count += ruleCount
		addLoadedStat(stats, category, 1, ruleCount)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(compiled) == 0 {
		return nil, fmt.Errorf("libyara 没有成功编译任何规则，跳过 %d 个文件", skipped)
	}
	if skipped > 0 {
		fmt.Printf("libyara 已跳过 %d 个不兼容规则文件\n", skipped)
	}
	return &nativeScanner{rulesets: compiled, count: count, stats: stats}, nil
}

func loadNativeScannerFromFS(fsys fs.FS, root, group string) (Scanner, error) {
	var compiled []*yara.Rules
	var count int
	var skipped int
	stats := make(map[string]*RuleLoadStat)

	err := fs.WalkDir(fsys, root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !isYARAFile(entry.Name()) {
			return nil
		}
		category, load := classifyRuleFile(entry.Name(), group)
		if !load {
			addSkippedStat(stats, category, 1)
			return nil
		}
		body, err := fs.ReadFile(fsys, path)
		if err != nil {
			skipped++
			addSkippedStat(stats, category, 1)
			return nil
		}
		compiler, err := newNativeCompilerForFS(fsys, root)
		if err != nil {
			return err
		}
		if err := compiler.AddString(string(body), namespaceFromPath(root, path)); err != nil {
			skipped++
			addSkippedStat(stats, category, 1)
			return nil
		}
		rules, err := compiler.GetRules()
		if err != nil {
			skipped++
			addSkippedStat(stats, category, 1)
			return nil
		}
		compiled = append(compiled, rules)
		ruleCount := len(rules.GetRules())
		count += ruleCount
		addLoadedStat(stats, category, 1, ruleCount)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(compiled) == 0 {
		return nil, fmt.Errorf("libyara 没有成功编译任何内置规则，跳过 %d 个文件", skipped)
	}
	return &nativeScanner{rulesets: compiled, count: count, stats: stats}, nil
}

func newNativeCompiler(root, currentFile string) (*yara.Compiler, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	defineCompileVariables(compiler)
	compiler.SetIncludeCallback(func(name, filename, namespace string) []byte {
		candidates := []string{
			filepath.Join(filepath.Dir(currentFile), name),
			filepath.Join(root, name),
		}
		if filename != "" {
			candidates = append([]string{filepath.Join(filepath.Dir(filename), name)}, candidates...)
		}
		for _, candidate := range candidates {
			cleaned, err := filepath.Abs(candidate)
			if err != nil || !strings.HasPrefix(cleaned, root+string(os.PathSeparator)) {
				continue
			}
			data, err := os.ReadFile(cleaned)
			if err == nil {
				return data
			}
		}
		return nil
	})
	return compiler, nil
}

func newNativeCompilerForFS(fsys fs.FS, root string) (*yara.Compiler, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	defineCompileVariables(compiler)
	compiler.SetIncludeCallback(func(name, filename, namespace string) []byte {
		candidates := []string{filepath.ToSlash(filepath.Join(root, name))}
		if filename != "" {
			candidates = append([]string{filepath.ToSlash(filepath.Join(filepath.Dir(filename), name))}, candidates...)
		}
		for _, candidate := range candidates {
			data, err := fs.ReadFile(fsys, candidate)
			if err == nil {
				return data
			}
		}
		return nil
	})
	return compiler, nil
}

func defineCompileVariables(compiler *yara.Compiler) {
	_ = compiler.DefineVariable("filepath", "")
	_ = compiler.DefineVariable("filename", "")
	_ = compiler.DefineVariable("extension", "")
	_ = compiler.DefineVariable("filetype", "")
}

func defineScanVariables(scanner *yara.Scanner, path string) {
	filename := ""
	extension := ""
	if path != "" {
		filename = filepath.Base(path)
		extension = strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	}
	_ = scanner.DefineVariable("filepath", path)
	_ = scanner.DefineVariable("filename", filename)
	_ = scanner.DefineVariable("extension", extension)
	_ = scanner.DefineVariable("filetype", extension)
}

func namespaceFromPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	var b strings.Builder
	for _, r := range rel {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	ns := strings.Trim(b.String(), "_")
	if ns == "" {
		return "default"
	}
	return ns
}

func isYARAFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yar") || strings.HasSuffix(lower, ".yara")
}

func addLoadedStat(stats map[string]*RuleLoadStat, category string, files, rules int) {
	stat := ensureStat(stats, category)
	stat.Files += files
	stat.Rules += rules
}

func addSkippedStat(stats map[string]*RuleLoadStat, category string, files int) {
	stat := ensureStat(stats, category)
	stat.SkippedFiles += files
}

func ensureStat(stats map[string]*RuleLoadStat, category string) *RuleLoadStat {
	if category == "" {
		category = "未分类规则"
	}
	stat := stats[category]
	if stat == nil {
		stat = &RuleLoadStat{Category: category}
		stats[category] = stat
	}
	return stat
}

func classifyRuleFile(name, group string) (string, bool) {
	if group == "webshell" {
		return "Webshell规则", true
	}
	platform, family := malwareRuleClass(name)
	target := currentPlatformLabel()
	if platform == "通用/跨平台" || platform == target {
		return platform + family + "规则", true
	}
	return platform + family + "规则", false
}

func malwareRuleClass(name string) (string, string) {
	base := strings.TrimSuffix(strings.TrimSuffix(name, ".yara"), ".yar")
	parts := strings.Split(base, "_")
	first := lowerPart(parts, 0)
	second := lowerPart(parts, 1)

	switch first {
	case "windows":
		return "Windows", familyLabel(second)
	case "linux":
		return "Linux", familyLabel(second)
	case "macos", "mac":
		return "macOS", familyLabel(second)
	case "macosx":
		return "macOS", familyLabel(second)
	case "multi", "mixed":
		return "通用/跨平台", familyLabel(second)
	case "gen":
		if second == "osx" || second == "macos" || second == "mac" {
			return "macOS", familyLabel(lowerPart(parts, 2))
		}
		return "通用/跨平台", "通用"
	case "mal":
		if second == "win" || second == "windows" {
			return "Windows", familyLabel(lowerPart(parts, 2))
		}
		if second == "lnx" || second == "linux" {
			return "Linux", familyLabel(lowerPart(parts, 2))
		}
		return "通用/跨平台", "恶意样本"
	case "apt":
		return "通用/跨平台", "APT"
	case "crime":
		return "通用/跨平台", "黑产"
	case "expl", "exploit", "vul", "vuln", "yara-rules":
		return "通用/跨平台", "漏洞利用"
	case "hktl", "htkl", "thor-hacktools":
		return "通用/跨平台", "黑客工具"
	case "webshell", "thor-webshells":
		return "通用/跨平台", "Webshell"
	case "cn":
		return "通用/跨平台", "中文样本"
	case "thor":
		return "通用/跨平台", "THOR"
	default:
		return "通用/跨平台", familyLabel(first)
	}
}

func lowerPart(parts []string, idx int) string {
	if idx >= len(parts) {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[idx]))
}

func familyLabel(value string) string {
	switch value {
	case "trojan":
		return "木马"
	case "backdoor", "bkdr":
		return "后门"
	case "ransomware", "ransom":
		return "勒索"
	case "rootkit":
		return "Rootkit"
	case "cryptominer", "miner":
		return "挖矿"
	case "exploit", "expl", "vuln", "vul", "cve":
		return "漏洞利用"
	case "hacktool", "hktl", "htkl":
		return "黑客工具"
	case "vulndriver":
		return "漏洞驱动"
	case "pup", "pua":
		return "PUP"
	case "virus":
		return "病毒"
	case "infostealer", "stealer", "spy":
		return "信息窃取"
	case "wiper":
		return "破坏工具"
	case "downloader":
		return "下载器"
	case "proxy":
		return "代理工具"
	case "packer":
		return "加壳"
	case "generic", "general", "configured", "susp", "suspicious", "":
		return "通用"
	case "cn":
		return "中文样本"
	case "thor":
		return "THOR"
	default:
		return strings.ToUpper(value[:1]) + value[1:]
	}
}

func currentPlatformLabel() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	case "darwin":
		return "macOS"
	default:
		return runtime.GOOS
	}
}
