package yara_lite

import (
	"bufio"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
)

// Rule 代表一个简化的 YARA 规则
type Rule struct {
	Name        string
	Tags        []string
	Meta        map[string]string
	Strings     []*regexp.Regexp // 编译好的正则列表
	StringNames []string         // 对应的字符串名称 ($a, $b)
}

// Scanner 是 YARA-Lite 扫描器
type Scanner struct {
	Rules []Rule
}

// NewScanner 加载指定文件系统和目录下的所有 .yar 文件
func NewScanner(fsys fs.FS, ruleDir string) (*Scanner, error) {
	scanner := &Scanner{}

	// 遍历目录
	entries, err := fs.ReadDir(fsys, ruleDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yar") {
			path := filepath.Join(ruleDir, entry.Name())
			// Fix: filepath.Join uses backslash on Windows, but fs.FS strictly uses forward slash
			// We must ensure path uses forward slashes for fs.Open
			path = filepath.ToSlash(path)

			rules, err := parseFile(fsys, path)
			if err != nil {
				fmt.Printf("Warning: Failed to parse %s: %v\n", entry.Name(), err)
				continue
			}
			scanner.Rules = append(scanner.Rules, rules...)
		}
	}

	return scanner, nil
}

// Scan 扫描内容并返回匹配的规则名
func (s *Scanner) Scan(content []byte) []string {
	var matches []string

	// 简单的 "Any String Matches" 逻辑
	for _, rule := range s.Rules {
		matched := false
		for _, re := range rule.Strings {
			if re.Match(content) {
				matched = true
				break
			}
		}

		if matched {
			matches = append(matches, rule.Name)
		}
	}

	return matches
}

// parseFile 解析单个 .yar 文件
func parseFile(fsys fs.FS, path string) ([]Rule, error) {
	file, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []Rule
	var currentRule *Rule
	inStrings := false

	scanner := bufio.NewScanner(file)

	// 正则匹配: rule RuleName {
	reRuleStart := regexp.MustCompile(`^rule\s+([\w_]+)`)
	// 正则匹配: $s = "string" [nocase]
	reString := regexp.MustCompile(`^\s*(\$[\w\d_]+)\s*=\s*(.*)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// 1. 发现新规则
		if match := reRuleStart.FindStringSubmatch(line); len(match) > 1 {
			// 保存上一个规则
			if currentRule != nil {
				rules = append(rules, *currentRule)
			}
			// 开始新规则
			currentRule = &Rule{
				Name: match[1],
				Meta: make(map[string]string),
			}
			inStrings = false
			continue
		}

		if currentRule == nil {
			continue
		}

		if line == "meta:" {
			inStrings = false
			continue
		}
		if line == "strings:" {
			inStrings = true
			continue
		}
		if line == "condition:" {
			inStrings = false
			continue
		}
		if line == "}" {
			continue
		}

		// 2. 解析字符串
		if inStrings {
			if match := reString.FindStringSubmatch(line); len(match) > 2 {
				strName := match[1]
				strValRaw := match[2]

				// 提取修饰符
				nocase := strings.Contains(strings.ToLower(strValRaw), "nocase")

				// 提取内容 "..." 或 /.../
				startQuote := strings.Index(strValRaw, "\"")
				endQuote := strings.LastIndex(strValRaw, "\"")

				if startQuote != -1 && endQuote > startQuote {
					content := strValRaw[startQuote+1 : endQuote]

					// 转义正则元字符
					pattern := regexp.QuoteMeta(content)
					if nocase {
						pattern = "(?i)" + pattern
					}

					re, err := regexp.Compile(pattern)
					if err == nil {
						currentRule.Strings = append(currentRule.Strings, re)
						currentRule.StringNames = append(currentRule.StringNames, strName)
					}
				}
			}
		}
	}

	if currentRule != nil {
		rules = append(rules, *currentRule)
	}

	return rules, nil
}
