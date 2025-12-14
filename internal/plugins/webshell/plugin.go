package webshell

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/25smoking/Argus/internal/core"
	"github.com/25smoking/Argus/internal/embedded"
	"github.com/25smoking/Argus/internal/forensics"
	"github.com/25smoking/Argus/internal/pkg/yara_lite"
)

type WebshellPlugin struct {
	scanner *yara_lite.Scanner
}

func (p *WebshellPlugin) Name() string {
	return "WebshellScan"
}

func (p *WebshellPlugin) Run(ctx context.Context, config *core.ScanConfig) ([]core.Result, error) {
	var results []core.Result

	// 1. 加载 Webshell 专用规则（仅 thor-webshells.yar）
	ruleDir := "assets/webshell_rules"
	var scanner *yara_lite.Scanner
	var err error

	// 优先尝试外部规则
	if _, statErr := os.Stat(ruleDir); statErr == nil {
		scanner, err = yara_lite.NewScanner(os.DirFS("."), ruleDir)
	} else {
		scanner, err = yara_lite.NewScanner(embedded.Content, ruleDir)
	}

	if err != nil {
		fmt.Printf("Warning: Failed to load Webshell YARA rules from %s: %v. Using basic mode.\n", ruleDir, err)
	} else {
		fmt.Printf("已加载 %d 条 Webshell 检测规则\n", len(scanner.Rules))
	}
	p.scanner = scanner

	var targetDirs []string
	if runtime.GOOS == "windows" {
		targetDirs = []string{"C:\\inetpub", "C:\\xampp\\htdocs", "C:\\Windows\\Temp"}
	} else {
		targetDirs = []string{"/var/www", "/tmp", "/home"}
	}

	extensions := map[string]bool{
		".php": true, ".jsp": true, ".asp": true, ".aspx": true,
		".jspx": true, ".pl": true, ".py": true, ".sh": true,
	}

	for _, root := range targetDirs {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			if !extensions[ext] {
				return nil
			}

			if res := p.scanFile(path); res != nil {
				results = append(results, *res)
			}
			return nil
		})
	}

	// 如果没有发现任何威胁，返回 pass 状态
	if len(results) == 0 {
		results = append(results, core.Result{
			Plugin:      p.Name(),
			Level:       "pass",
			Description: "Webshell 扫描完成，未发现威胁",
			Reference:   fmt.Sprintf("已扫描目录: %v", targetDirs),
		})
	}

	return results, nil
}

func (p *WebshellPlugin) scanFile(path string) *core.Result {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if len(data) > 10*1024*1024 {
		return nil
	}

	// 2. 使用 YARA-Lite 引擎扫描
	// 如果规则加载成功，优先使用下载的规则库
	if p.scanner != nil && len(p.scanner.Rules) > 0 {
		matches := p.scanner.Scan(data)
		if len(matches) > 0 {
			return &core.Result{
				Plugin:      p.Name(),
				Level:       "critical",
				Description: fmt.Sprintf("YARA 规则命中: %s", strings.Join(matches, ", ")),
				Reference:   path,
				Advice:      "检测到已知 Webshell 特征，请立即处置。",
			}
		}
	}

	// 3. 统计学分析：计算熵值
	entropy := forensics.CalculateEntropy(data)

	// 4. 后备：内置简单特征库 + 熵值加权
	content := string(data)
	basicKeywords := []string{
		"eval($_POST", "system($_GET", "shell_exec(", "Runtime.getRuntime().exec(",
		"base64_decode(", "AES/ECB/PKCS5Padding", "FROM base64",
	}
	for _, kw := range basicKeywords {
		if strings.Contains(content, kw) {
			level := "high"
			desc := "发现高危 Webshell 关键字"

			// 如果熵值较高(>5.5)，通常意味着混淆
			if entropy > 5.5 {
				level = "critical"
				desc = fmt.Sprintf("发现高熵值(%.2f)及 Webshell 关键字，极可能为混淆后门", entropy)
			}

			return &core.Result{
				Plugin:      p.Name(),
				Level:       level,
				Description: desc,
				Reference:   fmt.Sprintf("%s (关键字: %s)", path, kw),
				Advice:      "检测到可疑脚本特征，请立即隔离分析。",
			}
		}
	}

	// 5. 纯熵值检测 (针对全加密/高度混淆的 Webshell)
	// 正常源码熵值通常在 4.5~5.5 之间，压缩或加密文件 > 7.5
	if entropy > 7.4 {
		return &core.Result{
			Plugin:      p.Name(),
			Level:       "warning",
			Description: fmt.Sprintf("脚本文件熵值过高(%.2f)，疑似加密载荷", entropy),
			Reference:   path,
			Advice:      "文件内容可能被加密或高度混淆，建议人工审查。",
		}
	}

	return nil
}
