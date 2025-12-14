package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/25smoking/Argus/internal/config"
	"github.com/25smoking/Argus/internal/core"
	winsys "github.com/25smoking/Argus/internal/sys/windows"
)

type ThreatIntelPlugin struct{}

func (p *ThreatIntelPlugin) Name() string {
	return "ThreatIntel"
}

func (p *ThreatIntelPlugin) Run(ctx context.Context, scanConfig *core.ScanConfig) ([]core.Result, error) {
	// 加载配置
	cfgPath := config.GetConfigPath("threat_intel.yaml")
	tiConfig, err := config.LoadThreatIntelConfig(cfgPath)
	if err != nil {
		// 如果配置文件出错，不阻塞其他插件，只是返回空
		return nil, nil
	}

	if !tiConfig.ThreatIntel.Enabled {
		return nil, nil // 未启用
	}

	var results []core.Result
	client := &http.Client{
		Timeout: time.Duration(tiConfig.ThreatIntel.Timeout) * time.Second,
	}

	// 1. IP 威胁情报 (VirusTotal / AbuseIPDB)
	if tiConfig.ThreatIntel.Sources.AbuseIPDB.Enabled || tiConfig.ThreatIntel.Sources.VirusTotal.CheckIP {
		ipResults := p.scanIPs(client, tiConfig)
		results = append(results, ipResults...)
	}

	// 2. 文件 Hash 威胁情报 (VirusTotal)
	if tiConfig.ThreatIntel.Sources.VirusTotal.Enabled && tiConfig.ThreatIntel.Sources.VirusTotal.CheckHash {
		hashResults := p.scanFileHashes(client, tiConfig)
		results = append(results, hashResults...)
	}

	return results, nil
}

// --------------------------------------------------------------------------
// IP Scanning Logic
// --------------------------------------------------------------------------

func (p *ThreatIntelPlugin) scanIPs(client *http.Client, cfg *config.ThreatIntelConfig) []core.Result {
	conns, err := winsys.GetTcpConnections()
	if err != nil {
		return nil
	}

	uniqueIPs := make(map[string]bool)
	for _, conn := range conns {
		// skip loopback and private IPs (simple check)
		if isPublicIP(conn.RemoteAddr) {
			uniqueIPs[conn.RemoteAddr] = true
		}
	}

	var results []core.Result
	count := 0
	limit := cfg.ThreatIntel.MaxIPsPerScan

	for ip := range uniqueIPs {
		if count >= limit {
			break
		}

		// AbuseIPDB Check
		if cfg.ThreatIntel.Sources.AbuseIPDB.Enabled {
			res := checkAbuseIPDB(client, ip, cfg)
			if res != nil {
				results = append(results, *res)
			}
		}

		// VirusTotal IP Check
		// (Optional logic here, skipping to save quota for Hash)

		count++
		time.Sleep(500 * time.Millisecond) // Rate limit
	}
	return results
}

func isPublicIP(ip string) bool {
	// 简单过滤：忽略 127.0.0.1, 10., 192.168.
	if ip == "0.0.0.0" || strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "172.16.") {
		return false
	}
	return true
}

func checkAbuseIPDB(client *http.Client, ip string, cfg *config.ThreatIntelConfig) *core.Result {
	url := "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Key", cfg.ThreatIntel.Sources.AbuseIPDB.APIKey)
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	var data struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			Domain               string `json:"domain"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	score := data.Data.AbuseConfidenceScore
	if score > 20 { // Confidence > 20%
		level := "medium"
		if score > 80 {
			level = "critical"
		}
		return &core.Result{
			Plugin:      "ThreatIntel",
			Level:       level,
			Description: fmt.Sprintf("恶意IP地址: %s (AbuseIPDB Score: %d)", ip, score),
			Reference:   fmt.Sprintf("Country: %s, Domain: %s", data.Data.CountryCode, data.Data.Domain),
			Advice:      "该 IP 被威胁情报标记为恶意，建议阻断。",
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// Hash Scanning Logic
// --------------------------------------------------------------------------

func (p *ThreatIntelPlugin) scanFileHashes(client *http.Client, cfg *config.ThreatIntelConfig) []core.Result {
	procs, err := winsys.GetProcessList()
	if err != nil {
		return nil
	}

	// Filter Whitelist
	whitelist := make(map[string]bool)
	for _, name := range cfg.ThreatIntel.WhitelistProcesses {
		whitelist[strings.ToLower(name)] = true
	}

	uniqueHashes := make(map[string]string) // hash -> path
	count := 0
	limit := cfg.ThreatIntel.MaxHashesPerScan

	for _, proc := range procs {
		if count >= limit {
			break
		}
		if whitelist[strings.ToLower(proc.Name)] {
			continue
		}

		path, err := winsys.GetProcessExePath(proc.PID)
		if err != nil {
			continue
		}

		// Calculate Hash
		hash, err := calculateSHA256(path)
		if err != nil {
			continue
		}

		if _, exists := uniqueHashes[hash]; !exists {
			uniqueHashes[hash] = path
			count++
		}
	}

	var results []core.Result
	for hash, path := range uniqueHashes {
		res := checkVirusTotalHash(client, hash, cfg, path)
		if res != nil {
			results = append(results, *res)
		}
		time.Sleep(15 * time.Second) // VirusTotal Free Tier: 4 requests/min = 1 req / 15s
	}

	return results
}

func calculateSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func checkVirusTotalHash(client *http.Client, hash string, cfg *config.ThreatIntelConfig, path string) *core.Result {
	url := "https://www.virustotal.com/api/v3/files/" + hash
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("x-apikey", cfg.ThreatIntel.Sources.VirusTotal.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil // Not found (unknown file)
	}
	if resp.StatusCode != 200 {
		return nil
	}

	var data struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	malicious := data.Data.Attributes.LastAnalysisStats.Malicious
	if malicious > 0 {
		level := "medium"
		if malicious > 5 {
			level = "critical"
		}

		return &core.Result{
			Plugin:      "ThreatIntel",
			Level:       level,
			Description: fmt.Sprintf("恶意文件(VT): %s (检出率: %d)", filepath.Base(path), malicious),
			Reference:   fmt.Sprintf("Hash: %s, Path: %s", hash, path),
			Advice:      "文件被多个杀毒引擎标记为恶意，请立即隔离。",
		}
	}
	return nil
}
