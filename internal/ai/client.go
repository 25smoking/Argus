package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type AnalysisResult struct {
	Summary     string `json:"summary"`
	Suggestions string `json:"suggestions"`
}

// AnalyzeRequest 发送给 AI 的分析请求
func AnalyzeReport(modelType, apiKey, reportJson string) (string, error) {
	prompt := fmt.Sprintf(`你是 Argus 智能安全专家。请分析以下 Argus 扫描生成的 JSON 报告，并给出专业的分析结论和处置建议。
重点关注：1. 攻击者可能的入侵路径；2. 存在的持久化后门；3. 紧急处置建议。
请保持输出简洁明了。

被分析的扫描报告内容：
%s`, reportJson)

	switch modelType {
	case "deepseek":
		return callDeepSeek(apiKey, prompt)
	case "gemini":
		return callGemini(apiKey, prompt)
	default:
		return "", fmt.Errorf("不支持的模型类型: %s", modelType)
	}
}

// DeepSeek (兼容 OpenAI 格式)
func callDeepSeek(apiKey, prompt string) (string, error) {
	url := "https://api.deepseek.com/v1/chat/completions"

	payload := map[string]interface{}{
		"model": "deepseek-chat",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0.1,
	}

	return sendRequest(url, apiKey, payload)
}

// Google Gemini (REST API)
func callGemini(apiKey, prompt string) (string, error) {
	// Gemini Pro 1.5
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=%s", apiKey)

	payload := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
	}

	// Gemini API 通常不需要 Bearer Token，key 在 URL 中，但这里通用函数可能有 Header，需注意
	// 为了复用 sendRequest，我们稍作修改或独立实现
	// 这里简单起见，独立实现一个简单的 Gemini 请求，复用 sendRequest逻辑可能需要调整 Header

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// 增加超时时间到5分钟，DeepSeek处理大量数据时需要更长时间
	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API error: %d", resp.StatusCode)
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Candidates) > 0 && len(result.Candidates[0].Content.Parts) > 0 {
		return result.Candidates[0].Content.Parts[0].Text, nil
	}
	return "AI 未返回有效内容", nil
}

func sendRequest(url, apiKey string, payload interface{}) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	// 增加超时时间到5分钟，DeepSeek处理大量数据时需要更长时间
	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 简单处理响应，适配 OpenAI 格式
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API error: %d", resp.StatusCode)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Choices) > 0 {
		return result.Choices[0].Message.Content, nil
	}
	return "AI 未返回有效内容", nil
}
