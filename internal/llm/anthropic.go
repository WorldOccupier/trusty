package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type AnthropicProvider struct {
	config ProviderConfig
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model       string              `json:"model"`
	Messages    []anthropicMessage  `json:"messages"`
	System      string              `json:"system,omitempty"`
	Temperature float64             `json:"temperature"`
	MaxTokens   int                 `json:"max_tokens"`
}

type anthropicContent struct {
	Text string `json:"text"`
	Type string `json:"type"`
}

type anthropicResponse struct {
	Content    []anthropicContent `json:"content"`
	StopReason string             `json:"stop_reason"`
}

func (p *AnthropicProvider) Name() string {
	return "anthropic"
}

func (p *AnthropicProvider) AnalyzeCode(ctx context.Context, req AnalysisRequest) (*AnalysisResponse, error) {
	baseURL := p.config.BaseURL
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}

	system := "You are an expert code reviewer specializing in detecting issues in AI-generated code. " +
		"Analyze the code diff and find: " +
		"1. Hallucinated APIs — functions, types, or packages that don't exist " +
		"2. Logic errors — off-by-one, wrong variable, inverted conditional, missing edge case " +
		"3. Security vulnerabilities — injection, hardcoded secrets, unsafe crypto " +
		"4. Missing error handling — unchecked errors, swallowed panics " +
		"5. Wrong function signatures — incorrect parameter types, wrong return values " +
		"For each issue, provide: rule name, severity (error/warning/info), message, line number, and a fix suggestion. " +
		"Focus on the CHANGED lines in the diff. Return findings as JSON array."

	prompt := p.buildPrompt(req)

	body := anthropicRequest{
		Model: p.config.Model,
		Messages: []anthropicMessage{
			{Role: "user", Content: prompt},
		},
		System:      system,
		Temperature: p.config.Temperature,
		MaxTokens:   4096,
	}

	data, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/v1/messages", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("calling anthropic: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("anthropic error %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp anthropicResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	content := ""
	for _, c := range apiResp.Content {
		if c.Type == "text" {
			content += c.Text
		}
	}

	findings := p.parseFindings(content)

	return &AnalysisResponse{
		Findings: findings,
		Summary:  content,
	}, nil
}

func (p *AnthropicProvider) buildPrompt(req AnalysisRequest) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("File: %s\nLanguage: %s\n\n", req.FilePath, req.Language))
	if req.Context != "" {
		b.WriteString(fmt.Sprintf("Context:\n%s\n\n", req.Context))
	}
	b.WriteString(fmt.Sprintf("Diff:\n```\n%s\n```\n\n", req.DiffContent))
	if req.FullContent != "" {
		b.WriteString(fmt.Sprintf("Full file:\n```\n%s\n```\n", req.FullContent))
	}
	return b.String()
}

func (p *AnthropicProvider) parseFindings(content string) []Finding {
	var findings []Finding

	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		if idx := strings.LastIndex(content, "```"); idx >= 0 {
			content = content[:idx]
		}
		content = strings.TrimSpace(content)
	}

	if err := json.Unmarshal([]byte(content), &findings); err != nil {
		findings = append(findings, Finding{
			Rule:     "llm-analysis",
			Severity: SeverityInfo,
			Message:  content,
		})
	}

	return findings
}
