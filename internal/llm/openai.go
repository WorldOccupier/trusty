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

type OpenAIProvider struct {
	config ProviderConfig
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Temperature float64         `json:"temperature"`
}

type openAIChoice struct {
	Message openAIMessage `json:"message"`
}

type openAIResponse struct {
	Choices []openAIChoice `json:"choices"`
}

func (p *OpenAIProvider) Name() string {
	return "openai"
}

func (p *OpenAIProvider) AnalyzeCode(ctx context.Context, req AnalysisRequest) (*AnalysisResponse, error) {
	prompt := p.buildPrompt(req)

	body := openAIRequest{
		Model: p.config.Model,
		Messages: []openAIMessage{
			{Role: "system", Content: `You are an expert code reviewer specializing in detecting issues in AI-generated code.
Analyze the code diff and find:
1. **Hallucinated APIs** — functions, types, or packages that don't exist
2. **Logic errors** — off-by-one, wrong variable, inverted conditional, missing edge case
3. **Security vulnerabilities** — injection, hardcoded secrets, unsafe crypto
4. **Missing error handling** — unchecked errors, swallowed panics
5. **Wrong function signatures** — incorrect parameter types, wrong return values

For each issue, provide: rule name, severity (error/warning/info), message, line number, and a fix suggestion.

Focus on the CHANGED lines in the diff. Return findings as JSON array.`},
			{Role: "user", Content: prompt},
		},
		Temperature: p.config.Temperature,
	}

	data, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.config.BaseURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("calling API: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp openAIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return &AnalysisResponse{}, nil
	}

	content := apiResp.Choices[0].Message.Content
	findings := p.parseFindings(content)

	return &AnalysisResponse{
		Findings: findings,
		Summary:  content,
	}, nil
}

func (p *OpenAIProvider) buildPrompt(req AnalysisRequest) string {
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

func (p *OpenAIProvider) parseFindings(content string) []Finding {
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
