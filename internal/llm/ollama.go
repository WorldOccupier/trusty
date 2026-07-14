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

type OllamaProvider struct {
	config ProviderConfig
}

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type ollamaResponse struct {
	Message openAIMessage `json:"message"`
}

func (p *OllamaProvider) Name() string {
	return "ollama"
}

func (p *OllamaProvider) AnalyzeCode(ctx context.Context, req AnalysisRequest) (*AnalysisResponse, error) {
	baseURL := p.config.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	prompt := fmt.Sprintf(`Analyze this code diff and find issues in AI-generated code:

File: %s
Language: %s

Diff:
%s

Find:
1. Hallucinated APIs or imports that don't exist
2. Logic errors (off-by-one, wrong variable, inverted conditional)
3. Security vulnerabilities
4. Missing error handling
Return findings as JSON array with fields: rule, severity, message, line, suggestion.`,
		req.FilePath, req.Language, req.DiffContent)

	body := ollamaRequest{
		Model: p.config.Model,
		Messages: []openAIMessage{
			{Role: "user", Content: prompt},
		},
		Stream: false,
	}

	data, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/api/chat", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("calling ollama: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ollama error %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp ollamaResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	content := apiResp.Message.Content
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

	return &AnalysisResponse{Findings: findings, Summary: content}, nil
}
