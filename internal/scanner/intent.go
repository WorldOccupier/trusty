package scanner

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/WorldOccupier/trusty/internal/llm"
	"github.com/WorldOccupier/trusty/internal/types"
)

type IntentAnalyzer struct {
	llmProvider llm.Provider
}

func NewIntentAnalyzer(provider llm.Provider) *IntentAnalyzer {
	return &IntentAnalyzer{llmProvider: provider}
}

type IntentResult struct {
	File     string          `json:"file"`
	Findings []types.Finding `json:"findings"`
	Intent   string          `json:"intent,omitempty"`
}

func (a *IntentAnalyzer) Analyze(ctx context.Context, files []types.DiffFile, opts types.DiffOptions) ([]IntentResult, error) {
	commitMsg := a.getCommitMessages(opts)
	if commitMsg == "" {
		commitMsg = "No commit message available"
	}

	var results []IntentResult

	for _, file := range files {
		if file.Language != "go" && file.Language != "python" && file.Language != "javascript" && file.Language != "typescript" {
			continue
		}
		if a.llmProvider == nil {
			continue
		}

		result, err := a.analyzeFile(ctx, file, commitMsg)
		if err != nil {
			return results, fmt.Errorf("analyzing %s: %w", file.Path, err)
		}
		results = append(results, result)
	}

	return results, nil
}

func (a *IntentAnalyzer) analyzeFile(ctx context.Context, file types.DiffFile, commitMsg string) (IntentResult, error) {
	intentContext := fmt.Sprintf("INTENT (from commit message): %s\n\nAnalyze whether the code correctly implements this intent. Flag any mismatches, missing pieces, or contradictory implementations.", commitMsg)
	req := llm.AnalysisRequest{
		FilePath:    file.Path,
		Language:    file.Language,
		DiffContent: file.Diff,
		FullContent: file.Content,
		Context:     intentContext,
	}

	resp, err := a.llmProvider.AnalyzeCode(ctx, req)
	if err != nil {
		return IntentResult{File: file.Path}, fmt.Errorf("LLM analysis: %w", err)
	}

	var findings []types.Finding
	for _, f := range resp.Findings {
		findings = append(findings, types.Finding{
			Rule:       f.Rule,
			Severity:   mapLLMSeverity(f.Severity),
			Message:    f.Message,
			Line:       f.Line,
			Column:     f.Column,
			Suggestion: f.Suggestion,
			Category:   "intent",
		})
	}

	return IntentResult{
		File:     file.Path,
		Findings: findings,
		Intent:   commitMsg,
	}, nil
}

func (a *IntentAnalyzer) getCommitMessages(opts types.DiffOptions) string {
	var args []string
	switch {
	case opts.From != "" && opts.To != "":
		args = []string{"log", "--oneline", fmt.Sprintf("%s..%s", opts.From, opts.To)}
	case opts.From != "":
		args = []string{"log", "--oneline", "-5", opts.From}
	default:
		args = []string{"log", "--oneline", "-1"}
	}

	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	msg := strings.TrimSpace(string(out))
	if idx := strings.Index(msg, " "); idx > 0 && len(msg) > 50 {
		msg = msg[idx+1:]
	}

	return msg
}

func mapLLMSeverity(s llm.Severity) types.Severity {
	switch s {
	case llm.SeverityError:
		return types.SeverityError
	case llm.SeverityWarning:
		return types.SeverityWarning
	case llm.SeverityInfo:
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}
