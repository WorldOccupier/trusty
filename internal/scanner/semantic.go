package scanner

import (
	"context"
	"fmt"

	"github.com/WorldOccupier/trusty/internal/llm"
	"github.com/WorldOccupier/trusty/internal/types"
)

type SemanticAnalyzer struct {
	provider llm.Provider
}

func NewSemanticAnalyzer(provider llm.Provider) *SemanticAnalyzer {
	return &SemanticAnalyzer{provider: provider}
}

func (s *SemanticAnalyzer) Analyze(ctx context.Context, file types.DiffFile, projectContext string) ([]types.Finding, error) {
	if s.provider == nil {
		return nil, nil
	}

	req := llm.AnalysisRequest{
		FilePath:    file.Path,
		Language:    file.Language,
		DiffContent: file.Diff,
		FullContent: file.Content,
		Context:     projectContext,
	}

	resp, err := s.provider.AnalyzeCode(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("semantic analysis: %w", err)
	}

	var findings []types.Finding
	for _, f := range resp.Findings {
		sev := types.SeverityWarning
		switch f.Severity {
		case llm.SeverityError:
			sev = types.SeverityError
		case llm.SeverityWarning:
			sev = types.SeverityWarning
		case llm.SeverityInfo:
			sev = types.SeverityInfo
		}

		findings = append(findings, types.Finding{
			Rule:       f.Rule,
			Severity:   sev,
			Message:    f.Message,
			Line:       f.Line,
			Column:     f.Column,
			Suggestion: f.Suggestion,
			Category:   "semantic-analysis",
		})
	}

	return findings, nil
}
