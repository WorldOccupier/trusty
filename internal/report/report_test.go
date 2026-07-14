package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/WorldOccupier/trusty/internal/types"
)

func makeTestResult() types.ScanResult {
	return types.ScanResult{
		TrustScore: 85,
		Timestamp:  "2026-01-01T00:00:00Z",
		DurationMs: 150,
		Files: []types.FileResult{
			{
				Path:     "main.go",
				Language: "go",
				Score:    85,
				Findings: []types.Finding{
					{
						Rule:       "unused-import",
						Severity:   types.SeverityWarning,
						Message:    "Unused import: fmt",
						Line:       3,
						Column:     1,
						Suggestion: "Remove unused import",
						Category:   "static-analysis",
					},
				},
			},
			{
				Path:     "app.py",
				Language: "python",
				Score:    100,
				Findings: nil,
			},
		},
		Summary: types.ScanSummary{
			TotalIssues:  1,
			Errors:       0,
			Warnings:     1,
			Info:         0,
			FilesScanned: 2,
			Duration:     "150ms",
			Status:       "warning",
			MinScore:     70,
		},
	}
}

func TestWriteJSON(t *testing.T) {
	result := makeTestResult()
	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var decoded types.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.TrustScore != 85 {
		t.Errorf("TrustScore = %d, want 85", decoded.TrustScore)
	}
	if decoded.Summary.TotalIssues != 1 {
		t.Errorf("TotalIssues = %d, want 1", decoded.Summary.TotalIssues)
	}
	if len(decoded.Files) != 2 {
		t.Errorf("len(Files) = %d, want 2", len(decoded.Files))
	}
}

func TestFormatJSON(t *testing.T) {
	result := makeTestResult()
	got, err := FormatJSON(result)
	if err != nil {
		t.Fatalf("FormatJSON error: %v", err)
	}
	if !strings.Contains(got, `"trust_score": 85`) {
		t.Errorf("output missing trust_score: %s", got)
	}
	if !strings.Contains(got, `"total_issues": 1`) {
		t.Errorf("output missing total_issues: %s", got)
	}
}

func TestWriteSARIF(t *testing.T) {
	result := makeTestResult()
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, &result); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var sarif SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("unmarshal SARIF error: %v", err)
	}

	if sarif.Version != "2.1.0" {
		t.Errorf("Version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("len(Runs) = %d, want 1", len(sarif.Runs))
	}

	run := sarif.Runs[0]
	if run.Tool.Driver.Name != "Trusty" {
		t.Errorf("Tool name = %q, want Trusty", run.Tool.Driver.Name)
	}
	if len(run.Results) != 1 {
		t.Fatalf("len(Results) = %d, want 1", len(run.Results))
	}

	result0 := run.Results[0]
	if result0.RuleID != "unused-import" {
		t.Errorf("RuleID = %q, want unused-import", result0.RuleID)
	}
	if result0.Level != "warning" {
		t.Errorf("Level = %q, want warning", result0.Level)
	}

	if len(run.Tool.Driver.Rules) == 0 {
		t.Error("no rules defined in SARIF output")
	}
}

func TestParseResult(t *testing.T) {
	result := makeTestResult()
	data, _ := json.Marshal(result)

	parsed := ParseResult(data)
	if parsed == nil {
		t.Fatal("ParseResult returned nil")
	}
	if parsed.TrustScore != 85 {
		t.Errorf("TrustScore = %d, want 85", parsed.TrustScore)
	}
}

func TestParseResult_Invalid(t *testing.T) {
	parsed := ParseResult([]byte(`invalid`))
	if parsed != nil {
		t.Errorf("expected nil for invalid input, got %v", parsed)
	}
}

func TestFormatHTML(t *testing.T) {
	result := makeTestResult()
	got, err := FormatHTML(result)
	if err != nil {
		t.Fatalf("FormatHTML error: %v", err)
	}
	if !strings.Contains(got, "85") {
		t.Errorf("HTML output missing trust score")
	}
	if !strings.Contains(got, "Trusty Scan Report") {
		t.Errorf("HTML output missing report title")
	}
}

func TestFormatHTML_Empty(t *testing.T) {
	result := types.ScanResult{
		TrustScore: 100,
		Files:      nil,
		Summary:    types.ScanSummary{TotalIssues: 0, FilesScanned: 0},
	}
	got, err := FormatHTML(result)
	if err != nil {
		t.Fatalf("FormatHTML error: %v", err)
	}
	if !strings.Contains(got, "100") {
		t.Errorf("HTML output missing trust score")
	}
}
