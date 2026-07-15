package types

import (
	"testing"
)

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		name  string
		sev   Severity
		value int
	}{
		{"SeverityError", SeverityError, 3},
		{"SeverityWarning", SeverityWarning, 2},
		{"SeverityInfo", SeverityInfo, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.sev) != tt.value {
				t.Errorf("expected %s to be %d, got %d", tt.name, tt.value, tt.sev)
			}
		})
	}

	if SeverityError < SeverityWarning {
		t.Error("expected SeverityError > SeverityWarning")
	}
	if SeverityWarning < SeverityInfo {
		t.Error("expected SeverityWarning > SeverityInfo")
	}
}

func TestFindingCreation(t *testing.T) {
	f := Finding{
		Rule:       "test-rule",
		Severity:   SeverityWarning,
		Message:    "something went wrong",
		Line:       42,
		Column:     7,
		Suggestion: "fix it",
		Category:   "logic",
	}

	if f.Rule != "test-rule" {
		t.Errorf("expected rule 'test-rule', got %s", f.Rule)
	}
	if f.Severity != SeverityWarning {
		t.Errorf("expected SeverityWarning, got %v", f.Severity)
	}
	if f.Message != "something went wrong" {
		t.Errorf("expected message 'something went wrong', got %s", f.Message)
	}
	if f.Line != 42 {
		t.Errorf("expected line 42, got %d", f.Line)
	}
	if f.Column != 7 {
		t.Errorf("expected column 7, got %d", f.Column)
	}
	if f.Suggestion != "fix it" {
		t.Errorf("expected suggestion 'fix it', got %s", f.Suggestion)
	}
	if f.Category != "logic" {
		t.Errorf("expected category 'logic', got %s", f.Category)
	}
}

func TestFindingDefaults(t *testing.T) {
	f := Finding{}
	if f.Rule != "" {
		t.Errorf("expected empty rule, got %s", f.Rule)
	}
	if f.Severity != 0 {
		t.Errorf("expected Severity 0, got %d", f.Severity)
	}
	if f.Line != 0 {
		t.Errorf("expected Line 0, got %d", f.Line)
	}
}

func TestFileResult(t *testing.T) {
	findings := []Finding{
		{Rule: "r1", Severity: SeverityError, Message: "err", Category: "security"},
		{Rule: "r2", Severity: SeverityWarning, Message: "warn", Category: "logic"},
	}

	fr := FileResult{
		Path:     "src/main.go",
		Language: "go",
		Findings: findings,
		Score:    75,
	}

	if fr.Path != "src/main.go" {
		t.Errorf("expected path 'src/main.go', got %s", fr.Path)
	}
	if fr.Language != "go" {
		t.Errorf("expected language 'go', got %s", fr.Language)
	}
	if len(fr.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(fr.Findings))
	}
	if fr.Score != 75 {
		t.Errorf("expected score 75, got %d", fr.Score)
	}

	if fr.Findings[0].Severity != SeverityError {
		t.Error("first finding should be error severity")
	}
	if fr.Findings[1].Severity != SeverityWarning {
		t.Error("second finding should be warning severity")
	}
}

func TestScanSummary(t *testing.T) {
	s := ScanSummary{
		TotalIssues:  10,
		Errors:       3,
		Warnings:     5,
		Info:         2,
		FilesScanned: 15,
		Duration:     "1.2s",
		Status:       "completed",
		MinScore:     50,
	}

	if s.TotalIssues != 10 {
		t.Errorf("expected TotalIssues 10, got %d", s.TotalIssues)
	}
	if s.Errors != 3 {
		t.Errorf("expected Errors 3, got %d", s.Errors)
	}
	if s.Warnings != 5 {
		t.Errorf("expected Warnings 5, got %d", s.Warnings)
	}
	if s.Info != 2 {
		t.Errorf("expected Info 2, got %d", s.Info)
	}
	if s.FilesScanned != 15 {
		t.Errorf("expected FilesScanned 15, got %d", s.FilesScanned)
	}
	if s.Duration != "1.2s" {
		t.Errorf("expected Duration '1.2s', got %s", s.Duration)
	}
	if s.Status != "completed" {
		t.Errorf("expected Status 'completed', got %s", s.Status)
	}
	if s.MinScore != 50 {
		t.Errorf("expected MinScore 50, got %d", s.MinScore)
	}
}

func TestScanSummaryZeroValues(t *testing.T) {
	s := ScanSummary{}
	if s.TotalIssues != 0 {
		t.Error("expected zero-value TotalIssues")
	}
	if s.Status != "" {
		t.Error("expected zero-value Status")
	}
}

func TestScanResultComposition(t *testing.T) {
	sr := ScanResult{
		Files: []FileResult{
			{Path: "a.go", Language: "go", Score: 100},
		},
		Summary: ScanSummary{
			TotalIssues:  5,
			Errors:       1,
			Warnings:     3,
			Info:         1,
			FilesScanned: 3,
			Duration:     "500ms",
			Status:       "completed",
			MinScore:     50,
		},
		TrustScore: 85,
		Timestamp:  "2025-01-01T00:00:00Z",
		DurationMs: 500,
	}

	if len(sr.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(sr.Files))
	}
	if sr.TrustScore != 85 {
		t.Errorf("expected TrustScore 85, got %d", sr.TrustScore)
	}
	if sr.Timestamp != "2025-01-01T00:00:00Z" {
		t.Errorf("expected timestamp, got %s", sr.Timestamp)
	}
	if sr.DurationMs != 500 {
		t.Errorf("expected DurationMs 500, got %d", sr.DurationMs)
	}

	if sr.Summary.Status != "completed" {
		t.Errorf("expected status completed, got %s", sr.Summary.Status)
	}
	if sr.Files[0].Path != "a.go" {
		t.Errorf("expected file path 'a.go', got %s", sr.Files[0].Path)
	}
}

func TestScanResultEmpty(t *testing.T) {
	sr := ScanResult{}
	if sr.Files != nil {
		t.Error("expected nil Files")
	}
	if sr.TrustScore != 0 {
		t.Error("expected zero TrustScore")
	}
}

func TestDiffFile(t *testing.T) {
	df := DiffFile{
		Path:     "src/main.go",
		Language: "go",
		Diff:     "@@ -1,3 +1,4 @@\n-foo\n+bar",
		Content:  "package main\nfunc main() {}",
	}

	if df.Path != "src/main.go" {
		t.Errorf("expected path 'src/main.go', got %s", df.Path)
	}
	if df.Language != "go" {
		t.Errorf("expected language 'go', got %s", df.Language)
	}
	if df.Diff == "" {
		t.Error("expected non-empty Diff")
	}
	if df.Content == "" {
		t.Error("expected non-empty Content")
	}
}

func TestDiffOptions(t *testing.T) {
	opts := DiffOptions{
		Staged:    true,
		From:      "abc123",
		To:        "def456",
		Base:      "main",
		Head:      "feature-branch",
		Path:      "/repo",
		RawDiff:   "diff --git a/a.go b/a.go",
		ScanDir:   "/repo",
		ScanPaths: []string{"src/"},
	}

	if !opts.Staged {
		t.Error("expected Staged to be true")
	}
	if opts.From != "abc123" {
		t.Errorf("expected From 'abc123', got %s", opts.From)
	}
	if opts.To != "def456" {
		t.Errorf("expected To 'def456', got %s", opts.To)
	}
	if opts.Base != "main" {
		t.Errorf("expected Base 'main', got %s", opts.Base)
	}
	if opts.Head != "feature-branch" {
		t.Errorf("expected Head 'feature-branch', got %s", opts.Head)
	}
	if len(opts.ScanPaths) != 1 || opts.ScanPaths[0] != "src/" {
		t.Errorf("unexpected ScanPaths: %v", opts.ScanPaths)
	}
}

func TestDiffOptionsDefaults(t *testing.T) {
	opts := DiffOptions{}
	if opts.Staged {
		t.Error("expected Staged to default to false")
	}
	if opts.ScanPaths != nil {
		t.Error("expected nil ScanPaths")
	}
}

func TestFindingSeverityComparison(t *testing.T) {
	f1 := Finding{Rule: "error-finding", Severity: SeverityError, Category: "test"}
	f2 := Finding{Rule: "warning-finding", Severity: SeverityWarning, Category: "test"}
	f3 := Finding{Rule: "info-finding", Severity: SeverityInfo, Category: "test"}

	if f1.Severity <= f2.Severity {
		t.Error("expected error severity to be greater than warning")
	}
	if f2.Severity <= f3.Severity {
		t.Error("expected warning severity to be greater than info")
	}
}

func TestFileResultEmptyFindings(t *testing.T) {
	fr := FileResult{
		Path:     "clean.go",
		Language: "go",
		Findings: []Finding{},
		Score:    100,
	}

	if len(fr.Findings) != 0 {
		t.Error("expected empty findings")
	}
	if fr.Score != 100 {
		t.Errorf("expected score 100, got %d", fr.Score)
	}
}
