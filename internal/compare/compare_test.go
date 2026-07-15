package compare

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/WorldOccupier/trusty/internal/types"
)

func newFileResult(path string, findings ...types.Finding) types.FileResult {
	return types.FileResult{
		Path:     path,
		Language: "go",
		Findings: findings,
		Score:    100,
	}
}

func newFinding(rule, message string, severity types.Severity, line int) types.Finding {
	return types.Finding{
		Rule:     rule,
		Severity: severity,
		Message:  message,
		Line:     line,
		Category: "test",
	}
}

func TestLoadResultValidPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "result.json")

	r := types.ScanResult{
		TrustScore: 85,
		Summary:    types.ScanSummary{TotalIssues: 5},
	}
	data, _ := json.Marshal(r)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadResult(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TrustScore != 85 {
		t.Errorf("expected TrustScore 85, got %d", loaded.TrustScore)
	}
	if loaded.Summary.TotalIssues != 5 {
		t.Errorf("expected TotalIssues 5, got %d", loaded.Summary.TotalIssues)
	}
}

func TestLoadResultInvalidPath(t *testing.T) {
	_, err := LoadResult("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
	if !strings.Contains(err.Error(), "reading") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadResultJSONParseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid json}"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadResult(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCompareSameResults(t *testing.T) {
	f := newFinding("test-rule", "message", types.SeverityWarning, 1)
	base := &types.ScanResult{
		Files:      []types.FileResult{newFileResult("a.go", f)},
		TrustScore: 80,
	}
	curr := &types.ScanResult{
		Files:      []types.FileResult{newFileResult("a.go", f)},
		TrustScore: 80,
	}

	r := Compare(base, curr)
	if len(r.NewFindings) != 0 {
		t.Errorf("expected 0 new findings, got %d", len(r.NewFindings))
	}
	if len(r.FixedFindings) != 0 {
		t.Errorf("expected 0 fixed findings, got %d", len(r.FixedFindings))
	}
	if r.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged, got %d", r.UnchangedCount)
	}
	if r.ScoreChange != 0 {
		t.Errorf("expected score change 0, got %d", r.ScoreChange)
	}
}

func TestCompareDifferentResults(t *testing.T) {
	f1 := newFinding("rule-a", "msg a", types.SeverityWarning, 1)
	f2 := newFinding("rule-b", "msg b", types.SeverityError, 2)
	base := &types.ScanResult{
		Files:      []types.FileResult{newFileResult("a.go", f1)},
		TrustScore: 80,
	}
	curr := &types.ScanResult{
		Files:      []types.FileResult{newFileResult("a.go", f2)},
		TrustScore: 70,
	}

	r := Compare(base, curr)
	if len(r.NewFindings) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(r.NewFindings))
	}
	if len(r.FixedFindings) != 1 {
		t.Errorf("expected 1 fixed finding, got %d", len(r.FixedFindings))
	}
	if r.UnchangedCount != 0 {
		t.Errorf("expected 0 unchanged, got %d", r.UnchangedCount)
	}
	if r.ScoreChange != -10 {
		t.Errorf("expected score change -10, got %d", r.ScoreChange)
	}
}

func TestCompareBaselineWithNewFindings(t *testing.T) {
	base := &types.ScanResult{
		Files:      []types.FileResult{newFileResult("a.go")},
		TrustScore: 90,
	}
	f := newFinding("new-rule", "new msg", types.SeverityInfo, 5)
	curr := &types.ScanResult{
		Files:      []types.FileResult{newFileResult("a.go", f)},
		TrustScore: 85,
	}

	r := Compare(base, curr)
	if len(r.NewFindings) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(r.NewFindings))
	}
	if r.NewFindings[0].Rule != "new-rule" {
		t.Errorf("expected rule 'new-rule', got %s", r.NewFindings[0].Rule)
	}
}

func TestCompareCurrentWithFixedFindings(t *testing.T) {
	f := newFinding("old-rule", "old msg", types.SeverityError, 10)
	base := &types.ScanResult{
		Files:      []types.FileResult{newFileResult("a.go", f)},
		TrustScore: 60,
	}
	curr := &types.ScanResult{
		Files:      []types.FileResult{newFileResult("a.go")},
		TrustScore: 95,
	}

	r := Compare(base, curr)
	if len(r.FixedFindings) != 1 {
		t.Errorf("expected 1 fixed finding, got %d", len(r.FixedFindings))
	}
	if r.FixedFindings[0].Rule != "old-rule" {
		t.Errorf("expected rule 'old-rule', got %s", r.FixedFindings[0].Rule)
	}
}

func TestCompareMultipleFiles(t *testing.T) {
	f1 := newFinding("rule", "msg", types.SeverityWarning, 1)
	f2 := newFinding("rule", "msg", types.SeverityWarning, 1)

	base := &types.ScanResult{
		Files: []types.FileResult{
			newFileResult("a.go", f1),
			newFileResult("b.go"),
		},
		TrustScore: 80,
	}
	curr := &types.ScanResult{
		Files: []types.FileResult{
			newFileResult("a.go", f1),
			newFileResult("b.go", f2),
		},
		TrustScore: 75,
	}

	r := Compare(base, curr)
	if len(r.NewFindings) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(r.NewFindings))
	}
	if len(r.FixedFindings) != 0 {
		t.Errorf("expected 0 fixed findings, got %d", len(r.FixedFindings))
	}
	if r.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged, got %d", r.UnchangedCount)
	}
}

func TestPrintTableOutput(t *testing.T) {
	r := &Result{
		Baseline: "base.json",
		Current:  "curr.json",
		NewFindings: []FindingRef{
			{File: "a.go", Line: 10, Rule: "test-rule", Message: "a message"},
		},
		FixedFindings: []FindingRef{
			{File: "b.go", Line: 5, Rule: "old-rule", Message: "fixed"},
		},
		UnchangedCount: 3,
		ScoreChange:    5,
	}

	pr, pw, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = pw

	PrintTable(r)

	pw.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, pr)
	pr.Close()
	output := buf.String()

	if !strings.Contains(output, "Score change: +5") {
		t.Errorf("output missing score change:\n%s", output)
	}
	if !strings.Contains(output, "New Findings (1)") {
		t.Errorf("output missing new findings count:\n%s", output)
	}
	if !strings.Contains(output, "Fixed Findings (1)") {
		t.Errorf("output missing fixed findings count:\n%s", output)
	}
	if !strings.Contains(output, "a.go:10") {
		t.Errorf("output missing file:line reference:\n%s", output)
	}
	if !strings.Contains(output, "Unchanged: 3 findings") {
		t.Errorf("output missing unchanged count:\n%s", output)
	}
}

func TestPrintTableNoChanges(t *testing.T) {
	r := &Result{
		ScoreChange:    0,
		NewFindings:    nil,
		FixedFindings:  nil,
		UnchangedCount: 5,
	}

	pr, pw, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = pw

	PrintTable(r)

	pw.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, pr)
	pr.Close()
	output := buf.String()

	if !strings.Contains(output, "Score change: +0") {
		t.Errorf("output missing score change:\n%s", output)
	}
	if strings.Contains(output, "New Findings") {
		t.Errorf("should not print new findings section")
	}
	if strings.Contains(output, "Fixed Findings") {
		t.Errorf("should not print fixed findings section")
	}
	if !strings.Contains(output, "Unchanged: 5 findings") {
		t.Errorf("output missing unchanged count:\n%s", output)
	}
}

func TestLoadResultWithMinimalJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minimal.json")
	data := []byte(`{"trust_score":42,"summary":{"total_issues":0}}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadResult(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TrustScore != 42 {
		t.Errorf("expected TrustScore 42, got %d", loaded.TrustScore)
	}
}
