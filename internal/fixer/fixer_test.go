package fixer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/WorldOccupier/trusty/internal/types"
)

func TestNew(t *testing.T) {
	f := New()
	if f == nil {
		t.Fatal("New() returned nil")
	}
	if f.DryRun {
		t.Error("expected DryRun to be false")
	}
	if f.Interactive {
		t.Error("expected Interactive to be false")
	}
}

func TestLeadingWhitespace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"no indent", ""},
		{"  two spaces", "  "},
		{"\ttab", "\t"},
		{"    four spaces", "    "},
		{"\t\t tab tab", "\t\t "},
		{"  mixed", "  "},
		{"\t  ", "\t  "},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := leadingWhitespace(tt.input)
			if got != tt.want {
				t.Errorf("leadingWhitespace(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractDefer(t *testing.T) {
	tests := []struct {
		suggestion string
		want       string
	}{
		{"Use 'defer resource.Close()' immediately", "defer resource.Close()' immediately"},
		{"defer resp.Body.Close()", "defer resp.Body.Close()"},
		{"Add defer file.Close() at the call site", "defer file.Close() at the call site"},
		{"just a suggestion", ""},
		{"defer ", "defer"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.suggestion, func(t *testing.T) {
			got := extractDefer(tt.suggestion)
			if got != tt.want {
				t.Errorf("extractDefer(%q) = %q, want %q", tt.suggestion, got, tt.want)
			}
		})
	}
}

func TestGroupByFile(t *testing.T) {
	tests := []struct {
		name     string
		findings []types.Finding
		want     map[string]int
	}{
		{
			name:     "empty",
			findings: nil,
			want:     map[string]int{},
		},
		{
			name: "single file",
			findings: []types.Finding{
				{Rule: "nil-dereference", Category: "main.go"},
				{Rule: "unchecked-error", Category: "main.go"},
			},
			want: map[string]int{"main.go": 2},
		},
		{
			name: "multiple files",
			findings: []types.Finding{
				{Rule: "nil-dereference", Category: "a.go"},
				{Rule: "unchecked-error", Category: "b.go"},
				{Rule: "hardcoded-index", Category: "a.go"},
			},
			want: map[string]int{"a.go": 2, "b.go": 1},
		},
		{
			name: "empty category defaults to unknown",
			findings: []types.Finding{
				{Rule: "nil-dereference", Category: ""},
			},
			want: map[string]int{"unknown": 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := groupByFile(tt.findings)
			if len(got) != len(tt.want) {
				t.Errorf("got %d groups, want %d", len(got), len(tt.want))
			}
			for file, count := range tt.want {
				if len(got[file]) != count {
					t.Errorf("group[%q] has %d items, want %d", file, len(got[file]), count)
				}
			}
		})
	}
}

func TestGenerateFix(t *testing.T) {
	tests := []struct {
		name    string
		finding types.Finding
		want    string
	}{
		{
			name:    "uses suggestion if present",
			finding: types.Finding{Rule: "nil-dereference", Suggestion: "custom suggestion"},
			want:    "custom suggestion",
		},
		{
			name:    "nil-dereference",
			finding: types.Finding{Rule: "nil-dereference"},
			want:    "Add nil check before access",
		},
		{
			name:    "unchecked-error",
			finding: types.Finding{Rule: "unchecked-error"},
			want:    "Check and handle the error return value",
		},
		{
			name:    "missing-deferred-close",
			finding: types.Finding{Rule: "missing-deferred-close"},
			want:    "Add defer resource.Close()",
		},
		{
			name:    "typed-nil-interface",
			finding: types.Finding{Rule: "typed-nil-interface"},
			want:    "Return explicit typed nil instead of bare nil",
		},
		{
			name:    "hardcoded-index",
			finding: types.Finding{Rule: "hardcoded-index"},
			want:    "Add length check or use range loop",
		},
		{
			name:    "unknown rule returns empty",
			finding: types.Finding{Rule: "unknown-rule"},
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateFix(tt.finding)
			if got != tt.want {
				t.Errorf("generateFix() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyFix(t *testing.T) {
	tests := []struct {
		name    string
		lines   []string
		finding types.Finding
		fix     string
		want    string
	}{
		{
			name:  "out of bounds line returns empty",
			lines: []string{"line1"},
			finding: types.Finding{
				Rule: "missing-deferred-close",
				Line: 10,
			},
			fix:  "Add defer resource.Close()",
			want: "",
		},
		{
			name:  "negative line returns empty",
			lines: []string{"line1"},
			finding: types.Finding{
				Rule: "missing-deferred-close",
				Line: 0,
			},
			fix:  "Add defer resource.Close()",
			want: "",
		},
		{
			name: "inserts defer before resource close line",
			lines: []string{
				"func main() {",
				"    resp, _ := http.Get(url)",
				"    resp.Body.Close()",
				"}",
			},
			finding: types.Finding{
				Rule: "missing-deferred-close",
				Line: 3,
			},
			fix: "Add defer resp.Body.Close()",
			want: strings.Join([]string{
				"func main() {",
				"    resp, _ := http.Get(url)",
				"    defer resp.Body.Close()",
				"    resp.Body.Close()",
				"}",
			}, "\n"),
		},
		{
			name: "non-defer fix is not applied",
			lines: []string{
				"func main() {",
				"    x := 1",
				"}",
			},
			finding: types.Finding{
				Rule: "nil-dereference",
				Line: 2,
			},
			fix:  "Add nil check before access",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyFix(tt.lines, tt.finding, tt.fix)
			if got != tt.want {
				t.Errorf("applyFix() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyFindings_NoFindings(t *testing.T) {
	f := New()
	dir := t.TempDir()

	results, err := f.ApplyFindings(nil, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0", len(results))
	}
}

func TestApplyFindings_FileNotFound(t *testing.T) {
	f := New()
	dir := t.TempDir()

	findings := []types.Finding{
		{Rule: "nil-dereference", Category: "nonexistent.go", Line: 1},
	}

	results, err := f.ApplyFindings(findings, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Applied {
		t.Error("expected Applied to be false for missing file")
	}
	if f.Errors != 1 {
		t.Errorf("Errors = %d, want 1", f.Errors)
	}
}

func TestApplyFindings_NoAutoFix(t *testing.T) {
	f := New()
	dir := t.TempDir()
	filePath := filepath.Join(dir, "main.go")
	original := "package main\nfunc main() {}\n"
	if err := os.WriteFile(filePath, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []types.Finding{
		{Rule: "unknown-rule", Category: "main.go", Line: 1, Message: "some issue"},
	}

	results, err := f.ApplyFindings(findings, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Applied {
		t.Error("expected Applied to be false for no auto-fix")
	}
	if results[0].Fix != "No auto-fix available" {
		t.Errorf("Fix = %q, want 'No auto-fix available'", results[0].Fix)
	}
	if f.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", f.Skipped)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Error("file content should not change when no auto-fix is available")
	}
}

func TestApplyFindings_DryRun(t *testing.T) {
	f := New()
	f.DryRun = true
	dir := t.TempDir()
	filePath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(filePath, []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []types.Finding{
		{Rule: "nil-dereference", Category: "main.go", Line: 1, Message: "nil check"},
	}

	results, err := f.ApplyFindings(findings, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if !results[0].Applied {
		t.Error("expected Applied to be true in dry run")
	}
	if f.Fixed != 1 {
		t.Errorf("Fixed = %d, want 1", f.Fixed)
	}
	if f.DryRun != true {
		t.Error("DryRun should remain true")
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "package main\nfunc main() {}\n" {
		t.Error("file content should not change in dry run")
	}
}

func TestApplyFindings_SuccessfulFix(t *testing.T) {
	f := New()
	dir := t.TempDir()
	filePath := filepath.Join(dir, "app.go")
	content := []byte("package app\n\nfunc run() {\n\tresp, _ := http.Get(url)\n\tresp.Body.Close()\n}\n")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatal(err)
	}

	findings := []types.Finding{
		{
			Rule:       "missing-deferred-close",
			Category:   "app.go",
			Line:       4,
			Message:    "missing defer",
			Suggestion: "defer resp.Body.Close()",
		},
	}

	results, err := f.ApplyFindings(findings, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if !results[0].Applied {
		t.Error("expected Applied to be true")
	}
	if f.Fixed != 1 {
		t.Errorf("Fixed = %d, want 1", f.Fixed)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "defer resp.Body.Close()") {
		t.Errorf("file content should contain defer line after fix:\n%s", string(data))
	}
}

func TestApplyFindings_InteractiveYes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping interactive test in short mode")
	}

	f := New()
	f.Interactive = true
	dir := t.TempDir()
	filePath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(filePath, []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []types.Finding{
		{
			Rule:       "missing-deferred-close",
			Category:   "main.go",
			Line:       1,
			Message:    "missing defer close",
			Suggestion: "defer resp.Body.Close()",
		},
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("y\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()

	oldStdin := os.Stdin
	os.Stdin = r

	results, err := f.ApplyFindings(findings, dir)
	os.Stdin = oldStdin
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if !results[0].Applied {
		t.Error("expected Applied to be true when user says yes")
	}
	if f.Fixed != 1 {
		t.Errorf("Fixed = %d, want 1", f.Fixed)
	}
}

func TestApplyFindings_InteractiveNo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping interactive test in short mode")
	}

	f := New()
	f.Interactive = true
	dir := t.TempDir()
	filePath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(filePath, []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []types.Finding{
		{
			Rule:       "missing-deferred-close",
			Category:   "main.go",
			Line:       1,
			Message:    "missing defer close",
			Suggestion: "defer resp.Body.Close()",
		},
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("n\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()

	oldStdin := os.Stdin
	os.Stdin = r

	results, err := f.ApplyFindings(findings, dir)
	os.Stdin = oldStdin
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Applied {
		t.Error("expected Applied to be false when user says no")
	}
	if f.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", f.Skipped)
	}
}

func TestApplyResultFile_InvalidPath(t *testing.T) {
	f := New()
	err := f.ApplyResultFile("/nonexistent/path/result.json", ".")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestApplyResultFile_ValidFile(t *testing.T) {
	f := New()
	dir := t.TempDir()

	srcFile := filepath.Join(dir, "app.go")
	if err := os.WriteFile(srcFile, []byte("package app\n\nfunc run() {\n\tresp, _ := http.Get(url)\n\tresp.Body.Close()\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	scanResult := `{
		"files": [{
			"path": "app.go",
			"language": "go",
			"findings": [
				{
					"rule": "missing-deferred-close",
					"severity": 2,
					"message": "missing defer close",
					"line": 4,
					"suggestion": "defer resp.Body.Close()",
					"category": "app.go"
				}
			],
			"score": 93
		}],
		"summary": {
			"total_issues": 1,
			"files_scanned": 1,
			"status": "warning"
		},
		"trust_score": 93
	}`
	resultPath := filepath.Join(dir, "result.json")
	if err := os.WriteFile(resultPath, []byte(scanResult), 0644); err != nil {
		t.Fatal(err)
	}

	err := f.ApplyResultFile(resultPath, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Fixed != 1 {
		t.Errorf("Fixed = %d, want 1", f.Fixed)
	}
}

func TestApplyResultFile_NoFindings(t *testing.T) {
	f := New()
	dir := t.TempDir()

	scanResult := `{"files": [], "summary": {"total_issues": 0, "files_scanned": 0, "status": "clean"}, "trust_score": 100}`
	resultPath := filepath.Join(dir, "result.json")
	if err := os.WriteFile(resultPath, []byte(scanResult), 0644); err != nil {
		t.Fatal(err)
	}

	err := f.ApplyResultFile(resultPath, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Fixed != 0 {
		t.Errorf("Fixed = %d, want 0", f.Fixed)
	}
}
