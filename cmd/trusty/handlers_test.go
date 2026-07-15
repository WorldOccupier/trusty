package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/WorldOccupier/trusty/internal/types"
)

func TestSeverityHelpers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected types.Severity
		str      string
	}{
		{"error", "error", types.SeverityError, "ERROR"},
		{"warning", "warning", types.SeverityWarning, "WARN"},
		{"warn", "warn", types.SeverityWarning, "WARN"},
		{"info", "info", types.SeverityInfo, "INFO"},
		{"unknown defaults to info", "unknown", types.SeverityInfo, "INFO"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityFromString(tt.input)
			if got != tt.expected {
				t.Errorf("severityFromString(%q) = %d, want %d", tt.input, got, tt.expected)
			}
			if got2 := severityFromConfig(tt.input); got2 != tt.expected {
				t.Errorf("severityFromConfig(%q) = %d, want %d", tt.input, got2, tt.expected)
			}
			if got3 := severityStr(got); got3 != tt.str {
				t.Errorf("severityStr(%d) = %q, want %q", got, got3, tt.str)
			}
		})
	}
}

func TestFilterBySeverity(t *testing.T) {
	findings := []types.Finding{
		{Rule: "high", Severity: types.SeverityError},
		{Rule: "mid", Severity: types.SeverityWarning},
		{Rule: "low", Severity: types.SeverityInfo},
	}

	t.Run("info min returns all", func(t *testing.T) {
		got := filterBySeverity(findings, types.SeverityInfo)
		if len(got) != 3 {
			t.Errorf("got %d, want 3", len(got))
		}
	})

	t.Run("warning min returns warning+error", func(t *testing.T) {
		got := filterBySeverity(findings, types.SeverityWarning)
		if len(got) != 2 {
			t.Errorf("got %d, want 2", len(got))
		}
	})

	t.Run("error min returns only error", func(t *testing.T) {
		got := filterBySeverity(findings, types.SeverityError)
		if len(got) != 1 {
			t.Errorf("got %d, want 1", len(got))
		}
	})
}

func TestColorize(t *testing.T) {
	orig := useColor
	defer func() { useColor = orig }()

	useColor = true
	got := colorize(colorRed, "hello")
	if !strings.Contains(got, "hello") {
		t.Errorf("colorize should contain the string")
	}
	if !strings.HasPrefix(got, "\033[31m") {
		t.Errorf("colorize should start with red escape code")
	}

	useColor = false
	got = colorize(colorRed, "hello")
	if got != "hello" {
		t.Errorf("colorize without color should return plain string, got %q", got)
	}
}

func TestColorSeverity(t *testing.T) {
	orig := useColor
	defer func() { useColor = orig }()

	useColor = false
	if got := colorSeverity(types.SeverityError); got != "ERROR" {
		t.Errorf("got %q, want ERROR", got)
	}
	if got := colorSeverity(types.Severity(99)); got != "UNKNOWN" {
		t.Errorf("got %q, want UNKNOWN", got)
	}
}

func TestColorScore(t *testing.T) {
	orig := useColor
	defer func() { useColor = orig }()

	useColor = false

	tests := []struct {
		score int
		want  string
	}{
		{95, "95/100"},
		{75, "75/100"},
		{50, "50/100"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("score_%d", tt.score), func(t *testing.T) {
			got := colorScore(tt.score)
			if got != tt.want {
				t.Errorf("colorScore(%d) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestRemoveTier(t *testing.T) {
	tiers := []int{1, 2, 3}

	t.Run("remove middle", func(t *testing.T) {
		got := removeTier(tiers, 2)
		if len(got) != 2 || got[0] != 1 || got[1] != 3 {
			t.Errorf("got %v, want [1 3]", got)
		}
	})

	t.Run("remove non-existent", func(t *testing.T) {
		got := removeTier(tiers, 4)
		if len(got) != 3 {
			t.Errorf("got %v, want [1 2 3]", got)
		}
	})

	t.Run("nil slice", func(t *testing.T) {
		got := removeTier(nil, 1)
		if got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})
}

func TestWriteOutput(t *testing.T) {
	t.Run("stdout", func(t *testing.T) {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := writeOutput([]byte("hello"), "")
		w.Close()
		os.Stdout = old

		if err != nil {
			t.Fatalf("writeOutput returned error: %v", err)
		}
		var buf bytes.Buffer
		buf.ReadFrom(r)
		// fmt.Println adds a trailing newline
		if buf.String() != "hello\n" {
			t.Errorf("got %q, want %q", buf.String(), "hello\n")
		}
	})

	t.Run("file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "out.json")

		err := writeOutput([]byte(`{"key":"value"}`), path)
		if err != nil {
			t.Fatalf("writeOutput returned error: %v", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != `{"key":"value"}` {
			t.Errorf("got %q", string(data))
		}
	})
}

func TestLoadConfig(t *testing.T) {
	t.Run("no cfgFile returns default", func(t *testing.T) {
		orig := cfgFile
		cfgFile = ""
		defer func() { cfgFile = orig }()

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig() error: %v", err)
		}
		if cfg.Scan.MinScore != 70 {
			t.Errorf("MinScore = %d, want 70", cfg.Scan.MinScore)
		}
	})

	t.Run("cfgFile set loads from file", func(t *testing.T) {
		orig := cfgFile
		defer func() { cfgFile = orig }()

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, ".trusty.yml")
		os.WriteFile(cfgPath, []byte("scan:\n  min_score: 85\n"), 0644)

		cfgFile = cfgPath
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig() error: %v", err)
		}
		if cfg.Scan.MinScore != 85 {
			t.Errorf("MinScore = %d, want 85", cfg.Scan.MinScore)
		}
	})
}

func TestExplainFunctions(t *testing.T) {
	t.Run("ruleExplanations is populated", func(t *testing.T) {
		if len(ruleExplanations) == 0 {
			t.Fatal("ruleExplanations is empty")
		}
		if _, ok := ruleExplanations["sql-injection"]; !ok {
			t.Error("missing sql-injection rule")
		}
	})

	t.Run("listRuleIDs returns comma-separated", func(t *testing.T) {
		ids := listRuleIDs()
		if ids == "" {
			t.Fatal("listRuleIDs returned empty")
		}
		if !strings.Contains(ids, "sql-injection") {
			t.Error("listRuleIDs should contain sql-injection")
		}
	})

	t.Run("countFindings counts correctly", func(t *testing.T) {
		r := types.ScanResult{
			Files: []types.FileResult{
				{Findings: []types.Finding{{Rule: "a"}, {Rule: "b"}}},
				{Findings: []types.Finding{{Rule: "c"}}},
			},
		}
		if n := countFindings(r); n != 3 {
			t.Errorf("countFindings = %d, want 3", n)
		}
	})

	t.Run("printExplanation prints expected format", func(t *testing.T) {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		exp := ruleExplanation{
			Name:    "Test Rule",
			Problem: "A test problem",
			Example: "bad code",
			Fix:     "good code",
		}
		printExplanation("test-rule", exp)
		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		buf.ReadFrom(r)
		out := buf.String()
		if !strings.Contains(out, "test-rule") {
			t.Error("output should contain rule ID")
		}
		if !strings.Contains(out, "Test Rule") {
			t.Error("output should contain rule name")
		}
		if !strings.Contains(out, "A test problem") {
			t.Error("output should contain problem")
		}
	})
}

func TestRunExplain(t *testing.T) {
	t.Run("valid rule", func(t *testing.T) {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := runExplain(nil, []string{"sql-injection"})
		w.Close()
		os.Stdout = old

		if err != nil {
			t.Fatalf("runExplain error: %v", err)
		}
		var buf bytes.Buffer
		buf.ReadFrom(r)
		if !strings.Contains(buf.String(), "SQL Injection") {
			t.Error("output should contain rule name")
		}
	})

	t.Run("invalid rule returns error", func(t *testing.T) {
		err := runExplain(nil, []string{"nonexistent-rule"})
		if err == nil {
			t.Fatal("expected error for unknown rule")
		}
		if !strings.Contains(err.Error(), "unknown rule") {
			t.Errorf("error = %q, want 'unknown rule'", err.Error())
		}
	})

	t.Run("JSON file input", func(t *testing.T) {
		dir := t.TempDir()
		result := types.ScanResult{
			Files: []types.FileResult{
				{
					Path: "test.go",
					Findings: []types.Finding{
						{Rule: "sql-injection", Severity: types.SeverityError, Message: "test", Line: 1},
					},
				},
			},
		}
		data, _ := json.Marshal(result)
		path := filepath.Join(dir, "results.json")
		os.WriteFile(path, data, 0644)

		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := runExplain(nil, []string{path})
		w.Close()
		os.Stdout = old

		if err != nil {
			t.Fatalf("runExplain error: %v", err)
		}
		var buf bytes.Buffer
		buf.ReadFrom(r)
		if !strings.Contains(buf.String(), "Explaining") {
			t.Error("output should contain explanation header")
		}
	})
}

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "init"}
	cmd.Flags().Bool("interactive", false, "")
	return cmd
}

func TestRunInit(t *testing.T) {
	dir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(oldDir)

	cmd := newInitCmd()
	err := runInit(cmd, nil)
	if err != nil {
		t.Fatalf("runInit error: %v", err)
	}

	if _, err := os.Stat(".trusty.yml"); os.IsNotExist(err) {
		t.Fatal(".trusty.yml was not created")
	}

	data, err := os.ReadFile(".trusty.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "min_score: 70") {
		t.Error(".trusty.yml should contain default min_score")
	}
}

func TestRunInitExisting(t *testing.T) {
	dir := t.TempDir()
	oldDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(oldDir)

	os.WriteFile(".trusty.yml", []byte("existing"), 0644)

	cmd := newInitCmd()
	err := runInit(cmd, nil)
	if err == nil {
		t.Fatal("expected error for existing .trusty.yml")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want 'already exists'", err.Error())
	}
}

func TestRunDemo(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDemo(nil, nil)
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("runDemo error: %v", err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "Trust Score") {
		t.Error("output should contain Trust Score")
	}
	if !strings.Contains(out, "Issues Found") {
		t.Error("output should contain Issues Found")
	}
}

func TestLoadScanResult(t *testing.T) {
	dir := t.TempDir()
	result := types.ScanResult{
		TrustScore: 85,
		Summary: types.ScanSummary{
			TotalIssues: 3,
		},
	}
	data, _ := json.Marshal(result)
	path := filepath.Join(dir, "result.json")
	os.WriteFile(path, data, 0644)

	loaded, err := loadScanResult(path)
	if err != nil {
		t.Fatalf("loadScanResult error: %v", err)
	}
	if loaded.TrustScore != 85 {
		t.Errorf("TrustScore = %d, want 85", loaded.TrustScore)
	}
	if loaded.Summary.TotalIssues != 3 {
		t.Errorf("TotalIssues = %d, want 3", loaded.Summary.TotalIssues)
	}
}

func TestLoadScanResultInvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")
	_, err := loadScanResult(path)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestExplainFindings(t *testing.T) {
	result := types.ScanResult{
		Files: []types.FileResult{
			{
				Path: "main.go",
				Findings: []types.Finding{
					{Rule: "sql-injection", Severity: types.SeverityError, Message: "test"},
					{Rule: "off-by-one", Severity: types.SeverityWarning, Message: "test2"},
				},
			},
		},
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := explainFindings(result)
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("explainFindings error: %v", err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()
	if !strings.Contains(out, "Explaining") {
		t.Error("should contain explanation header")
	}
	if !strings.Contains(out, "SQL Injection") {
		t.Error("should contain SQL Injection explanation")
	}
	if !strings.Contains(out, "Off-by-One") {
		t.Error("should contain Off-by-One explanation")
	}
}

func TestExplainFindingsNone(t *testing.T) {
	result := types.ScanResult{
		Files: []types.FileResult{
			{
				Path:     "main.go",
				Findings: []types.Finding{{Rule: "nonexistent-rule"}},
			},
		},
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := explainFindings(result)
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("explainFindings error: %v", err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if !strings.Contains(buf.String(), "No recognized findings") {
		t.Error("should indicate no recognized findings")
	}
}
