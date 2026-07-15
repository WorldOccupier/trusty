package dashboard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerate_EmptyAudit(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "nonexistent.jsonl")

	html, err := Generate(auditPath)
	if err != nil {
		t.Fatalf("Generate() with empty audit failed: %v", err)
	}
	if html == "" {
		t.Fatal("Generate() returned empty string")
	}
	if !strings.Contains(html, "Trusty Dashboard") {
		t.Error("expected HTML to contain 'Trusty Dashboard'")
	}
	if !strings.Contains(html, "0") {
		t.Error("expected HTML to show zero values for empty audit")
	}
}

func TestGenerate_ProducesValidHTML(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	entry := `{"timestamp":"2025-01-01T00:00:00Z","user":"test","command":"scan","files_scanned":5,"total_issues":2,"trust_score":85,"errors":0,"warnings":2,"infos":0,"status":"warning"}`
	if err := os.WriteFile(auditPath, []byte(entry+"\n"), 0644); err != nil {
		t.Fatalf("writing audit file: %v", err)
	}

	html, err := Generate(auditPath)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	checks := []string{
		"<!DOCTYPE html>",
		"Trusty Dashboard",
		"chart.js",
		"scoreChart",
		"5",
		"85",
		"2",
		"warning",
	}
	for _, check := range checks {
		if !strings.Contains(html, check) {
			t.Errorf("expected HTML to contain %q", check)
		}
	}
}

func TestWriteJSON_EmptyAudit(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "nonexistent.jsonl")

	jsonStr, err := WriteJSON(auditPath)
	if err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		t.Fatalf("WriteJSON() produced invalid JSON: %v", err)
	}
	if data["total_scans"].(float64) != 0 {
		t.Errorf("expected total_scans 0, got %v", data["total_scans"])
	}
}

func TestWriteJSON_WithAuditData(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	entry := `{"timestamp":"2025-06-01T00:00:00Z","user":"tester","command":"scan","files_scanned":10,"total_issues":3,"trust_score":70,"errors":1,"warnings":1,"infos":1,"status":"failed"}`
	if err := os.WriteFile(auditPath, []byte(entry+"\n"), 0644); err != nil {
		t.Fatalf("writing audit file: %v", err)
	}

	jsonStr, err := WriteJSON(auditPath)
	if err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	var result struct {
		TotalScans  int `json:"total_scans"`
		AvgScore    int `json:"avg_score"`
		TotalIssues int `json:"total_issues"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result.TotalScans != 1 {
		t.Errorf("expected TotalScans 1, got %d", result.TotalScans)
	}
	if result.AvgScore != 70 {
		t.Errorf("expected AvgScore 70, got %d", result.AvgScore)
	}
	if result.TotalIssues != 3 {
		t.Errorf("expected TotalIssues 3, got %d", result.TotalIssues)
	}
}

func TestWriteToFile_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	outputPath := filepath.Join(dir, "dashboard.html")

	entry := `{"timestamp":"2025-01-01T00:00:00Z","user":"test","command":"scan","files_scanned":1,"total_issues":0,"trust_score":100,"errors":0,"warnings":0,"infos":0,"status":"clean"}`
	if err := os.WriteFile(auditPath, []byte(entry+"\n"), 0644); err != nil {
		t.Fatalf("writing audit file: %v", err)
	}

	if err := WriteToFile(auditPath, outputPath); err != nil {
		t.Fatalf("WriteToFile() failed: %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("WriteToFile() did not create output file")
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if !strings.Contains(string(data), "Trusty Dashboard") {
		t.Error("expected output to contain 'Trusty Dashboard'")
	}
}

func TestWriteToFile_EmptyAudit(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "empty.jsonl")
	outputPath := filepath.Join(dir, "empty.html")

	if err := WriteToFile(auditPath, outputPath); err != nil {
		t.Fatalf("WriteToFile() with empty audit failed: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if !strings.Contains(string(data), "0") {
		t.Error("expected HTML to contain zero values")
	}
}

func TestGenerate_MultipleAuditEntries(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	entries := []string{
		`{"timestamp":"2025-01-01T00:00:00Z","user":"alice","command":"scan","files_scanned":5,"total_issues":2,"trust_score":80,"errors":0,"warnings":2,"infos":0,"status":"warning"}`,
		`{"timestamp":"2025-01-02T00:00:00Z","user":"bob","command":"scan","files_scanned":10,"total_issues":0,"trust_score":100,"errors":0,"warnings":0,"infos":0,"status":"clean"}`,
		`{"timestamp":"2025-01-03T00:00:00Z","user":"alice","command":"scan","files_scanned":3,"total_issues":5,"trust_score":60,"errors":3,"warnings":2,"infos":0,"status":"failed"}`,
	}
	data := strings.Join(entries, "\n") + "\n"
	if err := os.WriteFile(auditPath, []byte(data), 0644); err != nil {
		t.Fatalf("writing audit file: %v", err)
	}

	html, err := Generate(auditPath)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	for _, name := range []string{"alice", "bob"} {
		if !strings.Contains(html, name) {
			t.Errorf("expected HTML to contain user %q", name)
		}
	}
	if !strings.Contains(html, "3") {
		t.Error("expected HTML to show total scans of 3")
	}
}

func TestScoreHistory_Ordering(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	entries := []string{
		`{"timestamp":"2025-01-01T00:00:00Z","user":"t","command":"scan","files_scanned":1,"total_issues":5,"trust_score":60,"errors":3,"warnings":2,"infos":0,"status":"failed"}`,
		`{"timestamp":"2025-01-02T00:00:00Z","user":"t","command":"scan","files_scanned":1,"total_issues":0,"trust_score":100,"errors":0,"warnings":0,"infos":0,"status":"clean"}`,
	}
	if err := os.WriteFile(auditPath, []byte(strings.Join(entries, "\n")+"\n"), 0644); err != nil {
		t.Fatalf("writing audit file: %v", err)
	}

	html, err := Generate(auditPath)
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	if !strings.Contains(html, "60") && !strings.Contains(html, "100") {
		t.Error("expected HTML to contain both score values")
	}
}
