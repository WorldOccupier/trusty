package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	trail := New("")
	if trail == nil {
		t.Fatal("New() returned nil")
	}
	if trail.path != ".trusty-audit.jsonl" {
		t.Errorf("expected default path .trusty-audit.jsonl, got %q", trail.path)
	}
}

func TestNew_CustomPath(t *testing.T) {
	trail := New("/tmp/custom-audit.jsonl")
	if trail.path != "/tmp/custom-audit.jsonl" {
		t.Errorf("expected /tmp/custom-audit.jsonl, got %q", trail.path)
	}
}

func TestRecordAndQuery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	trail := New(path)

	entry, err := trail.Record("scan", 10, 5, 85, 1, 2, 3, "clean")
	if err != nil {
		t.Fatalf("Record() failed: %v", err)
	}

	if entry.Command != "scan" {
		t.Errorf("expected command 'scan', got %q", entry.Command)
	}
	if entry.FilesScanned != 10 {
		t.Errorf("expected FilesScanned 10, got %d", entry.FilesScanned)
	}
	if entry.TotalIssues != 5 {
		t.Errorf("expected TotalIssues 5, got %d", entry.TotalIssues)
	}
	if entry.TrustScore != 85 {
		t.Errorf("expected TrustScore 85, got %d", entry.TrustScore)
	}
	if entry.Errors != 1 {
		t.Errorf("expected Errors 1, got %d", entry.Errors)
	}
	if entry.Warnings != 2 {
		t.Errorf("expected Warnings 2, got %d", entry.Warnings)
	}
	if entry.Infos != 3 {
		t.Errorf("expected Infos 3, got %d", entry.Infos)
	}
	if entry.Status != "clean" {
		t.Errorf("expected Status 'clean', got %q", entry.Status)
	}
	if entry.Timestamp == "" {
		t.Error("expected non-empty Timestamp")
	}

	entries, err := trail.Query(0, "", "")
	if err != nil {
		t.Fatalf("Query() failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestRecord_MultipleEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	trail := New(path)

	for i := 0; i < 5; i++ {
		_, err := trail.Record("scan", 1, 0, 100, 0, 0, 0, "clean")
		if err != nil {
			t.Fatalf("Record() iteration %d failed: %v", i, err)
		}
	}

	entries, err := trail.Query(0, "", "")
	if err != nil {
		t.Fatalf("Query() failed: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
}

func TestQuery_Limit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	trail := New(path)

	for i := 0; i < 10; i++ {
		_, err := trail.Record("scan", 1, 0, 100, 0, 0, 0, "clean")
		if err != nil {
			t.Fatalf("Record() failed: %v", err)
		}
	}

	entries, err := trail.Query(3, "", "")
	if err != nil {
		t.Fatalf("Query() failed: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
}

func TestQuery_StatusFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	trail := New(path)

	trail.Record("scan", 1, 0, 100, 0, 0, 0, "clean")
	trail.Record("scan", 1, 5, 60, 3, 2, 0, "failed")
	trail.Record("scan", 1, 2, 80, 0, 2, 0, "warning")

	entries, err := trail.Query(0, "failed", "")
	if err != nil {
		t.Fatalf("Query() failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 'failed' entry, got %d", len(entries))
	}
	if entries[0].Status != "failed" {
		t.Errorf("expected status 'failed', got %q", entries[0].Status)
	}
}

func TestQuery_SinceFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	trail := New(path)

	trail.Record("scan", 1, 0, 100, 0, 0, 0, "clean")

	since := "2099-01-01T00:00:00Z"
	entries, err := trail.Query(0, "", since)
	if err != nil {
		t.Fatalf("Query() failed: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries since %q, got %d", since, len(entries))
	}
}

func TestQuery_NonExistentFile(t *testing.T) {
	trail := New("/tmp/nonexistent-audit-12345.jsonl")
	entries, err := trail.Query(0, "", "")
	if err != nil {
		t.Fatalf("Query() should not error on non-existent file: %v", err)
	}
	if entries != nil {
		t.Fatalf("expected nil entries, got %v", entries)
	}
}

func TestSummary_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	trail := New(path)

	total, avg, issues, err := trail.Summary()
	if err != nil {
		t.Fatalf("Summary() failed: %v", err)
	}
	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
	if avg != 0 {
		t.Errorf("expected avg 0, got %d", avg)
	}
	if issues != 0 {
		t.Errorf("expected issues 0, got %d", issues)
	}
}

func TestSummary_WithEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	trail := New(path)

	trail.Record("scan", 1, 2, 80, 1, 1, 0, "warning")
	trail.Record("scan", 1, 5, 60, 3, 2, 0, "failed")
	trail.Record("scan", 1, 0, 100, 0, 0, 0, "clean")

	total, avg, issues, err := trail.Summary()
	if err != nil {
		t.Fatalf("Summary() failed: %v", err)
	}
	if total != 3 {
		t.Errorf("expected total 3, got %d", total)
	}
	if avg != 80 {
		t.Errorf("expected average score 80, got %d", avg)
	}
	if issues != 7 {
		t.Errorf("expected total issues 7, got %d", issues)
	}
}

func TestRecord_AppendMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	trail := New(path)

	trail.Record("first", 1, 0, 100, 0, 0, 0, "clean")
	trail.Record("second", 1, 0, 100, 0, 0, 0, "clean")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
}

func TestQuery_InvalidJSONLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	trail := New(path)

	trail.Record("valid", 1, 0, 100, 0, 0, 0, "clean")

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("opening file: %v", err)
	}
	f.WriteString("not-json\n")
	f.Close()

	entries, err := trail.Query(0, "", "")
	if err != nil {
		t.Fatalf("Query() failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 valid entry, got %d", len(entries))
	}
}
