package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/WorldOccupier/trusty/internal/config"
	"github.com/WorldOccupier/trusty/internal/types"
)

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name     string
		findings []types.Finding
		want     int
	}{
		{
			name:     "no findings returns 100",
			findings: nil,
			want:     100,
		},
		{
			name:     "empty findings returns 100",
			findings: []types.Finding{},
			want:     100,
		},
		{
			name: "single error deducts 15",
			findings: []types.Finding{
				{Severity: types.SeverityError},
			},
			want: 85,
		},
		{
			name: "single warning deducts 7",
			findings: []types.Finding{
				{Severity: types.SeverityWarning},
			},
			want: 93,
		},
		{
			name: "single info deducts 3",
			findings: []types.Finding{
				{Severity: types.SeverityInfo},
			},
			want: 97,
		},
		{
			name: "mixed findings cumulative",
			findings: []types.Finding{
				{Severity: types.SeverityError},
				{Severity: types.SeverityWarning},
				{Severity: types.SeverityInfo},
			},
			want: 75,
		},
		{
			name: "multiple errors",
			findings: []types.Finding{
				{Severity: types.SeverityError},
				{Severity: types.SeverityError},
				{Severity: types.SeverityError},
			},
			want: 55,
		},
		{
			name: "penalty caps at 0",
			findings: []types.Finding{
				{Severity: types.SeverityError},
				{Severity: types.SeverityError},
				{Severity: types.SeverityError},
				{Severity: types.SeverityError},
				{Severity: types.SeverityError},
				{Severity: types.SeverityError},
				{Severity: types.SeverityError},
			},
			want: 0,
		},
		{
			name: "warnings adding up",
			findings: []types.Finding{
				{Severity: types.SeverityWarning},
				{Severity: types.SeverityWarning},
				{Severity: types.SeverityWarning},
				{Severity: types.SeverityWarning},
				{Severity: types.SeverityWarning},
			},
			want: 65,
		},
		{
			name: "info only stays high",
			findings: []types.Finding{
				{Severity: types.SeverityInfo},
				{Severity: types.SeverityInfo},
				{Severity: types.SeverityInfo},
			},
			want: 91,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateScore(tt.findings)
			if got != tt.want {
				t.Errorf("calculateScore() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNewScanner_NilProvider(t *testing.T) {
	cfg := config.Default()
	s := NewScanner(cfg, nil)
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
	if s.semantic == nil {
		t.Fatal("semantic analyzer is nil")
	}
	if s.semantic.provider != nil {
		t.Error("expected nil provider in semantic analyzer")
	}
}

func TestNewScanner_WithConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Scan.Tiers = []int{1}
	s := NewScanner(cfg, nil)
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
	if s.cfg == nil {
		t.Fatal("config is nil")
	}
	if s.cfg.Scan.MinScore != cfg.Scan.MinScore {
		t.Errorf("MinScore = %d, want %d", s.cfg.Scan.MinScore, cfg.Scan.MinScore)
	}
}

func TestSetCacheEnabled(t *testing.T) {
	cfg := config.Default()
	s := NewScanner(cfg, nil)
	if s.cache == nil {
		t.Fatal("cache is nil")
	}

	if !s.cache.Enabled() {
		t.Error("expected cache enabled by default")
	}

	s.SetCacheEnabled(false)
	if s.cache.Enabled() {
		t.Error("expected cache disabled after SetCacheEnabled(false)")
	}

	s.SetCacheEnabled(true)
	if !s.cache.Enabled() {
		t.Error("expected cache enabled after SetCacheEnabled(true)")
	}
}

func TestFlushCache(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()

	s := NewScanner(cfg, nil)
	if s.cache == nil {
		t.Fatal("cache is nil")
	}

	s.cache.path = filepath.Join(dir, ".trusty-cache.json")

	s.cache.Set("test.go", "content", []types.Finding{
		{Rule: "test-rule", Severity: types.SeverityWarning, Message: "test"},
	}, 93)

	s.FlushCache()

	data, err := os.ReadFile(s.cache.path)
	if err != nil {
		t.Fatalf("cache file not written: %v", err)
	}
	if !strings.Contains(string(data), "test-rule") {
		t.Errorf("cache file should contain finding: %s", string(data))
	}
}

func TestFlushCache_NotWrittenWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()

	s := NewScanner(cfg, nil)
	s.cache.path = filepath.Join(dir, ".trusty-cache.json")

	s.SetCacheEnabled(false)
	s.cache.Set("test.go", "content", []types.Finding{
		{Rule: "rule", Severity: types.SeverityWarning, Message: "msg"},
	}, 85)

	s.FlushCache()

	if _, err := os.Stat(s.cache.path); err == nil {
		t.Error("cache file should not exist when disabled")
	}
}

func TestFlushCache_EmptyCache(t *testing.T) {
	cfg := config.Default()
	s := NewScanner(cfg, nil)
	if s.cache == nil {
		t.Fatal("cache is nil")
	}

	s.FlushCache()

	data, err := os.ReadFile(s.cache.path)
	if err != nil {
		t.Fatalf("cache file should exist: %v", err)
	}
	if string(data) != "{}" {
		t.Errorf("expected empty cache object, got: %s", string(data))
	}
}

func TestParseDiffContent_Empty(t *testing.T) {
	files, err := ParseDiffContent("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("got %d files, want 0", len(files))
	}
}

func TestParseDiffContent_WhitespaceOnly(t *testing.T) {
	files, err := ParseDiffContent("  \n\t\n  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("got %d files, want 0", len(files))
	}
}

func TestParseDiffContent_SingleFile(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
index abc..def 100644
--- a/main.go
+++ b/main.go
@@ -1 +1 @@
-fmt.Println("hello")
+fmt.Println("world")`
	files, err := ParseDiffContent(diff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if files[0].Path != "main.go" {
		t.Errorf("Path = %q, want %q", files[0].Path, "main.go")
	}
	if files[0].Language != "go" {
		t.Errorf("Language = %q, want %q", files[0].Language, "go")
	}
}

func TestParseDiffContent_MultiFile(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
index abc..def 100644
--- a/main.go
+++ b/main.go
@@ -1 +1 @@
-fmt.Println("hello")
+fmt.Println("world")
diff --git a/app.py b/app.py
index 123..456 100755
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-print("hello")
+print("world")`
	files, err := ParseDiffContent(diff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2", len(files))
	}
	if files[0].Path != "main.go" {
		t.Errorf("files[0].Path = %q, want %q", files[0].Path, "main.go")
	}
	if files[1].Path != "app.py" {
		t.Errorf("files[1].Path = %q, want %q", files[1].Path, "app.py")
	}
	if files[1].Language != "python" {
		t.Errorf("files[1].Language = %q, want %q", files[1].Language, "python")
	}
}

func TestParseDiffContent_NewFile(t *testing.T) {
	diff := `diff --git a/newfile.go b/newfile.go
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/newfile.go
@@ -0,0 +1 @@
+package main`
	files, err := ParseDiffContent(diff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if files[0].Path != "newfile.go" {
		t.Errorf("Path = %q, want %q", files[0].Path, "newfile.go")
	}
}

func TestParseDiffContent_DeletedFile(t *testing.T) {
	diff := `diff --git a/old.go b/old.go
deleted file mode 100644
index abc1234..0000000
--- a/old.go
+++ /dev/null
@@ -1 +0,0 @@
-// removed`
	files, err := ParseDiffContent(diff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if files[0].Path != "old.go" {
		t.Errorf("Path = %q, want %q", files[0].Path, "old.go")
	}
}

func TestParseDiffContent_NonGoFile(t *testing.T) {
	diff := `diff --git a/index.js b/index.js
index abc..def 100644
--- a/index.js
+++ b/index.js
@@ -1 +1 @@
-console.log("hello")
+console.log("world")`
	files, err := ParseDiffContent(diff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if files[0].Path != "index.js" {
		t.Errorf("Path = %q, want %q", files[0].Path, "index.js")
	}
	if files[0].Language != "typescript" {
		t.Errorf("Language = %q, want %q", files[0].Language, "typescript")
	}
}

func TestParseDiffContent_SubdirectoryFile(t *testing.T) {
	diff := `diff --git a/src/util/helper.go b/src/util/helper.go
index abc..def 100644
--- a/src/util/helper.go
+++ b/src/util/helper.go
@@ -1 +1 @@
-package util
+package util`
	files, err := ParseDiffContent(diff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if files[0].Path != "src/util/helper.go" {
		t.Errorf("Path = %q, want %q", files[0].Path, "src/util/helper.go")
	}
}

func TestCacheIntegration(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()

	s := NewScanner(cfg, nil)
	s.cache.path = filepath.Join(dir, ".trusty-cache.json")

	s.cache.Set("test.go", "content1", []types.Finding{
		{Rule: "rule1", Severity: types.SeverityError, Message: "msg1"},
	}, 85)

	findings, score, ok := s.cache.Get("test.go", "content1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Rule != "rule1" {
		t.Errorf("Rule = %q, want %q", findings[0].Rule, "rule1")
	}
	if score != 85 {
		t.Errorf("Score = %d, want %d", score, 85)
	}

	_, _, ok = s.cache.Get("test.go", "different-content")
	if ok {
		t.Error("expected cache miss for different content")
	}
}

func TestCacheClear(t *testing.T) {
	cfg := config.Default()
	s := NewScanner(cfg, nil)

	s.cache.Set("a.go", "content", []types.Finding{{Rule: "r", Severity: types.SeverityWarning, Message: "m"}}, 90)
	s.cache.Clear()

	_, _, ok := s.cache.Get("a.go", "content")
	if ok {
		t.Error("expected cache miss after Clear")
	}
}

func TestCacheInvalidate(t *testing.T) {
	cfg := config.Default()
	s := NewScanner(cfg, nil)

	s.cache.Set("a.go", "content", []types.Finding{{Rule: "r", Severity: types.SeverityWarning, Message: "m"}}, 90)
	s.cache.Invalidate("a.go")

	_, _, ok := s.cache.Get("a.go", "content")
	if ok {
		t.Error("expected cache miss after Invalidate")
	}
}
