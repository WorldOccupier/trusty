package scanner

import (
	"testing"
)

func TestStaticAnalyzer_Analyze_Go(t *testing.T) {
	s := NewStaticAnalyzer()

	tests := []struct {
		name    string
		content string
		want    int
		rule    string
	}{
		{
			name: "no issues with used stdlib",
			content: `package main
import "fmt"
func main() { fmt.Println("hello") }`,
			want: 0,
		},
		{
			name: "unused external import flagged",
			content: `package main
import "example.com/mypkg"
func main() {}`,
			want: 1,
			rule: "unused-import",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.Analyze("test.go", tt.content)
			if len(got) != tt.want {
				t.Errorf("got %d findings, want %d", len(got), tt.want)
			}
			if tt.rule != "" && len(got) > 0 && got[0].Rule != tt.rule {
				t.Errorf("got rule %q, want %q", got[0].Rule, tt.rule)
			}
		})
	}
}

func TestStaticAnalyzer_Analyze_Python(t *testing.T) {
	s := NewStaticAnalyzer()

	tests := []struct {
		name    string
		content string
		want    int
		rule    string
	}{
		{
			name:    "wildcard import",
			content: "from os import *",
			want:    1,
			rule:    "wildcard-import",
		},
		{
			name:    "dangerous eval",
			content: "eval(user_input)",
			want:    1,
			rule:    "dangerous-function",
		},
		{
			name:    "clean code",
			content: "import os\nprint('hello')",
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.Analyze("test.py", tt.content)
			if len(got) != tt.want {
				t.Errorf("got %d findings, want %d", len(got), tt.want)
			}
			if tt.rule != "" && len(got) > 0 && got[0].Rule != tt.rule {
				t.Errorf("got rule %q, want %q", got[0].Rule, tt.rule)
			}
		})
	}
}

func TestStaticAnalyzer_Analyze_TypeScript(t *testing.T) {
	s := NewStaticAnalyzer()

	tests := []struct {
		name    string
		content string
		want    int
		rule    string
	}{
		{
			name:    "any type",
			content: "function foo(x: any) { return x; }",
			want:    1,
			rule:    "any-type",
		},
		{
			name:    "clean code",
			content: "function foo(x: string): string { return x; }",
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.Analyze("test.ts", tt.content)
			if len(got) != tt.want {
				t.Errorf("got %d findings, want %d", len(got), tt.want)
			}
			if tt.rule != "" && len(got) > 0 && got[0].Rule != tt.rule {
				t.Errorf("got rule %q, want %q", got[0].Rule, tt.rule)
			}
		})
	}
}

func TestStaticAnalyzer_UnsupportedLanguage(t *testing.T) {
	s := NewStaticAnalyzer()
	got := s.Analyze("test.rs", "fn main() {}")
	if len(got) != 0 {
		t.Errorf("expected 0 findings for unsupported language, got %d", len(got))
	}
}

func TestStaticAnalyzer_EmptyInput(t *testing.T) {
	s := NewStaticAnalyzer()
	got := s.Analyze("", "")
	if got != nil {
		t.Errorf("expected nil for empty input, got %v", got)
	}
}

func TestIsStdLib(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"fmt", true},
		{"os", true},
		{"net/http", true},
		{"github.com/foo/bar", false},
		{"golang.org/x/net", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isStdLib(tt.path); got != tt.want {
				t.Errorf("isStdLib(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"main.go", "go"},
		{"app.py", "python"},
		{"index.js", "typescript"},
		{"index.ts", "typescript"},
		{"lib.rs", "rust"},
		{"Main.java", "java"},
		{"Gemfile.rb", "ruby"},
		{"script.php", "php"},
		{"main.c", "c"},
		{"main.cpp", "cpp"},
		{"Makefile", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := detectLanguage(tt.path); got != tt.want {
				t.Errorf("detectLanguage(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseDiffContent(t *testing.T) {
	tests := []struct {
		name  string
		diff  string
		count int
	}{
		{
			name:  "empty diff",
			diff:  "",
			count: 0,
		},
		{
			name:  "whitespace only",
			diff:  "  \n\t\n  ",
			count: 0,
		},
		{
			name: "single file",
			diff: `diff --git a/main.go b/main.go
index abc..def 100644
--- a/main.go
+++ b/main.go
@@ -1 +1 @@
-fmt.Println("hello")
+fmt.Println("world")`,
			count: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := ParseDiffContent(tt.diff)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(files) != tt.count {
				t.Errorf("got %d files, want %d", len(files), tt.count)
			}
		})
	}
}
