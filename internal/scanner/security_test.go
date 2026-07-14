package scanner

import (
	"testing"

	"github.com/WorldOccupier/trusty/internal/types"
)

func TestSecurityScanner_Scan_Go(t *testing.T) {
	s := NewSecurityScanner()

	tests := []struct {
		name    string
		content string
		wantMin int
		rule    string
	}{
		{
			name:    "sql injection",
			content: `rows, _ := db.Query("SELECT * FROM users WHERE id = " + userID)`,
			wantMin: 1,
			rule:    "sql-injection",
		},
		{
			name:    "hardcoded secret",
			content: `apiKey := "sk-1234567890123456789012345678901234567890"`,
			wantMin: 1,
			rule:    "hardcoded-secret",
		},
		{
			name:    "command injection",
			content: `cmd := exec.Command("sh", "-c", "echo " + userInput)`,
			wantMin: 1,
			rule:    "command-injection",
		},
		{
			name:    "insecure crypto",
			content: `hash := md5.Sum(data)`,
			wantMin: 1,
			rule:    "insecure-crypto",
		},
		{
			name:    "insecure random",
			content: `n := rand.Intn(100)`,
			wantMin: 1,
			rule:    "insecure-random",
		},
		{
			name:    "clean code",
			content: `package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hello\") }`,
			wantMin: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := []types.DiffFile{{
				Path:     "test.go",
				Content:  tt.content,
				Language: "go",
			}}
			got := s.Scan(files)
			if len(got) < tt.wantMin {
				t.Errorf("got %d findings, want >= %d", len(got), tt.wantMin)
			}
			if tt.rule != "" {
				found := false
				for _, f := range got {
					if f.Rule == tt.rule {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected rule %q not found in %d findings", tt.rule, len(got))
				}
			}
		})
	}
}

func TestSecurityScanner_Scan_Python(t *testing.T) {
	s := NewSecurityScanner()

	tests := []struct {
		name    string
		content string
		wantMin int
		rule    string
	}{
		{
			name:    "command injection",
			content: `os.system("rm -rf " + user_path)`,
			wantMin: 1,
			rule:    "command-injection",
		},
		{
			name:    "hardcoded secret",
			content: `API_KEY = "ghp_123456789012345678901234567890123456"`,
			wantMin: 1,
			rule:    "hardcoded-secret",
		},
		{
			name:    "dangerous eval",
			content: `eval(user_input)`,
			wantMin: 1,
			rule:    "dangerous-eval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := []types.DiffFile{{
				Path:     "test.py",
				Content:  tt.content,
				Language: "python",
			}}
			got := s.Scan(files)
			if len(got) < tt.wantMin {
				t.Errorf("got %d findings, want >= %d", len(got), tt.wantMin)
			}
			if tt.rule != "" {
				found := false
				for _, f := range got {
					if f.Rule == tt.rule {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected rule %q not found in %d findings", tt.rule, len(got))
				}
			}
		})
	}
}

func TestSecurityScanner_Scan_JavaScript(t *testing.T) {
	s := NewSecurityScanner()

	tests := []struct {
		name    string
		content string
		wantMin int
		rule    string
	}{
		{
			name:    "xss innerHTML",
			content: `document.getElementById("x").innerHTML = userInput`,
			wantMin: 1,
			rule:    "xss-inner-html",
		},
		{
			name:    "document.write",
			content: `document.write(userInput)`,
			wantMin: 1,
			rule:    "xss-document-write",
		},
		{
			name:    "hardcoded secret",
			content: `const key = "AKIA1234567890123456"`,
			wantMin: 1,
			rule:    "hardcoded-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := []types.DiffFile{{
				Path:     "test.js",
				Content:  tt.content,
				Language: "javascript",
			}}
			got := s.Scan(files)
			if len(got) < tt.wantMin {
				t.Errorf("got %d findings, want >= %d", len(got), tt.wantMin)
			}
			if tt.rule != "" {
				found := false
				for _, f := range got {
					if f.Rule == tt.rule {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected rule %q not found in %d findings", tt.rule, len(got))
				}
			}
		})
	}
}

func TestSecurityScanner_UnsupportedLanguage(t *testing.T) {
	s := NewSecurityScanner()
	files := []types.DiffFile{{
		Path:     "test.rs",
		Content:  `fn main() { let x = 1; }`,
		Language: "rust",
	}}
	got := s.Scan(files)
	if len(got) != 0 {
		t.Errorf("expected 0 findings for unsupported language, got %d", len(got))
	}
}
