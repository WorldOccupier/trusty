package scanner

import (
	"testing"

	"github.com/WorldOccupier/trusty/internal/types"
)

func TestLogicDetector_Detect_Go(t *testing.T) {
	d := NewLogicDetector()

	tests := []struct {
		name    string
		content string
		wantMin int
		rule    string
	}{
		{
			name: "off-by-one loop",
			content: `package main
func main() { for i := 0; i <= 10; i++ {} }`,
			wantMin: 1,
			rule:    "off-by-one",
		},
		{
			name: "self assignment",
			content: `package main
func main() { x := 1
x = x }`,
			wantMin: 1,
			rule:    "self-assignment",
		},
		{
			name: "infinite loop",
			content: `package main
func main() { for {} }`,
			wantMin: 1,
			rule:    "infinite-loop",
		},
		{
			name: "missing default in switch",
			content: `package main
func main() { switch x := 1; x { case 1: } }`,
			wantMin: 1,
			rule:    "missing-default",
		},
		{
			name: "clean code",
			content: `package main
import "fmt"
func main() { for i := 0; i < 10; i++ { fmt.Println(i) } }`,
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
			got := d.Detect(files)
			if tt.wantMin > 0 && len(got) < tt.wantMin {
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
				if !found && tt.wantMin > 0 {
					t.Errorf("expected rule %q not found", tt.rule)
				}
			}
		})
	}
}

func TestLogicDetector_Detect_Python(t *testing.T) {
	d := NewLogicDetector()

	tests := []struct {
		name    string
		content string
		wantMin int
		rule    string
	}{
		{
			name:    "redundant equality",
			content: "if x == True:\n    pass",
			wantMin: 1,
			rule:    "redundant-equality",
		},
		{
			name:    "bare except",
			content: "try:\n    pass\nexcept:\n    pass",
			wantMin: 1,
			rule:    "bare-except",
		},
		{
			name:    "range len",
			content: "for i in range(len(items)):\n    print(i)",
			wantMin: 1,
			rule:    "range-len-pattern",
		},
		{
			name:    "none comparison",
			content: "if x == None:\n    pass",
			wantMin: 1,
			rule:    "none-comparison",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := []types.DiffFile{{
				Path:     "test.py",
				Content:  tt.content,
				Language: "python",
			}}
			got := d.Detect(files)
			if tt.wantMin > 0 && len(got) < tt.wantMin {
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
				if !found && tt.wantMin > 0 {
					t.Errorf("expected rule %q not found", tt.rule)
				}
			}
		})
	}
}

func TestLogicDetector_Detect_JavaScript(t *testing.T) {
	d := NewLogicDetector()

	tests := []struct {
		name    string
		content string
		wantMin int
		rule    string
	}{
		{
			name:    "loose equality",
			content: "if (x == 5) { return true; }",
			wantMin: 1,
			rule:    "loose-equality",
		},
		{
			name:    "var usage",
			content: "var x = 5;",
			wantMin: 1,
			rule:    "var-usage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := []types.DiffFile{{
				Path:     "test.js",
				Content:  tt.content,
				Language: "javascript",
			}}
			got := d.Detect(files)
			if tt.wantMin > 0 && len(got) < tt.wantMin {
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
				if !found && tt.wantMin > 0 {
					t.Errorf("expected rule %q not found", tt.rule)
				}
			}
		})
	}
}

func TestLogicDetector_UnsupportedLanguage(t *testing.T) {
	d := NewLogicDetector()
	files := []types.DiffFile{{
		Path:     "test.rs",
		Content:  `fn main() { let x = 1; }`,
		Language: "rust",
	}}
	got := d.Detect(files)
	if len(got) != 0 {
		t.Errorf("expected 0 findings, got %d", len(got))
	}
}
