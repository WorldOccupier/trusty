package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/WorldOccupier/trusty/internal/fixer"
	"github.com/WorldOccupier/trusty/internal/scanner"
	"github.com/WorldOccupier/trusty/internal/types"
	"github.com/spf13/cobra"
)

var demoFiles = map[string]string{
	"main.go": `package main

import (
	"database/sql"
	"fmt"
	"os"
)

func main() {
	username := os.Args[1]
	query := "SELECT * FROM users WHERE name='" + username + "'"
	db, _ := sql.Open("mysql", "user:pass@tcp(localhost:3306)/db")
	rows, _ := db.Query(query)
	fmt.Println(rows)
}

func unused() {
	_ = fmt.Sprintf("this import is used")
}
`,
	"calc.go": `package main

func sumTen() int {
	sum := 0
	for i := 0; i <= 10; i++ {
		sum += i
	}
	return sum
}

func getHalf(items []string) []string {
	return items[:len(items)-1]
}

func unsafeDivide(a, b int) int {
	return a / b
}

func processAll(data []string) {
	for i := 0; i < len(data); i++ {
		process(data[i])
	}
}

func process(v string) {}
`,
	"utils.go": `package main

import (
	"fmt"
	"os/exec"
)

func runCmd(input string) {
	cmd := exec.Command("sh", "-c", "echo "+input)
	cmd.Run()
}

func setValue(v int) int {
	v = v
	return v
}

func unused() {
	fmt.Println("not used")
}
`,
}

func detectLang(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	default:
		return "go"
	}
}

func runDemo(_ *cobra.Command, _ []string) error {
	tmpDir, err := os.MkdirTemp("", "trusty-demo-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	fmt.Print("Creating sample project with common AI-generated code issues...")
	var files []types.DiffFile
	for name, content := range demoFiles {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
		files = append(files, types.DiffFile{
			Path:     name,
			Language: detectLang(name),
			Content:  content,
		})
	}
	fmt.Println(" done")

	fmt.Println("\nRunning Trusty analyzers...")

	sec := scanner.NewSecurityScanner()
	logic := scanner.NewLogicDetector()
	static := scanner.NewStaticAnalyzer()

	var allFindings []types.Finding
	fileResults := make(map[string][]types.Finding)

	for _, f := range files {
		var findings []types.Finding
		findings = append(findings, static.Analyze(f.Path, f.Content)...)
		logicFindings := logic.Detect([]types.DiffFile{f})
		findings = append(findings, logicFindings...)
		secFindings := sec.Scan([]types.DiffFile{f})
			findings = append(findings, secFindings...)

		for i := range findings {
			if findings[i].Category == "" {
				findings[i].Category = f.Path
			}
		}
		allFindings = append(allFindings, findings...)
		fileResults[f.Path] = findings
	}

	if len(allFindings) == 0 {
		fmt.Println("\nNo issues detected in demo code.")
		fmt.Println("\nNote: Some checks (hallucinated imports, LLM analysis) require")
		fmt.Println("an API key. Set OPENAI_API_KEY for full 3-tier scanning.")
		return nil
	}

	errors := 0
	warnings := 0
	infos := 0
	for _, f := range allFindings {
		switch f.Severity {
		case types.SeverityError:
			errors++
		case types.SeverityWarning:
			warnings++
		case types.SeverityInfo:
			infos++
		}
	}

	score := 100 - (errors*15 + warnings*7 + infos*3)
	if score < 0 {
		score = 0
	}

	fmt.Printf("\nTrust Score: %d/100\n", score)
	fmt.Printf("Files Scanned: %d\n", len(files))
	fmt.Printf("Issues Found: %d (%d errors, %d warnings, %d info)\n\n",
		len(allFindings), errors, warnings, infos)

	for _, f := range files {
		findings := fileResults[f.Path]
		if len(findings) == 0 {
			continue
		}
		fmt.Printf("--- %s ---\n", f.Path)
		for _, finding := range findings {
			sev := "info"
			if finding.Severity == types.SeverityError {
				sev = "error"
			} else if finding.Severity == types.SeverityWarning {
				sev = "warning"
			}
			msg := fmt.Sprintf("  [%s] %s", sev, finding.Message)
			if finding.Line > 0 {
				msg += fmt.Sprintf(" (line %d)", finding.Line)
			}
			fmt.Println(msg)
			if finding.Suggestion != "" {
				fmt.Printf("         Suggestion: %s\n", finding.Suggestion)
			}
		}
		fmt.Println()
	}

	// Also demonstrate fix suggestions
	fmt.Println("\n=== Fix Suggestions ===")
	fixr := fixer.New()
	fixr.DryRun = true
	fixResults, _ := fixr.ApplyFindings(allFindings, tmpDir)
	for _, fr := range fixResults {
		if fr.Fix != "" && fr.Fix != "No auto-fix available" {
			fmt.Printf("  %s:%d — %s\n", fr.File, fr.Line, fr.Fix)
		}
	}

	// Guide to explain
	fmt.Println("\n=== Explain Rules ===")
	shown := make(map[string]bool)
	for _, f := range allFindings {
		if !shown[f.Rule] {
			fmt.Printf("  trusty explain %s\n", f.Rule)
			shown[f.Rule] = true
		}
	}

	fmt.Println("\nTip: Run 'trusty fix results.json --dry-run' on real scan results to preview fixes.")
	fmt.Println("Tip: Run 'trusty explain <rule>' to learn more about any finding rule.")

	fmt.Println("\nThis demo ran static analysis, security, and logic checks.")
	fmt.Println("For LLM-based analysis, set OPENAI_API_KEY and run:")
	fmt.Println("  trusty scan --staged")
	return nil
}
