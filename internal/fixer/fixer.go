package fixer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

type Fixer struct {
	DryRun      bool
	Interactive bool
	Fixed       int
	Skipped     int
	Errors      int
}

func New() *Fixer {
	return &Fixer{}
}

type FixResult struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
	Fix     string `json:"fix"`
	Applied bool   `json:"applied"`
}

func (f *Fixer) ApplyFindings(findings []types.Finding, sourceDir string) ([]FixResult, error) {
	var results []FixResult
	fileFindings := groupByFile(findings)

	for filePath, ff := range fileFindings {
		fullPath := filepath.Join(sourceDir, filePath)
		content, err := os.ReadFile(filepath.Clean(fullPath))
		if err != nil {
			for range ff {
				results = append(results, FixResult{
					File:    filePath,
					Message: "Could not read file",
					Applied: false,
				})
				f.Errors++
			}
			continue
		}

		lines := strings.Split(string(content), "\n")
		modified := make([]string, len(lines))
		copy(modified, lines)

		for _, finding := range ff {
			fix := generateFix(finding)
			if fix == "" {
				results = append(results, FixResult{
					File:    filePath,
					Line:    finding.Line,
					Rule:    finding.Rule,
					Message: finding.Message,
					Fix:     "No auto-fix available",
					Applied: false,
				})
				f.Skipped++
				continue
			}

			result := FixResult{
				File:    filePath,
				Line:    finding.Line,
				Rule:    finding.Rule,
				Message: finding.Message,
				Fix:     fix,
			}

			if f.Interactive {
				fmt.Printf("\n%s:%d\n", filePath, finding.Line)
				fmt.Printf("  Issue: %s\n", finding.Message)
				fmt.Printf("  Suggestion: %s\n", fix)
				fmt.Printf("  Apply? [y/N] ")
				var response string
				fmt.Scanln(&response)
				response = strings.TrimSpace(strings.ToLower(response))
				if response != "y" && response != "yes" {
					result.Applied = false
					results = append(results, result)
					f.Skipped++
					continue
				}
			}

			if f.DryRun {
				result.Applied = true
				results = append(results, result)
				f.Fixed++
				continue
			}

			newContent := applyFix(modified, finding, fix)
			if newContent != "" {
				modified = strings.Split(newContent, "\n")
				result.Applied = true
				f.Fixed++
			} else {
				result.Applied = false
				f.Errors++
			}
			results = append(results, result)
		}

		if !f.DryRun && !f.Interactive {
			newContent := strings.Join(modified, "\n")
			if err := os.WriteFile(filepath.Clean(fullPath), []byte(newContent), 0644); err != nil {
				return results, fmt.Errorf("writing %s: %w", fullPath, err)
			}
		}
	}

	return results, nil
}

func (f *Fixer) ApplyResultFile(resultPath string, sourceDir string) error {
	data, err := os.ReadFile(filepath.Clean(resultPath))
	if err != nil {
		return fmt.Errorf("reading result file: %w", err)
	}

	var scanResult types.ScanResult
	if err := json.Unmarshal(data, &scanResult); err != nil {
		return fmt.Errorf("parsing result: %w", err)
	}

	var allFindings []types.Finding
	for _, fr := range scanResult.Files {
		allFindings = append(allFindings, fr.Findings...)
	}

	if len(allFindings) == 0 {
		fmt.Println("No findings to fix.")
		return nil
	}

	results, err := f.ApplyFindings(allFindings, sourceDir)
	if err != nil {
		return err
	}

	output, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(output))

	fmt.Fprintf(os.Stderr, "\nFixed: %d, Skipped: %d, Errors: %d\n", f.Fixed, f.Skipped, f.Errors)
	return nil
}

func groupByFile(findings []types.Finding) map[string][]types.Finding {
	grouped := make(map[string][]types.Finding)
	for _, f := range findings {
		file := f.Category
		if file == "" {
			file = "unknown"
		}
		grouped[file] = append(grouped[file], f)
	}
	return grouped
}

func generateFix(finding types.Finding) string {
	if finding.Suggestion != "" {
		return finding.Suggestion
	}

	switch finding.Rule {
	case "nil-dereference":
		return "Add nil check before access"
	case "unchecked-error":
		return "Check and handle the error return value"
	case "missing-deferred-close":
		return "Add defer resource.Close()"
	case "typed-nil-interface":
		return "Return explicit typed nil instead of bare nil"
	case "hardcoded-index":
		return "Add length check or use range loop"
	default:
		return ""
	}
}

func applyFix(lines []string, finding types.Finding, fix string) string {
	idx := finding.Line - 1
	if idx < 0 || idx >= len(lines) {
		return ""
	}

	line := lines[idx]
	switch finding.Rule {
	case "missing-deferred-close":
		if strings.Contains(fix, "defer") {
			indent := leadingWhitespace(line)
			newLine := indent + extractDefer(fix)
			newLines := make([]string, 0, len(lines)+1)
			newLines = append(newLines, lines[:idx]...)
			newLines = append(newLines, newLine)
			newLines = append(newLines, lines[idx:]...)
			return strings.Join(newLines, "\n")
		}
	}

	return ""
}

func leadingWhitespace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return s[:i]
}

func extractDefer(suggestion string) string {
	if idx := strings.Index(suggestion, "defer "); idx >= 0 {
		end := strings.Index(suggestion[idx:], "\n")
		if end < 0 {
			end = len(suggestion[idx:])
		}
		return strings.TrimSpace(suggestion[idx : idx+end])
	}
	return ""
}
