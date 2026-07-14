package compare

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/WorldOccupier/trusty/internal/types"
)

type Result struct {
	Baseline string `json:"baseline"`
	Current  string `json:"current"`

	NewFindings    []FindingRef `json:"new_findings"`
	FixedFindings  []FindingRef `json:"fixed_findings"`
	UnchangedCount int          `json:"unchanged_count"`
	ScoreChange    int          `json:"score_change"`
}

type FindingRef struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

func LoadResult(path string) (*types.ScanResult, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var r types.ScanResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &r, nil
}

func Compare(baseline, current *types.ScanResult) *Result {
	r := &Result{}

	baseFindings := buildIndex(baseline)
	currFindings := buildIndex(current)

	seen := map[string]bool{}

	for key, f := range currFindings {
		if _, exists := baseFindings[key]; !exists {
			r.NewFindings = append(r.NewFindings, f)
		}
		seen[key] = true
	}

	for key, f := range baseFindings {
		if _, exists := currFindings[key]; !exists {
			r.FixedFindings = append(r.FixedFindings, f)
		}
		if seen[key] {
			r.UnchangedCount++
		}
	}

	r.ScoreChange = current.TrustScore - baseline.TrustScore

	return r
}

func buildIndex(r *types.ScanResult) map[string]FindingRef {
	idx := make(map[string]FindingRef)
	for _, file := range r.Files {
		for _, f := range file.Findings {
			key := fmt.Sprintf("%s|%s|%d|%s", file.Path, f.Rule, f.Line, f.Message)
			idx[key] = FindingRef{
				File:    file.Path,
				Line:    f.Line,
				Rule:    f.Rule,
				Message: f.Message,
			}
		}
	}
	return idx
}

func PrintTable(r *Result) {
	fmt.Printf("Baseline vs Current Comparison\n")
	fmt.Printf("Score change: %+d\n\n", r.ScoreChange)

	if len(r.NewFindings) > 0 {
		fmt.Printf("New Findings (%d):\n", len(r.NewFindings))
		fmt.Println(strings.Repeat("-", 60))
		for _, f := range r.NewFindings {
			fmt.Printf("  %s:%d [%s] %s\n", f.File, f.Line, f.Rule, f.Message)
		}
		fmt.Println()
	}

	if len(r.FixedFindings) > 0 {
		fmt.Printf("Fixed Findings (%d):\n", len(r.FixedFindings))
		fmt.Println(strings.Repeat("-", 60))
		for _, f := range r.FixedFindings {
			fmt.Printf("  %s:%d [%s] %s\n", f.File, f.Line, f.Rule, f.Message)
		}
		fmt.Println()
	}

	fmt.Printf("Unchanged: %d findings\n", r.UnchangedCount)
}
