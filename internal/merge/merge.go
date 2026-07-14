package merge

import (
	"context"
	"fmt"
	"os"

	"github.com/WorldOccupier/trusty/internal/config"
	"github.com/WorldOccupier/trusty/internal/policy"
	"github.com/WorldOccupier/trusty/internal/scanner"
	"github.com/WorldOccupier/trusty/internal/types"
)

type Result struct {
	Passed  bool
	Message string
	Details *Details
}

type Details struct {
	ScanResult        *types.ScanResult
	PolicyViolations  []policy.Violation
	RegressionMessage string
}

func Run(ctx context.Context, cfg *config.Config, policyPath string, track bool) (*Result, error) {
	s := scanner.NewScanner(cfg, nil)

	diffOpts := types.DiffOptions{
		Staged: true,
	}

	scanResult, err := s.Scan(ctx, diffOpts)
	s.FlushCache()
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	d := &Details{
		ScanResult: scanResult,
	}

	if policyPath != "" {
		p, err := policy.LoadFromFile(policyPath)
		if err != nil {
			return nil, fmt.Errorf("loading policy: %w", err)
		}
		policy.Apply(cfg, p)
	}

	var allFindings []types.Finding
	for _, f := range scanResult.Files {
		allFindings = append(allFindings, f.Findings...)
	}

	allPolicies, err := policy.LoadPolicies(policyPath)
	if err == nil {
		violations := policy.Evaluate(allFindings, allPolicies)
		d.PolicyViolations = violations
		if len(violations) > 0 {
			for _, v := range violations {
				if v.Action == "block" {
					return &Result{
						Passed:  false,
						Message: fmt.Sprintf("Blocked by policy %q: %s", v.PolicyName, v.Message),
						Details: d,
					}, nil
				}
			}
		}
	} else if policyPath != "" {
		fmt.Fprintf(os.Stderr, "Warning: could not load policies from %s: %v\n", policyPath, err)
	}

	if track {
		hist := scanner.LoadHistory(".trusty-history.json")
		entry := hist.Record(scanResult.TrustScore, scanResult.Summary.TotalIssues, scanResult.Summary.Errors, scanResult.Summary.Warnings, scanResult.Summary.Info, scanResult.Summary.FilesScanned)
		if err := hist.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save regression history: %v\n", err)
		}
		d.RegressionMessage = hist.Compare(entry)
	}

	passed := true
	issues := []string{}

	if scanResult.Summary.TotalIssues > 0 {
		passed = false
		issues = append(issues, fmt.Sprintf("found %d issue(s) with trust score %d/100", scanResult.Summary.TotalIssues, scanResult.TrustScore))
	}

	if d.RegressionMessage != "" && d.RegressionMessage != "No regressions detected." {
		passed = false
		issues = append(issues, d.RegressionMessage)
	}

	message := "All checks passed"
	if !passed {
		message = "Gate blocked: "
		for i, issue := range issues {
			if i > 0 {
				message += "; "
			}
			message += issue
		}
	}

	return &Result{
		Passed:  passed,
		Message: message,
		Details: d,
	}, nil
}
