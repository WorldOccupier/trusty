package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/WorldOccupier/trusty/internal/llm"
	"github.com/WorldOccupier/trusty/internal/policy"
	"github.com/WorldOccupier/trusty/internal/report"
	"github.com/WorldOccupier/trusty/internal/scanner"
	"github.com/WorldOccupier/trusty/internal/types"
)
func runSecurity(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	diffOpts := types.DiffOptions{
		Staged: staged,
		From:   from,
		To:     to,
	}

	files, err := scanner.GetDiff(diffOpts)
	if err != nil {
		return fmt.Errorf("getting diff: %w", err)
	}

	sec := scanner.NewSecurityScanner()
	findings := sec.Scan(files)

	minSev := severityFromConfig(cfg.Rules.Security.Severity)
	if minSeverity != "" {
		if s := severityFromString(minSeverity); s > minSev {
			minSev = s
		}
	}
	findings = filterBySeverity(findings, minSev)

	output := map[string]interface{}{
		"findings":      findings,
		"total":         len(findings),
		"files_scanned": len(files),
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	if err := writeOutput(data, outFile); err != nil {
		return err
	}

	for _, f := range findings {
		if f.Severity == types.SeverityError || f.Severity == types.SeverityWarning {
			fmt.Fprintf(os.Stderr, "[%s] %s:%d %s\n", severityStr(f.Severity), f.Category, f.Line, f.Message)
		}
	}

	if len(findings) > 0 {
		return fmt.Errorf("found %d security issue(s)", len(findings))
	}

	return nil
}

func runLogic(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	diffOpts := types.DiffOptions{
		Staged: staged,
		From:   from,
		To:     to,
	}

	files, err := scanner.GetDiff(diffOpts)
	if err != nil {
		return fmt.Errorf("getting diff: %w", err)
	}

	ld := scanner.NewLogicDetector()
	findings := ld.Detect(files)

	minSev := severityFromConfig(cfg.Rules.LogicErrors.Severity)
	if minSeverity != "" {
		if s := severityFromString(minSeverity); s > minSev {
			minSev = s
		}
	}
	findings = filterBySeverity(findings, minSev)

	output := map[string]interface{}{
		"findings":      findings,
		"total":         len(findings),
		"files_scanned": len(files),
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	if err := writeOutput(data, outFile); err != nil {
		return err
	}

	for _, f := range findings {
		if f.Severity == types.SeverityError || f.Severity == types.SeverityWarning {
			fmt.Fprintf(os.Stderr, "[%s] %s:%d %s\n", severityStr(f.Severity), f.Category, f.Line, f.Message)
		}
	}

	if len(findings) > 0 {
		return fmt.Errorf("found %d logic error(s)", len(findings))
	}

	return nil
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if minScore > 0 {
		cfg.Scan.MinScore = minScore
	}
	if outputFmt != "" {
		cfg.Output.Format = outputFmt
	}

	var llmProvider llm.Provider
	if cfg.LLM.APIKey != "" {
		llmCfg := llm.ProviderConfig{
			Model:       cfg.LLM.Model,
			Temperature: cfg.LLM.Temperature,
			APIKey:      cfg.LLM.APIKey,
			BaseURL:     cfg.LLM.BaseURL,
		}
		llmProvider = llm.NewProvider(cfg.LLM.Provider, llmCfg)
	}

	s := scanner.NewScanner(cfg, llmProvider)

	if noCache {
		s.SetCacheEnabled(false)
	}

	if policyFile != "" {
		p, err := policy.LoadFromFile(policyFile)
		if err != nil {
			return fmt.Errorf("loading policy file: %w", err)
		}
		policy.Apply(cfg, p)
	}
	if policyURL != "" {
		p, err := policy.LoadFromURL(policyURL)
		if err != nil {
			return fmt.Errorf("loading policy URL: %w", err)
		}
		policy.Apply(cfg, p)
	}

	diffOpts := types.DiffOptions{
		Staged: staged,
		From:   from,
		To:     to,
		Base:   base,
		Head:   head,
	}

	if diffFile != "" {
		raw, err := os.ReadFile(filepath.Clean(diffFile))
		if err != nil {
			return fmt.Errorf("reading diff file: %w", err)
		}
		diffOpts.RawDiff = string(raw)
	}

	var result *types.ScanResult
	if allPackages {
		results, err := s.ScanAllPackages(context.Background(), diffOpts)
		s.FlushCache()
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
		data, _ := json.MarshalIndent(results, "", "  ")
		if err := writeOutput(data, outFile); err != nil {
			return err
		}
		for _, pkg := range results {
			if pkg.Error != "" {
				fmt.Fprintf(os.Stderr, "[ERROR] %s: %s\n", pkg.Path, pkg.Error)
			} else if pkg.Result != nil && pkg.Result.Summary.TotalIssues > 0 {
				fmt.Fprintf(os.Stderr, "[WARN] %s: %d issue(s), score %d/100\n",
					pkg.Path, pkg.Result.Summary.TotalIssues, pkg.Result.TrustScore)
			}
		}
		return nil
	}

	var scanErr error
	result, scanErr = s.Scan(context.Background(), diffOpts)
	s.FlushCache()
	if scanErr != nil {
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	if trackRegression {
		hist := scanner.LoadHistory(".trusty-history.json")
		entry := hist.Record(result.TrustScore, result.Summary.TotalIssues, result.Summary.Errors, result.Summary.Warnings, result.Summary.Info, result.Summary.FilesScanned)
		if err := hist.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save regression history: %v\n", err)
		}
		if delta := hist.Compare(entry); delta != "" {
			fmt.Fprintf(os.Stderr, "Regression: %s\n", delta)
		}
	}

	reporter := report.New()
	scanResult := reporter.BuildResult(result.Files, result.Summary, result.TrustScore, result.Timestamp, result.DurationMs)

	out := os.Stdout
	if outFile != "" {
		f, err := os.Create(filepath.Clean(outFile))
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	switch cfg.Output.Format {
	case "sarif":
		if err := report.WriteSARIF(out, &scanResult); err != nil {
			return fmt.Errorf("writing SARIF: %w", err)
		}
	case "html":
		data, err := report.FormatHTML(scanResult)
		if err != nil {
			return fmt.Errorf("formatting HTML: %w", err)
		}
		if out != os.Stdout {
			if _, err := fmt.Fprint(out, data); err != nil {
				return fmt.Errorf("writing HTML: %w", err)
			}
		} else {
			fmt.Println(data)
		}
	default:
		if err := report.WriteJSON(out, scanResult); err != nil {
			return fmt.Errorf("writing JSON: %w", err)
		}
	}

	if result.Summary.TotalIssues > 0 {
		return fmt.Errorf("found %d issue(s) — trust score %d/100",
			result.Summary.TotalIssues, result.TrustScore)
	}

	return nil
}

func runHallu(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	s := scanner.NewScanner(cfg, nil)
	diffOpts := types.DiffOptions{
		Staged: staged,
		From:   from,
		To:     to,
	}

	result, err := s.Scan(context.Background(), diffOpts)
	if err != nil {
		return fmt.Errorf("hallucination check failed: %w", err)
	}

	type halluIssue struct {
		Rule       string `json:"rule"`
		Severity   int    `json:"severity"`
		Message    string `json:"message"`
		FilePath   string `json:"file_path"`
		Line       int    `json:"line,omitempty"`
		Suggestion string `json:"suggestion,omitempty"`
	}

	var issues []halluIssue
	for _, file := range result.Files {
		for _, finding := range file.Findings {
			if finding.Category == "hallucination" || finding.Rule == "hallucinated-import" {
				issues = append(issues, halluIssue{
					Rule:       finding.Rule,
					Severity:   int(finding.Severity),
					Message:    finding.Message,
					FilePath:   file.Path,
					Line:       finding.Line,
					Suggestion: finding.Suggestion,
				})
			}
		}
	}

	output := map[string]interface{}{
		"hallucinated_imports": issues,
		"total":                len(issues),
		"files_scanned":        result.Summary.FilesScanned,
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	if err := writeOutput(data, outFile); err != nil {
		return err
	}

	if len(issues) > 0 {
		return fmt.Errorf("found %d potentially hallucinated import(s)", len(issues))
	}

	return nil
}

func runReport(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if minScore > 0 {
		cfg.Scan.MinScore = minScore
	}

	diffOpts := types.DiffOptions{
		Staged: staged,
		From:   from,
		To:     to,
	}

	s := scanner.NewScanner(cfg, nil)
	result, err := s.Scan(context.Background(), diffOpts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	reporter := report.New()
	scanResult := reporter.BuildResult(result.Files, result.Summary, result.TrustScore, result.Timestamp, result.DurationMs)

	outFile := "trusty-report.json"
	if len(args) > 0 {
		outFile = args[0]
	}

	switch outputFmt {
	case "sarif":
		outFile = "trusty.sarif"
		f, err := os.Create(filepath.Clean(outFile))
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		if err := report.WriteSARIF(f, &scanResult); err != nil {
			return fmt.Errorf("writing SARIF: %w", err)
		}
	case "html":
		outFile = "trusty-report.html"
		data, err := report.FormatHTML(scanResult)
		if err != nil {
			return fmt.Errorf("formatting HTML: %w", err)
		}
		if err := os.WriteFile(filepath.Clean(outFile), []byte(data), 0644); err != nil {
			return fmt.Errorf("writing HTML report: %w", err)
		}
	default:
		data, err := report.FormatJSON(scanResult)
		if err != nil {
			return fmt.Errorf("formatting report: %w", err)
		}
		if err := os.WriteFile(filepath.Clean(outFile), []byte(data), 0644); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
	}

	fmt.Printf("Report written to %s (trust score: %d/100)\n", outFile, result.TrustScore)
	return nil
}

