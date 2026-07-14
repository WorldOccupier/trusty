package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/user/trustpilot/internal/config"
	"github.com/user/trustpilot/internal/llm"
	"github.com/user/trustpilot/internal/report"
	"github.com/user/trustpilot/internal/scanner"
	"github.com/user/trustpilot/internal/types"
)

var (
	cfgFile   string
	outputFmt string
	minScore  int
	from      string
	to        string
	base      string
	head      string
	staged    bool
	verbose   bool
)

func main() {
	root := &cobra.Command{
		Use:   "trustpilot",
		Short: "AI Code Verification CLI",
		Long: `TrustPilot automates verification of AI-generated code.
3-tier engine: static analysis, LLM semantic analysis, behavioral verification.

Only 29% of developers trust AI-generated code. TrustPilot gives teams
confidence to ship faster.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "help" || cmd.Name() == "completion" {
				return nil
			}
			if cfgFile == "" {
				for _, name := range []string{".trustpilot.yml", ".trustpilot.yaml"} {
					if _, err := os.Stat(name); err == nil {
						cfgFile = name
						break
					}
				}
			}
			return nil
		},
	}

	root.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file path")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan code changes for AI-generated code issues",
		Long: `Scan git diff with 3-tier verification engine.

Tier 1: Static analysis — AST parsing, import validation, pattern matching
Tier 2: LLM semantic analysis — detects hallucinated APIs, logic errors
Tier 3: Behavioral verification — function signature & error handling checks

Examples:
  trustpilot scan                          # Scan staged changes
  trustpilot scan --staged                 # Scan staged changes
  trustpilot scan --from HEAD~3 --to HEAD  # Scan commit range
  trustpilot scan --base main --head feat  # Scan branch diff
  trustpilot scan --format sarif           # Output SARIF format`,
		RunE: runScan,
	}

	scanCmd.Flags().BoolVarP(&staged, "staged", "s", false, "Scan staged changes only")
	scanCmd.Flags().StringVar(&from, "from", "", "Start commit (requires --to)")
	scanCmd.Flags().StringVar(&to, "to", "", "End commit (requires --from)")
	scanCmd.Flags().StringVar(&base, "base", "", "Base branch (requires --head)")
	scanCmd.Flags().StringVar(&head, "head", "", "Head branch (requires --base)")
	scanCmd.Flags().StringVarP(&outputFmt, "format", "f", "json", "Output format: json, sarif")
	scanCmd.Flags().IntVarP(&minScore, "min-score", "m", 0, "Minimum trust score (0-100)")

	halluCmd := &cobra.Command{
		Use:   "hallu",
		Short: "Detect hallucinated imports in code changes",
		Long: `Detect hallucinated imports and non-existent packages in AI-generated code.

Examples:
  trustpilot hallu                           # Check staged changes
  trustpilot hallu --from HEAD~1 --to HEAD   # Check specific commits`,
		RunE: runHallu,
	}

	halluCmd.Flags().BoolVarP(&staged, "staged", "s", false, "Check staged changes only")
	halluCmd.Flags().StringVar(&from, "from", "", "Start commit")
	halluCmd.Flags().StringVar(&to, "to", "", "End commit")

	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Generate scan report in various formats",
		Long: `Generate scan reports in JSON or SARIF format.

Examples:
  trustpilot report --format sarif --min-score 80
  trustpilot report --format json --min-score 70`,
		RunE: runReport,
	}

	reportCmd.Flags().StringVarP(&outputFmt, "format", "f", "json", "Report format: json, sarif")
	reportCmd.Flags().IntVarP(&minScore, "min-score", "m", 70, "Minimum trust score")
	reportCmd.Flags().BoolVarP(&staged, "staged", "s", false, "Scan staged changes")
	reportCmd.Flags().StringVar(&from, "from", "", "Start commit")
	reportCmd.Flags().StringVar(&to, "to", "", "End commit")

	root.AddCommand(scanCmd)
	root.AddCommand(halluCmd)
	root.AddCommand(reportCmd)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadConfig() (*config.Config, error) {
	if cfgFile != "" {
		return config.Load(cfgFile)
	}
	return config.Default(), nil
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

	diffOpts := types.DiffOptions{
		Staged: staged,
		From:   from,
		To:     to,
		Base:   base,
		Head:   head,
	}

	result, err := s.Scan(context.Background(), diffOpts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	reporter := report.New()
	scanResult := reporter.BuildResult(result.Files, result.Summary, result.TrustScore, result.Timestamp, result.DurationMs)

	switch cfg.Output.Format {
	case "sarif":
		if err := report.WriteSARIF(os.Stdout, &scanResult); err != nil {
			return fmt.Errorf("writing SARIF: %w", err)
		}
	default:
		if err := report.WriteJSON(os.Stdout, scanResult); err != nil {
			return fmt.Errorf("writing JSON: %w", err)
		}
	}

	if result.Summary.Status == "failed" {
		fmt.Fprintf(os.Stderr, "\nTrust score %d/%d — below minimum threshold of %d\n",
			result.TrustScore, 100, cfg.Scan.MinScore)
		os.Exit(1)
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
	fmt.Println(string(data))

	if len(issues) > 0 {
		fmt.Fprintf(os.Stderr, "\nFound %d potentially hallucinated import(s)\n", len(issues))
		os.Exit(1)
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

	outFile := "trustpilot-report.json"
	if len(args) > 0 {
		outFile = args[0]
	}

	switch outputFmt {
	case "sarif":
		outFile = "trustpilot.sarif"
		f, err := os.Create(filepath.Clean(outFile))
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		if err := report.WriteSARIF(f, &scanResult); err != nil {
			return fmt.Errorf("writing SARIF: %w", err)
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
