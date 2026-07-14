package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/WorldOccupier/trusty/internal/config"
	"github.com/WorldOccupier/trusty/internal/llm"
	"github.com/WorldOccupier/trusty/internal/report"
	"github.com/WorldOccupier/trusty/internal/scanner"
	"github.com/WorldOccupier/trusty/internal/types"
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
		Use:   "trusty",
		Short: "AI Code Verification CLI",
		Long: `Trusty automates verification of AI-generated code.
3-tier engine: static analysis, LLM semantic analysis, behavioral verification.

Only 29% of developers trust AI-generated code. Trusty gives teams
confidence to ship faster.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "help" || cmd.Name() == "completion" {
				return nil
			}
			if cfgFile == "" {
				for _, name := range []string{".trusty.yml", ".trusty.yaml"} {
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
  trusty scan                          # Scan staged changes
  trusty scan --staged                 # Scan staged changes
  trusty scan --from HEAD~3 --to HEAD  # Scan commit range
  trusty scan --base main --head feat  # Scan branch diff
  trusty scan --format sarif           # Output SARIF format`,
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
  trusty hallu                           # Check staged changes
  trusty hallu --from HEAD~1 --to HEAD   # Check specific commits`,
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
  trusty report --format sarif --min-score 80
  trusty report --format json --min-score 70`,
		RunE: runReport,
	}

	reportCmd.Flags().StringVarP(&outputFmt, "format", "f", "json", "Report format: json, sarif")
	reportCmd.Flags().IntVarP(&minScore, "min-score", "m", 70, "Minimum trust score")
	reportCmd.Flags().BoolVarP(&staged, "staged", "s", false, "Scan staged changes")
	reportCmd.Flags().StringVar(&from, "from", "", "Start commit")
	reportCmd.Flags().StringVar(&to, "to", "", "End commit")

	securityCmd := &cobra.Command{
		Use:   "security",
		Short: "Scan for security vulnerabilities in code changes",
		Long: `Detect security vulnerabilities in code changes including:
  - SQL injection
  - Cross-site scripting (XSS)
  - Hardcoded secrets (API keys, tokens, passwords)
  - Command injection
  - Path traversal
  - Insecure cryptography

Examples:
  trusty security                          # Scan for vulnerabilities
  trusty security --staged                 # Scan staged changes
  trusty security --from HEAD~1 --to HEAD  # Check specific commits`,
		RunE: runSecurity,
	}
	securityCmd.Flags().BoolVarP(&staged, "staged", "s", false, "Scan staged changes only")
	securityCmd.Flags().StringVar(&from, "from", "", "Start commit")
	securityCmd.Flags().StringVar(&to, "to", "", "End commit")

	logicCmd := &cobra.Command{
		Use:   "logic",
		Short: "Detect logic errors in code changes",
		Long: `Detect logic errors in code changes including:
  - Off-by-one errors in loops
  - Inverted conditionals
  - Self-assignments
  - Missing switch defaults
  - Infinite loops
  - Edge case omissions

Examples:
  trusty logic                           # Detect logic errors
  trusty logic --staged                  # Check staged changes
  trusty logic --from HEAD~1 --to HEAD   # Check specific commits`,
		RunE: runLogic,
	}
	logicCmd.Flags().BoolVarP(&staged, "staged", "s", false, "Scan staged changes only")
	logicCmd.Flags().StringVar(&from, "from", "", "Start commit")
	logicCmd.Flags().StringVar(&to, "to", "", "End commit")

	testgenCmd := &cobra.Command{
		Use:   "testgen",
		Short: "Generate behavioral tests for changed functions",
		Long: `Generate behavioral test contracts for exported functions in Go files.
Analyzes function signatures and generates property-based test stubs.

Examples:
  trusty testgen                         # Generate tests for changed files
  trusty testgen --staged                # Generate tests for staged changes
  trusty testgen --from HEAD~1 --to HEAD # Generate for specific commits`,
		RunE: runTestGen,
	}
	testgenCmd.Flags().BoolVarP(&staged, "staged", "s", false, "Scan staged changes only")
	testgenCmd.Flags().StringVar(&from, "from", "", "Start commit")
	testgenCmd.Flags().StringVar(&to, "to", "", "End commit")

	root.AddCommand(scanCmd)
	root.AddCommand(halluCmd)
	root.AddCommand(reportCmd)
	root.AddCommand(securityCmd)
	root.AddCommand(logicCmd)
	root.AddCommand(testgenCmd)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runSecurity(cmd *cobra.Command, args []string) error {
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

	output := map[string]interface{}{
		"findings":      findings,
		"total":         len(findings),
		"files_scanned": len(files),
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	for _, f := range findings {
		if f.Severity == types.SeverityError || f.Severity == types.SeverityWarning {
			fmt.Fprintf(os.Stderr, "[%s] %s:%d %s\n", severityStr(f.Severity), f.Category, f.Line, f.Message)
		}
	}

	hasErrors := false
	for _, f := range findings {
		if f.Severity == types.SeverityError {
			hasErrors = true
			break
		}
	}
	if hasErrors {
		os.Exit(1)
	}

	return nil
}

func runLogic(cmd *cobra.Command, args []string) error {
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

	output := map[string]interface{}{
		"findings":      findings,
		"total":         len(findings),
		"files_scanned": len(files),
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	for _, f := range findings {
		if f.Severity == types.SeverityError || f.Severity == types.SeverityWarning {
			fmt.Fprintf(os.Stderr, "[%s] %s:%d %s\n", severityStr(f.Severity), f.Category, f.Line, f.Message)
		}
	}

	return nil
}

func severityStr(s types.Severity) string {
	switch s {
	case types.SeverityError:
		return "ERROR"
	case types.SeverityWarning:
		return "WARN"
	case types.SeverityInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

func runTestGen(cmd *cobra.Command, args []string) error {
	diffOpts := types.DiffOptions{
		Staged: staged,
		From:   from,
		To:     to,
	}

	files, err := scanner.GetDiff(diffOpts)
	if err != nil {
		return fmt.Errorf("getting diff: %w", err)
	}

	tg := scanner.NewTestGenerator()
	findings, err := tg.GenerateTests(files)
	if err != nil {
		return fmt.Errorf("test generation: %w", err)
	}

	output := map[string]interface{}{
		"results":       findings,
		"total":         len(findings),
		"files_scanned": len(files),
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	return nil
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
