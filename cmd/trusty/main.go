package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/WorldOccupier/trusty/internal/audit"
	"github.com/WorldOccupier/trusty/internal/config"
	"github.com/WorldOccupier/trusty/internal/dashboard"
	"github.com/WorldOccupier/trusty/internal/llm"
	"github.com/WorldOccupier/trusty/internal/policy"
	"github.com/WorldOccupier/trusty/internal/prcomment"
	"github.com/WorldOccupier/trusty/internal/report"
	"github.com/WorldOccupier/trusty/internal/sbom"
	"github.com/WorldOccupier/trusty/internal/scanner"
	"github.com/WorldOccupier/trusty/internal/tui"
	"github.com/WorldOccupier/trusty/internal/types"
)

var (
	cfgFile         string
	outputFmt       string
	minScore        int
	minSeverity     string
	fuzzIterations  int
	from            string
	to              string
	base            string
	head            string
	staged          bool
	verbose         bool
	fuzzDir         string
	noCache         bool
	fingerprintAll  bool
	outFile         string
	diffFile        string
	trackRegression bool
	allPackages     bool
	policyFile      string
	policyURL       string
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
	scanCmd.Flags().BoolVar(&noCache, "no-cache", false, "Disable incremental cache")
	scanCmd.Flags().StringVarP(&outFile, "output", "o", "", "Write output to file")
	scanCmd.Flags().StringVar(&diffFile, "diff-file", "", "Read diff from file instead of git")
	scanCmd.Flags().BoolVar(&trackRegression, "track", false, "Track regression history in .trusty-history.json")
	scanCmd.Flags().BoolVar(&allPackages, "all-packages", false, "Scan all Go modules in workspace")
	scanCmd.Flags().StringVar(&policyFile, "policy-file", "", "Path to team policy YAML overlay")
	scanCmd.Flags().StringVar(&policyURL, "policy-url", "", "URL to team policy YAML overlay")

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
	halluCmd.Flags().StringVarP(&outFile, "output", "o", "", "Write output to file")

	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Generate scan report in various formats",
		Long: `Generate scan reports in JSON or SARIF format.

Examples:
  trusty report --format sarif --min-score 80
  trusty report --format json --min-score 70`,
		RunE: runReport,
	}

	reportCmd.Flags().StringVarP(&outputFmt, "format", "f", "json", "Report format: json, sarif, html")
	reportCmd.Flags().IntVarP(&minScore, "min-score", "m", 70, "Minimum trust score")
	reportCmd.Flags().BoolVarP(&staged, "staged", "s", false, "Scan staged changes")
	reportCmd.Flags().StringVar(&from, "from", "", "Start commit")
	reportCmd.Flags().StringVar(&to, "to", "", "End commit")
	reportCmd.Flags().StringVarP(&outFile, "output", "o", "", "Write output to file")

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
	securityCmd.Flags().StringVar(&minSeverity, "min-severity", "", "Minimum severity (error, warning, info)")
	securityCmd.Flags().StringVarP(&outFile, "output", "o", "", "Write output to file")

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
	logicCmd.Flags().StringVar(&minSeverity, "min-severity", "", "Minimum severity (error, warning, info)")
	logicCmd.Flags().StringVarP(&outFile, "output", "o", "", "Write output to file")

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
	testgenCmd.Flags().StringVar(&fuzzDir, "fuzz-dir", ".", "Directory to scan for functions (fuzz mode)")

	fuzzCmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Property-based fuzz testing for exported Go functions",
		Long: `Generate random inputs for exported Go functions and verify they don't panic.
Analyzes function signatures and generates type-appropriate random test values.

Examples:
  trusty fuzz                         # Fuzz all changed Go files
  trusty fuzz --staged                # Fuzz staged changes
  trusty fuzz --dir ./internal/scanner # Fuzz specific directory
  trusty fuzz --iterations 1000       # Set iterations per function`,
		RunE: runFuzz,
	}
	fuzzCmd.Flags().BoolVarP(&staged, "staged", "s", false, "Scan staged changes only")
	fuzzCmd.Flags().StringVar(&from, "from", "", "Start commit")
	fuzzCmd.Flags().StringVar(&to, "to", "", "End commit")
	fuzzCmd.Flags().StringVar(&fuzzDir, "dir", ".", "Directory containing Go files to fuzz")
	fuzzCmd.Flags().IntVar(&fuzzIterations, "iterations", 100, "Number of fuzz iterations per function")

	intentCmd := &cobra.Command{
		Use:   "intent",
		Short: "Verify code matches commit intent via LLM",
		Long: `Analyze code changes against commit messages to verify the implementation
matches the described intent. Uses LLM to detect mismatches, missing pieces,
or contradictory implementations.

Examples:
  trusty intent                         # Check intent of latest changes
  trusty intent --staged                # Check staged changes
  trusty intent --from HEAD~1 --to HEAD # Check specific commits`,
		RunE: runIntent,
	}
	intentCmd.Flags().BoolVarP(&staged, "staged", "s", false, "Check staged changes only")
	intentCmd.Flags().StringVar(&from, "from", "", "Start commit")
	intentCmd.Flags().StringVar(&to, "to", "", "End commit")

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold a .trusty.yml config file",
		Long: `Generate a default .trusty.yml configuration file in the current directory.
Will not overwrite an existing config file.

Examples:
  trusty init`,
		RunE: runInit,
	}

	fingerprintCmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Detect AI-generated code patterns statistically",
		Long: `Analyze code for statistical patterns that correlate with AI-generated code.
Uses 8 signal dimensions: comment density, line uniformity, doc coverage,
function length consistency, naming conventions, repeated patterns,
import grouping, and error handling verbosity.

Examples:
  trusty fingerprint                       # Analyze changed files
  trusty fingerprint --staged              # Analyze staged changes
  trusty fingerprint --all                 # Analyze all files in repo
  trusty fingerprint --from HEAD~1 --to HEAD`,
		RunE: runFingerprint,
	}
	fingerprintCmd.Flags().BoolVarP(&staged, "staged", "s", false, "Analyze staged changes only")
	fingerprintCmd.Flags().StringVar(&from, "from", "", "Start commit")
	fingerprintCmd.Flags().StringVar(&to, "to", "", "End commit")
	fingerprintCmd.Flags().BoolVar(&fingerprintAll, "all", false, "Analyze all tracked Go files")

	watchCmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch files and auto-scan on changes",
		Long: `Watch Go source files for changes and automatically re-run scans.
Uses fsnotify to detect file modifications with debouncing.

Examples:
  trusty watch                          # Watch current directory
  trusty watch ./internal/scanner       # Watch specific directory
  trusty watch ./pkg/... ./cmd/...      # Watch multiple directories`,
		RunE: runWatch,
	}

	prCommentCmd := &cobra.Command{
		Use:   "pr-comment",
		Short: "Post scan results as a GitHub PR comment",
		Long: `Read a scan result JSON file and post a formatted comment
to the GitHub PR specified by the GITHUB_TOKEN, GITHUB_REPOSITORY,
and GITHUB_PR_NUMBER environment variables.

Examples:
  trusty scan --output results.json
  trusty pr-comment results.json`,
		RunE: runPRComment,
	}

	tuiCmd := &cobra.Command{
		Use:   "tui",
		Short: "Interactive TUI for browsing scan results",
		Long: `Launch a terminal UI to browse scan results from a file
or run a fresh scan interactively.

Examples:
  trusty tui                          # Launch TUI with live scan
  trusty tui results.json             # Browse existing results`,
		RunE: runTUI,
	}

	auditCmd := &cobra.Command{
		Use:   "audit",
		Short: "View scan audit trail",
		Long: `Display the scan audit trail with historical results.
Stored in .trusty-audit.jsonl (append-only JSONL format).

Examples:
  trusty audit                          # Show recent audit entries
  trusty audit --limit 50               # Show last 50 entries
  trusty audit --status failed           # Filter by status
  trusty audit --since 2026-01-01       # Entries since date
  trusty audit --json                   # Output as JSON`,
		RunE: runAudit,
	}
	auditCmd.Flags().Int("limit", 20, "Number of entries to show")
	auditCmd.Flags().String("status", "", "Filter by status (clean, warning, failed)")
	auditCmd.Flags().String("since", "", "Show entries since date (RFC3339)")
	auditCmd.Flags().Bool("json", false, "Output as JSON")

	sbomCmd := &cobra.Command{
		Use:   "sbom",
		Short: "Generate software bill of materials",
		Long: `Generate a CycloneDX SBOM from Go module dependencies.
Scans go.mod files in the workspace.

Examples:
  trusty sbom                           # Generate SBOM for root module
  trusty sbom --all                     # Generate SBOM for all modules
  trusty sbom --output bom.json         # Write to file`,
		RunE: runSBOM,
	}
	sbomCmd.Flags().Bool("all", false, "Scan all Go modules in workspace")
	sbomCmd.Flags().StringP("output", "o", "", "Write output to file")

	policyCheckCmd := &cobra.Command{
		Use:   "policy",
		Short: "Evaluate YAML/OPA policies against findings",
		Long: `Evaluate verification policies against scan findings.
Supports YAML-based policies with conditions on severity,
rule, and category fields.

Examples:
  trusty policy --policy policy.yml     # Evaluate YAML policy
  trusty policy --policy policy.rego --opa  # Evaluate via OPA
  trusty scan --output findings.json
  trusty policy --policy policy.yml --input findings.json`,
		RunE: runPolicyCheck,
	}
	policyCheckCmd.Flags().StringP("policy", "p", "policy.yml", "Path to policy file (.yml or .rego)")
	policyCheckCmd.Flags().String("input", "", "Input findings JSON file (default: use live scan)")
	policyCheckCmd.Flags().Bool("opa", false, "Use OPA binary to evaluate Rego policies")

	dashboardCmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Generate HTML dashboard from audit data",
		Long: `Generate a self-contained HTML dashboard with score trends
and scan history. Reads from .trusty-audit.jsonl.

Examples:
  trusty dashboard                      # Generate HTML dashboard
  trusty dashboard --output dashboard.html
  trusty dashboard --json               # Output data as JSON`,
		RunE: runDashboard,
	}
	dashboardCmd.Flags().StringP("output", "o", "trusty-dashboard.html", "Output file path")
	dashboardCmd.Flags().Bool("json", false, "Output data as JSON")

	root.AddCommand(scanCmd)
	root.AddCommand(halluCmd)
	root.AddCommand(reportCmd)
	root.AddCommand(securityCmd)
	root.AddCommand(logicCmd)
	root.AddCommand(testgenCmd)
	root.AddCommand(fuzzCmd)
	root.AddCommand(intentCmd)
	root.AddCommand(initCmd)
	root.AddCommand(fingerprintCmd)
	root.AddCommand(watchCmd)
	root.AddCommand(prCommentCmd)
	root.AddCommand(tuiCmd)
	root.AddCommand(auditCmd)
	root.AddCommand(sbomCmd)
	root.AddCommand(policyCheckCmd)
	root.AddCommand(dashboardCmd)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

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
		os.Exit(1)
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
		os.Exit(1)
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

func severityFromString(s string) types.Severity {
	switch s {
	case "error":
		return types.SeverityError
	case "warning", "warn":
		return types.SeverityWarning
	case "info":
		return types.SeverityInfo
	default:
		return types.SeverityInfo
	}
}

func severityFromConfig(s string) types.Severity {
	return severityFromString(s)
}

func filterBySeverity(findings []types.Finding, minSev types.Severity) []types.Finding {
	if minSev <= types.SeverityInfo {
		return findings
	}
	var filtered []types.Finding
	for _, f := range findings {
		if f.Severity >= minSev {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func writeOutput(data []byte, path string) error {
	if path == "" {
		fmt.Println(string(data))
		return nil
	}
	return os.WriteFile(filepath.Clean(path), data, 0644)
}

func runInit(cmd *cobra.Command, args []string) error {
	for _, name := range []string{".trusty.yml", ".trusty.yaml"} {
		if _, err := os.Stat(name); err == nil {
			return fmt.Errorf("%s already exists", name)
		}
	}
	def := `# Trusty Configuration
version: 1

scan:
  min_score: 70
  languages:
    - go
    - python
    - typescript

llm:
  provider: openai
  model: gpt-4o
  temperature: 0.1
  # api_key: set via OPENAI_API_KEY or ANTHROPIC_API_KEY

rules:
  hallucination:
    severity: error
  logic_errors:
    severity: warning
  security:
    severity: error

output:
  format: pretty
`
	if err := os.WriteFile(".trusty.yml", []byte(def), 0644); err != nil {
		return fmt.Errorf("writing .trusty.yml: %w", err)
	}
	fmt.Println("Created .trusty.yml")
	return nil
}

func runFuzz(cmd *cobra.Command, args []string) error {
	_, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	var files []types.DiffFile

	if cmd.Flags().Changed("dir") || (!staged && from == "" && to == "") {
		goFiles, err := filepath.Glob(filepath.Join(fuzzDir, "*.go"))
		if err != nil || len(goFiles) == 0 {
			fmt.Println(`{"functions":[],"total":0,"files_scanned":0,"errors":0}`)
			return nil
		}
		for _, gf := range goFiles {
			if strings.HasSuffix(gf, "_test.go") || strings.HasSuffix(gf, "_fuzz_test.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Clean(gf))
			if err != nil {
				continue
			}
			files = append(files, types.DiffFile{
				Path:     gf,
				Language: "go",
				Content:  string(data),
			})
		}
	} else {
		diffOpts := types.DiffOptions{
			Staged: staged,
			From:   from,
			To:     to,
		}
		files, err = scanner.GetDiff(diffOpts)
		if err != nil {
			return fmt.Errorf("getting diff: %w", err)
		}
	}

	if fuzzIterations <= 0 {
		fuzzIterations = 100
	}

	fuzzer := scanner.NewFuzzEngine(fuzzIterations)
	output := fuzzer.Fuzz(files)
	defer fuzzer.Cleanup(files)

	fuzzer.RunTests(files)

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	if output.Errors > 0 {
		os.Exit(1)
	}

	return nil
}

func runTestGen(cmd *cobra.Command, args []string) error {
	_, err := loadConfig()
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
		fmt.Fprintf(os.Stderr, "Found %d issue(s) — trust score %d/100\n",
			result.Summary.TotalIssues, result.TrustScore)
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
	if err := writeOutput(data, outFile); err != nil {
		return err
	}

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

func runIntent(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if cfg.LLM.APIKey == "" {
		return fmt.Errorf("LLM API key required — set OPENAI_API_KEY or ANTHROPIC_API_KEY")
	}

	llmCfg := llm.ProviderConfig{
		Model:       cfg.LLM.Model,
		Temperature: cfg.LLM.Temperature,
		APIKey:      cfg.LLM.APIKey,
		BaseURL:     cfg.LLM.BaseURL,
	}
	llmProvider := llm.NewProvider(cfg.LLM.Provider, llmCfg)

	diffOpts := types.DiffOptions{
		Staged: staged,
		From:   from,
		To:     to,
	}

	files, err := scanner.GetDiff(diffOpts)
	if err != nil {
		return fmt.Errorf("getting diff: %w", err)
	}

	analyzer := scanner.NewIntentAnalyzer(llmProvider)
	results, err := analyzer.Analyze(context.Background(), files, diffOpts)
	if err != nil {
		return fmt.Errorf("intent analysis: %w", err)
	}

	output := map[string]interface{}{
		"results": results,
		"total":   len(results),
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	totalIssues := 0
	for _, r := range results {
		totalIssues += len(r.Findings)
	}
	if totalIssues > 0 {
		fmt.Fprintf(os.Stderr, "\nFound %d intent mismatch(es)\n", totalIssues)
		os.Exit(1)
	}

	return nil
}

func runFingerprint(cmd *cobra.Command, args []string) error {
	var files []types.DiffFile

	if fingerprintAll {
		var goFiles []string
		filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() && strings.HasPrefix(info.Name(), ".") && path != "." {
				return filepath.SkipDir
			}
			if strings.HasSuffix(path, ".go") {
				goFiles = append(goFiles, path)
			}
			return nil
		})
		for _, gf := range goFiles {
			if strings.HasSuffix(gf, "_test.go") || strings.HasSuffix(gf, "_fuzz_test.go") || strings.HasSuffix(gf, "_trusty_test.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Clean(gf))
			if err != nil {
				continue
			}
			files = append(files, types.DiffFile{
				Path:     gf,
				Language: "go",
				Content:  string(data),
			})
		}
	} else {
		diffOpts := types.DiffOptions{
			Staged: staged,
			From:   from,
			To:     to,
		}
		var err error
		files, err = scanner.GetDiff(diffOpts)
		if err != nil {
			return fmt.Errorf("getting diff: %w", err)
		}
	}

	fp := scanner.NewFingerprinter()
	var results []scanner.FingerprintResult

	for _, f := range files {
		if f.Language != "go" && f.Language != "python" && f.Language != "javascript" && f.Language != "typescript" {
			continue
		}
		result := fp.Analyze(f.Content, f.Path)
		results = append(results, result)
	}

	output := map[string]interface{}{
		"files":  results,
		"total":  len(results),
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	return nil
}

func runWatch(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
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

	dirs := args
	w := scanner.NewWatcher(cfg, s, dirs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	return w.Watch(ctx)
}

func runPRComment(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trusty pr-comment <scan-result.json>")
	}

	data, err := os.ReadFile(filepath.Clean(args[0]))
	if err != nil {
		return fmt.Errorf("reading scan result: %w", err)
	}

	client := prcomment.New()
	body := prcomment.BuildCommentBody(data)

	if err := client.Post(body); err != nil {
		return fmt.Errorf("posting PR comment: %w", err)
	}

	fmt.Println("PR comment posted successfully.")
	return nil
}

func runTUI(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return tui.RunFromFile(args[0])
	}

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
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

	return tui.Run(s, diffOpts)
}

func runAudit(cmd *cobra.Command, args []string) error {
	limit, _ := cmd.Flags().GetInt("limit")
	status, _ := cmd.Flags().GetString("status")
	since, _ := cmd.Flags().GetString("since")
	asJSON, _ := cmd.Flags().GetBool("json")

	trail := audit.New(".trusty-audit.jsonl")
	entries, err := trail.Query(limit, status, since)
	if err != nil {
		return fmt.Errorf("reading audit trail: %w", err)
	}

	if entries == nil {
		fmt.Println("No audit entries found. Run trusty scan --track first.")
		return nil
	}

	if asJSON {
		data, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Printf("\n%-30s %-20s %-12s %-10s %-8s %s\n",
		"Timestamp", "User", "Command", "Score", "Issues", "Status")
	fmt.Println(strings.Repeat("-", 90))
	for _, e := range entries {
		fmt.Printf("%-30s %-20s %-12s %-10d %-8d %s\n",
			e.Timestamp, e.User, e.Command, e.TrustScore, e.TotalIssues, e.Status)
	}
	fmt.Printf("\n%d entries\n", len(entries))
	return nil
}

func runSBOM(cmd *cobra.Command, args []string) error {
	allMods, _ := cmd.Flags().GetBool("all")
	outPath, _ := cmd.Flags().GetString("output")

	if allMods {
		mods, err := sbom.FindGoMods(".")
		if err != nil {
			return fmt.Errorf("finding go.mod files: %w", err)
		}
		if len(mods) == 0 {
			return fmt.Errorf("no go.mod files found")
		}
		type moduleSBOM struct {
			Path string `json:"path"`
			BOM  json.RawMessage `json:"bom"`
		}
		var results []moduleSBOM
		for _, mod := range mods {
			data, err := sbom.GenerateGoSBOM(filepath.Dir(mod))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", mod, err)
				continue
			}
			results = append(results, moduleSBOM{
				Path: mod,
				BOM:  data,
			})
		}
		output, _ := json.MarshalIndent(results, "", "  ")
		if outPath != "" {
			return os.WriteFile(filepath.Clean(outPath), output, 0644)
		}
		fmt.Println(string(output))
		return nil
	}

	data, err := sbom.GenerateGoSBOM(".")
	if err != nil {
		// Try go.sum fallback
		data2, err2 := sbom.GenerateFromGoSum("go.sum")
		if err2 != nil {
			return fmt.Errorf("generating SBOM (tried go.mod: %v, go.sum: %v)", err, err2)
		}
		data = data2
	}

	if outPath != "" {
		return os.WriteFile(filepath.Clean(outPath), data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func runPolicyCheck(cmd *cobra.Command, args []string) error {
	policyPath, _ := cmd.Flags().GetString("policy")
	inputPath, _ := cmd.Flags().GetString("input")
	useOPA, _ := cmd.Flags().GetBool("opa")

	var findings []types.Finding

	if inputPath != "" {
		data, err := os.ReadFile(filepath.Clean(inputPath))
		if err != nil {
			return fmt.Errorf("reading input: %w", err)
		}
		var scanResult types.ScanResult
		if err := json.Unmarshal(data, &scanResult); err != nil {
			var findingsOnly []types.Finding
			if err2 := json.Unmarshal(data, &findingsOnly); err2 != nil {
				return fmt.Errorf("parsing input (tried result: %v, findings: %v)", err, err2)
			}
			findings = findingsOnly
		} else {
			for _, f := range scanResult.Files {
				findings = append(findings, f.Findings...)
			}
		}
	} else {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		s := scanner.NewScanner(cfg, nil)
		diffOpts := types.DiffOptions{Staged: staged, From: from, To: to, Base: base, Head: head}
		result, err := s.Scan(context.Background(), diffOpts)
		s.FlushCache()
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
		for _, f := range result.Files {
			findings = append(findings, f.Findings...)
		}
	}

	if useOPA {
		result, err := policy.EvaluateViaOPA(policyPath, findings)
		if err != nil {
			return fmt.Errorf("OPA evaluation: %w", err)
		}
		fmt.Println(result)
		return nil
	}

	policies, err := policy.LoadPolicies(policyPath)
	if err != nil {
		// Try alternate paths
		policies, err = policy.LoadPolicies("policy.yml")
		if err != nil {
			return fmt.Errorf("loading policies from %s (tried policy.yml): %w", policyPath, err)
		}
	}

	violations := policy.Evaluate(findings, policies)
	output := map[string]interface{}{
		"findings_count":   len(findings),
		"policies_count":   len(policies),
		"violations_count": len(violations),
		"violations":       violations,
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))

	if len(violations) > 0 {
		os.Exit(1)
	}
	return nil
}

func runDashboard(cmd *cobra.Command, args []string) error {
	outPath, _ := cmd.Flags().GetString("output")
	asJSON, _ := cmd.Flags().GetBool("json")

	if asJSON {
		data, err := dashboard.WriteJSON(".trusty-audit.jsonl")
		if err != nil {
			return fmt.Errorf("generating dashboard JSON: %w", err)
		}
		fmt.Println(data)
		return nil
	}

	if err := dashboard.WriteToFile(".trusty-audit.jsonl", outPath); err != nil {
		return fmt.Errorf("generating dashboard: %w", err)
	}

	fmt.Printf("Dashboard written to %s\n", outPath)
	return nil
}
