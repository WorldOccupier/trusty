package main

import (
	"github.com/spf13/cobra"
)

func initCommands(root *cobra.Command) {
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
		Long: `Auto-scan Go source files on change using fsnotify.

Examples:
  trusty watch                          # Watch current directory
  trusty watch ./internal/scanner       # Watch specific directory`,
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
		Args: cobra.ExactArgs(1),
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
		Long: `Generate HTML dashboard with score trends from .trusty-audit.jsonl.

Examples:
  trusty dashboard                      # Generate HTML dashboard
  trusty dashboard --output dashboard.html`,
		RunE: runDashboard,
	}
	dashboardCmd.Flags().StringP("output", "o", "trusty-dashboard.html", "Output file path")
	dashboardCmd.Flags().Bool("json", false, "Output data as JSON")

	fixCmd := &cobra.Command{
		Use:   "fix",
		Short: "Auto-apply fix suggestions from scan results",
		Long: `Apply fix suggestions from scan findings directly to source files.
Supports --dry-run to preview and --interactive to confirm each fix.

Examples:
  trusty scan --output results.json
  trusty fix results.json                    # Apply fixes
  trusty fix results.json --dry-run           # Preview fixes
  trusty fix results.json --interactive       # Confirm each fix`,
		RunE: runFix,
	}
	fixCmd.Flags().Bool("dry-run", false, "Preview fixes without applying")
	fixCmd.Flags().BoolP("interactive", "i", false, "Confirm each fix before applying")
	fixCmd.Flags().String("dir", ".", "Source directory root")

	compareCmd := &cobra.Command{
		Use:   "compare",
		Short: "Diff between two scan result files",
		Long: `Show new, fixed, and unchanged findings between two scans.

Examples:
  trusty scan --output baseline.json
  trusty scan --output current.json
  trusty compare baseline.json current.json`,
		Args: cobra.ExactArgs(2),
		RunE: runCompare,
	}
	compareCmd.Flags().Bool("json", false, "Output as JSON")

	upgradeCmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Check for and apply updates",
		Long: `Check the latest Trusty release on GitHub and upgrade
the installed binary.

Examples:
  trusty upgrade              # Check and upgrade
  trusty upgrade --check      # Only check for newer version`,
		RunE: runUpgrade,
	}
	upgradeCmd.Flags().Bool("check", false, "Only check for newer version, don't upgrade")

	var hookType string
	installHookCmd := &cobra.Command{
		Use:   "install-hook",
		Short: "Install a git hook to auto-scan code changes",
		Long: `Install a pre-commit or pre-push git hook that runs trusty scan --staged
before each commit or push.

Examples:
  trusty install-hook                    # Install pre-commit hook
  trusty install-hook --type pre-push    # Install pre-push hook
  trusty install-hook --force            # Overwrite existing hook
  trusty install-hook --uninstall        # Remove hook`,
		RunE: runInstallHook,
	}
	installHookCmd.Flags().StringVarP(&hookType, "type", "t", "pre-commit", "Hook type: pre-commit, pre-push")
	installHookCmd.Flags().Bool("force", false, "Overwrite existing hook")
	installHookCmd.Flags().Bool("uninstall", false, "Remove the hook instead of installing")

	mergeCmd := &cobra.Command{
		Use:   "merge",
		Short: "Combined scan + policy + regression CI merge gate",
		Long: `Run scan, policy checks, and regression tracking as a single CI merge gate.

Examples:
  trusty merge                           # Run all checks
  trusty merge --min-score 80            # Require minimum score
  trusty merge --policy-file policy.yml  # Enforce team policy`,
		RunE: runMerge,
	}
	mergeCmd.Flags().IntVarP(&minScore, "min-score", "m", 0, "Minimum trust score (0-100)")
	mergeCmd.Flags().StringVar(&policyFile, "policy-file", "", "Path to team policy YAML")
	mergeCmd.Flags().BoolVar(&trackRegression, "track", false, "Check regression history")

	webCmd := &cobra.Command{
		Use:   "web",
		Short: "Start live web dashboard server",
		Long: `Start a persistent HTTP server with a real-time dashboard,
REST API, and Server-Sent Events for live updates.

Examples:
  trusty web                          # Start on :8080
  trusty web --port 9090              # Custom port
  trusty web --sso                    # Enable SSO authentication`,
		RunE: runWeb,
	}
	webCmd.Flags().Int("port", 8080, "Server port")
	webCmd.Flags().Bool("sso", false, "Enable SSO authentication")
	webCmd.Flags().String("sso-config", "", "SSO config file path")

	slackCmd := &cobra.Command{
		Use:   "slack",
		Short: "Post scan results to Slack",
		Long: `Post scan results as a formatted message to a Slack channel
via Incoming Webhook.

Examples:
  trusty scan --output results.json
  trusty slack results.json
  trusty slack results.json --webhook-url https://hooks.slack.com/...`,
		Args: cobra.ExactArgs(1),
		RunE: runSlack,
	}
	slackCmd.Flags().String("webhook-url", "", "Slack webhook URL (or set SLACK_WEBHOOK_URL)")

	jiraCmd := &cobra.Command{
		Use:   "jira",
		Short: "Create Jira tickets from scan findings",
		Long: `Create Jira issues from scan findings automatically.
Uses JIRA_HOST, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_PROJECT env vars.

Examples:
  trusty scan --output results.json
  trusty jira results.json
  trusty jira results.json --project MYPROJ`,
		Args: cobra.ExactArgs(1),
		RunE: runJira,
	}
	jiraCmd.Flags().String("project", "", "Jira project key (or set JIRA_PROJECT)")

	mrCommentCmd := &cobra.Command{
		Use:   "mr-comment",
		Short: "Post scan results as a GitLab MR comment",
		Long: `Post formatted scan results as a comment on a GitLab merge request.
Uses CI_PROJECT_ID, CI_MERGE_REQUEST_IID, and GITLAB_TOKEN env vars.

Examples:
  trusty scan --output results.json
  trusty mr-comment results.json`,
		Args: cobra.ExactArgs(1),
		RunE: runMRComment,
	}

	ciCmd := &cobra.Command{
		Use:   "ci",
		Short: "Auto-detect CI platform and run the appropriate pipeline",
		Long: `Detect the current CI platform from environment variables and run
the appropriate pipeline: scan, PR/MR comment, and policy checks.

Supported platforms: GitHub Actions, GitLab CI, Jenkins, CircleCI

Examples:
  trusty ci                           # Auto-detect and run`,
		RunE: runCI,
	}

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate Trusty configuration and environment",
		Long: `Check that Trusty is properly configured and the environment
is ready for scanning. Validates config file, git repo, LLM API keys,
and cache file integrity.

Examples:
  trusty validate                     # Run all checks
  trusty validate --config .trusty.yml`,
		RunE: runValidate,
	}
	validateCmd.Flags().StringVarP(&cfgFile, "config", "c", "", "Config file path")

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
	root.AddCommand(fixCmd)
	root.AddCommand(compareCmd)
	root.AddCommand(upgradeCmd)
	root.AddCommand(installHookCmd)
	root.AddCommand(mergeCmd)
	root.AddCommand(webCmd)
	root.AddCommand(slackCmd)
	root.AddCommand(jiraCmd)
	root.AddCommand(mrCommentCmd)
	root.AddCommand(ciCmd)
	root.AddCommand(validateCmd)
}
