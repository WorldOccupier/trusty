# Architecture

## 3-Tier Scan Engine

```
Tier 1: Static Analysis (milliseconds)
  ├── AST parsing & type checking
  ├── Import/dependency validation
  ├── Error handling inspection
  ├── Nil safety analysis
  └── Pattern matching for known AI error signatures

Tier 2: LLM Semantic Analysis (seconds)
  ├── Diff + context sent to LLM
  ├── Specialized prompts for AI-code failure patterns
  ├── Hallucinated API detection
  ├── Plausible-but-wrong logic identification
  └── Cross-file context awareness

Tier 3: Behavioral Verification (seconds-minutes)
  ├── Function signature analysis
  ├── Input validation checking
  ├── Error handling patterns
  └── Nil/map safety verification
```

## Trust Score

Trusty calculates a quantitative **trust score** (0-100) for each scan:

| Score | Meaning | Action |
|-------|---------|--------|
| 90-100 | High confidence | Auto-merge safe |
| 70-89 | Moderate confidence | Quick human review |
| 50-69 | Low confidence | Full review required |
| 0-49 | Untrusted | Block merge, investigate |

Score = 100 - (errors x 15 + warnings x 7 + infos x 3), min 0.

## Project Structure

```
trusty/
├── cmd/trusty/
│   ├── main.go                     # Entry point (67 lines): imports, vars, root command
│   ├── commands.go                 # All 30 cobra.Command definitions + registration
│   ├── helpers.go                  # Shared helper functions (loadConfig, loadScanResult, etc.)
│   ├── handlers_scan.go            # Core scan command handlers (runScan, runSecurity, runLogic, etc.)
│   ├── handlers_analysis.go        # Analysis handlers (runFuzz, runTestGen, runIntent, runFingerprint)
│   ├── handlers_admin.go           # Admin handlers (runInit, runWatch, runAudit, runSBOM, runCI, etc.)
│   └── handlers_integration.go     # Integration handlers (runPRComment, runSlack, runJira, runWeb, etc.)
├── internal/
│   ├── scanner/                    # Core 3-tier scan engine
│   │   ├── scanner.go              # Orchestrator + ScanAllPackages
│   │   ├── diff.go                 # Git diff parsing + ParseDiffContent
│   │   ├── static.go               # Tier 1: AST analysis
│   │   ├── semantic.go             # Tier 2: LLM-based analysis
│   │   ├── verify.go               # Tier 3: Behavioral verification
│   │   ├── security.go             # Security vulnerability scanner
│   │   ├── logic.go                # Logic error detection
│   │   ├── logic_go.go             # Go AST logic checks
│   │   ├── logic_edge.go           # Python/JS edge case checks
│   │   ├── testgen.go              # Test contract generation
│   │   ├── fuzz.go                 # Property-based fuzz testing
│   │   ├── fingerprint.go          # AI-code fingerprinting (core)
│   │   ├── fingerprint_signals.go  # Signal analysis methods
│   │   ├── fingerprint_helpers.go  # Pattern matching helpers
│   │   ├── intent.go               # LLM-based intent verification
│   │   ├── cache.go                # Incremental SHA256 content-hash cache
│   │   ├── regression.go           # Regression tracking (.trusty-history.json)
│   │   └── watch.go                # Fsnotify file watcher
│   ├── hallucination/              # Hallucination detection
│   │   ├── detector.go             # Detection logic
│   │   └── registry.go             # Package registry client
│   ├── audit/                      # Audit trail (JSONL)
│   │   └── audit.go
│   ├── sbom/                       # CycloneDX SBOM generation
│   │   └── sbom.go
│   ├── dashboard/                  # HTML dashboard from audit data
│   │   └── dashboard.go
│   ├── sso/                        # SSO/SAML config + middleware
│   │   └── sso.go
│   ├── report/                     # Output formatting
│   │   ├── json.go                 # JSON output + ParseResult
│   │   ├── sarif.go                # SARIF v2.1.0 output
│   │   ├── html.go                 # HTML report generation
│   │   └── score.go                # Trust score models
│   ├── config/                     # .trusty.yml parsing
│   │   └── config.go
│   ├── llm/                        # LLM provider abstraction
│   │   ├── provider.go             # Interface + factory
│   │   ├── openai.go               # OpenAI GPT-4o
│   │   ├── anthropic.go            # Anthropic Claude
│   │   └── ollama.go               # Local inference
│   ├── policy/                     # Team policy overlay + engine
│   │   ├── policy.go               # Policy overlay (file/URL)
│   │   └── engine.go               # YAML policy engine + OPA
│   ├── ci/                         # CI platform auto-detection + pipeline runner
│   │   ├── ci.go
│   │   └── comment.go
│   ├── validate/                   # Environment and config validation
│   │   └── validate.go
│   ├── hook/                       # Pre-commit/pre-push git hook management
│   │   └── hook.go
│   ├── merge/                      # Auto-merge gate (scan + policy + regression)
│   │   └── merge.go
│   ├── server/                     # Live web dashboard server (SSE + REST API)
│   │   └── server.go
│   ├── slack/                      # Slack webhook notification
│   │   └── slack.go
│   ├── jira/                       # Jira ticket creation
│   │   └── jira.go
│   ├── mrcomment/                  # GitLab MR comment posting
│   │   └── gitlab.go
│   ├── prcomment/                  # GitHub PR comment posting
│   ├── plugin/                     # Go plugin system
│   │   └── plugin.go
│   ├── tui/                        # Bubble Tea TUI
│   │   └── tui.go
│   └── types/                      # Shared types
│       └── types.go
├── Dockerfile                      # Multi-stage build
├── helm/trusty/                    # Helm chart
│   ├── Chart.yaml, values.yaml
│   └── templates/                  # deployment.yaml, service.yaml
├── .gitlab-ci.yml                  # GitLab CI template
├── vscode-trusty/                  # VS Code extension scaffolding
│   ├── package.json
│   └── extension.js
├── .github/actions/trusty/         # GitHub Action
├── go.mod
└── README.md
```

## Key Design Decisions

- `trusty scan` runs all scanners (static, hallucination, security, logic) as tier 1.
- Findings from `security` and `logic` are aggregated per-file alongside static analysis results.
- Cache uses SHA256 content hash, persisted to `.trusty-cache.json`. Disable with `--no-cache`.
- Fuzz tests generate `_fuzz_test.go` files with `defer recover()` wrappers.
- Test contracts generate `_trusty_test.go` files (not `_test.go`) to avoid conflicts.
- Fingerprint uses 8 weighted signals; scores >= 70 = "likely-ai".
- Intent requires LLM API key; passes commit messages as context.
- All detection commands exit 1 when issues found — suitable for CI gating.
- `scan --diff-file` accepts a pre-generated git diff from file/stdin, bypassing git repo dependency.
- `--output` / `-o` flag writes JSON output to a file instead of stdout.
- Shell completions available natively via cobra.
- Regression tracking stores score history in `.trusty-history.json`.
- Team policies overlay a YAML policy (min_score) on top of local config.
- Distributed scan discovers Go modules in subdirectories and runs scan per package.
- Plugin system provides Checker interface + Go plugin loader.
