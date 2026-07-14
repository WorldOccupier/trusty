# Trusty — AI Code Verification CLI

Bridge the trust gap in AI-generated code.

AI coding assistants generate code that *looks* correct but contains subtle bugs, hallucinated APIs, logic errors, and security vulnerabilities. Trusty automatically verifies AI-generated code with a 3-tier engine: static analysis, LLM semantic analysis, and behavioral verification.

**Only 29% of developers trust AI-generated code** (Stack Overflow 2025). Trusty gives teams the confidence to ship faster.

## Quick Start

```bash
go install github.com/WorldOccupier/trusty/cmd/trusty@latest

# Scan staged changes
trusty scan

# Check for hallucinated imports
trusty hallu

# Detect security vulnerabilities
trusty security

# Detect logic errors
trusty logic

# AI-code fingerprinting
trusty fingerprint --all

# Scan with LLM analysis (requires API key)
export OPENAI_API_KEY="sk-..."
trusty scan --format sarif --min-score 80

# Generate default config
trusty init
```

## Features

### Phase 1 — Core Engine (Implemented)

- `scan` — Git diff analysis with 3-tier verification engine
- `hallu` — AI hallucination detection (fake imports, non-existent APIs)
- `report` — Structured output with SARIF, JSON, HTML, and trust scoring
- `init` — Scaffold `.trusty.yml` config file
- Config file (`.trusty.yml`) with rules, severity, exclusions
- Multi-language support (Go, Python, JavaScript/TypeScript)

### Phase 2 — Semantic Analysis (Implemented)

- [x] **Security vulnerability scan** — Detect SQL injection, XSS, hardcoded secrets, insecure crypto, missing input validation
- [x] **Logic error detection** — Detect off-by-one errors, wrong variable usage, inverted conditionals, missing edge cases
- [x] **Test contract generation** — Auto-generate behavioral property-based tests from function signatures and code analysis
- [x] **Fuzz testing** — Property-based fuzz testing with random input generation for exported Go functions
- [x] **Intent extraction** — Parse commit messages and code context via LLM; flag mismatches between described intent and implementation

### Phase 3 — Integration & UX (In Progress)

- [x] **GitHub Actions integration** — Composite action that gates PR merges based on trust score
- [x] **HTML report** — Beautiful, shareable HTML report with score bar and per-file findings
- [x] **Watch mode** — `trusty watch` — auto-scan on file change with fsnotify
- [x] **File-based diff input** — `scan --diff-file` accepts a pre-generated diff instead of reading from git
- [x] **Shell completions** — `trusty completion bash|zsh|fish|powershell` (cobra built-in)
- [ ] **GitLab CI integration** — Merge request decoration with findings
- [ ] **GitHub PR commenting** — Auto-comment on PRs with per-file findings and suggestions
- [ ] **TUI mode** — Interactive terminal UI (Bubble Tea) for browsing findings, applying fixes, and exploring scan results
- [ ] **VS Code extension** — Inline diagnostics via LSP protocol

### Phase 4 — Advanced (In Progress)

- [x] **AI-code fingerprinting** — Statistical detection of AI-generated code patterns (8 weighted signals, 0–100 score)
- [x] **Incremental cache** — Skip re-analysis of unchanged files via SHA256 content hash; `.trusty-cache.json`
- [x] **Multi-model LLM** — OpenAI, Anthropic Claude, local Ollama
- [ ] **Regression tracking** — Track trust scores across commits/branches; alert when score drops
- [ ] **Team policies** — Organization-wide `.trusty.yml` with enforced rules, minimum scores per repo/team
- [ ] **Distributed scan** — Parallel scanning across packages/microservices
- [ ] **Plugin system** — Lua or Go plugin API for custom checkers

### Phase 5 — Enterprise

- [ ] **Audit trail** — Log all scans, findings, and approvals for compliance
- [ ] **SBOM generation** — Generate software bill of materials from scan
- [ ] **Policy-as-code** — Rego/OPA-based verification policies
- [ ] **Dashboard** — Web UI for team-wide trust metrics and trends
- [ ] **SSO/SAML** — Enterprise authentication
- [ ] **On-prem deployment** — Helm chart for Kubernetes, Docker image

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

Trusty calculates a quantitative **trust score** (0–100) for each scan:

| Score | Meaning | Action |
|-------|---------|--------|
| 90-100 | High confidence | Auto-merge safe |
| 70-89 | Moderate confidence | Quick human review |
| 50-69 | Low confidence | Full review required |
| 0-49 | Untrusted | Block merge, investigate |

Score = 100 - (errors × 15 + warnings × 7 + infos × 3), min 0.

## Configuration

```yaml
# .trusty.yml
version: 1

scan:
  tiers: [1, 2, 3]
  min_score: 70
  languages: [go, python, typescript]

llm:
  provider: openai        # openai, anthropic, ollama
  model: gpt-4o
  temperature: 0.1

rules:
  hallucination:
    severity: error
  logic_errors:
    severity: warning
  security:
    severity: error

output:
  format: json            # json, sarif, html
  ci_mode: false
```

## Commands

### `trusty scan`

```bash
# Scan staged changes (default)
trusty scan

# Scan a specific commit range
trusty scan --from HEAD~3 --to HEAD

# Scan branch diff against base
trusty scan --base main --head feature-branch

# Set minimum trust score (fails if below)
trusty scan --min-score 80

# Output SARIF format (GitHub Advanced Security compatible)
trusty scan --format sarif --min-score 80

# Output HTML report
trusty scan --format html --output report.html

# Write JSON output to file
trusty scan --output results.json

# Scan from a pre-generated diff file (no git repo needed)
trusty scan --diff-file /tmp/changes.diff

# Disable incremental cache
trusty scan --no-cache

# Use custom config
trusty scan --config .trusty.yml

# Exit code 1 when issues found (CI gating)
trusty scan && echo "Clean" || echo "Issues found"
```

### `trusty init`

```bash
# Scaffold .trusty.yml in current directory (refuses to overwrite)
trusty init
```

### `trusty hallu`

```bash
# Check staged changes for hallucinated imports
trusty hallu

# Check specific commits
trusty hallu --from HEAD~1 --to HEAD

# Write results to file
trusty hallu --output hallu-results.json
```

### `trusty report`

```bash
# Generate SARIF report (GitHub Advanced Security)
trusty report --format sarif --min-score 80

# Generate JSON report
trusty report --format json --output results.json

# Generate HTML report (self-contained, dark theme)
trusty report --format html

# Scan and report with threshold
trusty report --staged --min-score 70
```

### `trusty security`

```bash
# Scan for security vulnerabilities in code changes
trusty security

# Scan with custom severity threshold
trusty security --min-severity high

# Check specific commits
trusty security --from HEAD~1 --to HEAD

# Write results to file
trusty security --output security-results.json
```

### `trusty logic`

```bash
# Detect logic errors in code changes
trusty logic

# Run logic analysis on specific commits
trusty logic --from HEAD~3 --to HEAD

# Filter by minimum severity
trusty logic --min-severity warning

# Write results to file
trusty logic --output logic-results.json
```

### `trusty testgen`

```bash
# Generate behavioral tests for changed functions
trusty testgen

# Generate and run tests
trusty testgen --run

# Output tests to a specific directory
trusty testgen --output ./tests
```

### `trusty fuzz`

```bash
# Fuzz all changed Go files
trusty fuzz

# Fuzz staged changes
trusty fuzz --staged

# Fuzz a specific directory
trusty fuzz --dir ./internal/scanner

# Set iterations per function
trusty fuzz --iterations 1000
```

### `trusty fingerprint`

```bash
# Analyze changed files for AI-generated code patterns
trusty fingerprint

# Analyze all tracked Go files in the repo
trusty fingerprint --all

# Analyze staged changes
trusty fingerprint --staged

# Analyze a specific commit range
trusty fingerprint --from HEAD~1 --to HEAD
```

### `trusty intent`

```bash
# Verify code matches commit intent (requires LLM API key)
trusty intent

# Check staged changes against intent
trusty intent --staged

# Check specific commits
trusty intent --from HEAD~1 --to HEAD
```

### `trusty watch`

```bash
# Watch current directory and auto-scan on changes
trusty watch

# Watch a specific directory
trusty watch ./internal/scanner

# Watch multiple directories
trusty watch ./pkg/... ./cmd/...
```

### `trusty completion`

```bash
# Generate shell completion scripts
trusty completion bash > /etc/bash_completion.d/trusty
trusty completion zsh > /usr/local/share/zsh/site-functions/_trusty
trusty completion fish > ~/.config/fish/completions/trusty.fish
```

## Architecture

```
trusty/
├── cmd/trusty/main.go              # CLI entry point (cobra)
├── internal/
│   ├── scanner/                    # Core 3-tier scan engine
│   │   ├── scanner.go              # Orchestrator
│   │   ├── diff.go                 # Git diff parsing + ParseDiffContent
│   │   ├── static.go               # Tier 1: AST analysis
│   │   ├── semantic.go             # Tier 2: LLM-based analysis
│   │   ├── verify.go               # Tier 3: Behavioral verification
│   │   ├── security.go             # Security vulnerability scanner
│   │   ├── logic.go                # Logic error detection
│   │   ├── testgen.go              # Test contract generation
│   │   ├── fuzz.go                 # Property-based fuzz testing
│   │   ├── fingerprint.go          # AI-code fingerprinting (8 signals)
│   │   ├── intent.go               # LLM-based intent verification
│   │   ├── cache.go                # Incremental SHA256 content-hash cache
│   │   └── watch.go                # Fsnotify file watcher
│   ├── hallucination/              # Hallucination detection
│   │   ├── detector.go             # Detection logic
│   │   └── registry.go             # Package registry client
│   ├── report/                     # Output formatting
│   │   ├── json.go                 # JSON output
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
│   └── types/                      # Shared types
│       └── types.go
├── .github/actions/trusty/         # GitHub Action
├── go.mod
└── README.md
```

## CI Integration

### GitHub Actions

```yaml
# .github/workflows/trusty.yml
name: Trusty Code Verification
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: ./.github/actions/trusty
        with:
          min-score: 70
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

## Why Trusty?

- **AI-generated code has 1.7x more issues** than human code (Stanford/MIT 2026)
- **1.75x more logic errors**, **1.57x more security findings**
- **67% of devs spend extra time debugging AI code** that's "almost right"
- **75% of tech leaders expect severe AI-code debt** by 2027
- **$120M+ invested** in code verification (Qodo raised $70M Series B in 2026)

The market is validated. The problem is painful. Trusty solves it — locally, openly, and precisely.

## License

MIT — Free for personal and commercial use.
