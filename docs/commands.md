# Trusty CLI Commands

All commands exit 1 when findings are present (not just below score threshold). Use for CI gating.

## `trusty scan`

3-tier scan (static + LLM + behavioral).

```bash
# Scan staged changes (default)
trusty scan

# Scan entire directory recursively (all supported languages)
trusty scan --dir .
trusty scan --dir /path/to/code --format sarif --output results.json

# Scan specific files or directories (non-git mode)
trusty scan main.go lib.py app.js src/

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

### Extended flags

```bash
# Track regression history
trusty scan --track

# Scan all Go modules in workspace
trusty scan --all-packages

# Overlay team policy from file
trusty scan --policy-file ./team-policy.yml

# Overlay team policy from URL
trusty scan --policy-url https://example.com/org-policy.yml
```

**Key flags:** `--staged, --dir, --from, --to, --base, --head, --format, --output, --min-score, --no-cache, --diff-file, --track, --all-packages, --policy-file, --policy-url`

## `trusty fix`

Auto-apply fix suggestions from scan results directly to source files. Each finding's `Suggestion` field is used as the fix when available; built-in fix templates cover 50+ rule types across all supported languages.

```bash
# Save scan results, then apply fixes
trusty scan --output results.json
trusty fix results.json

# Preview fixes without modifying files
trusty fix results.json --dry-run

# Confirm each fix before applying
trusty fix results.json --interactive

# Specify source directory (default: .)
trusty fix results.json --dir /path/to/project

# Pipeline: scan entire directory and auto-fix
trusty scan --dir . --output results.json && trusty fix results.json
```

**Mechanically auto-fixed rules** (line-level replacement):
- `none-comparison` — `== None` → `is None` in Python
- `var-usage` — `var` → `const` in JavaScript
- `missing-radix` — appends `, 10` to `parseInt()` calls
- `console-log`, `system-out-println` — comments out the line
- `redundant-equality` — strips `== True` in Python
- `bare-except` — `except:` → `except Exception:`
- `bare-exception-catch` — adds `as e` to bare exception catches
- `missing-deferred-close` / `missing-defer-close` — inserts `defer X.Close()` line

All other rules provide a descriptive suggestion to manually apply.

**Key flags:** `--dry-run, --interactive, --dir`

## `trusty init`

Scaffold `.trusty.yml` in current directory (refuses to overwrite).

```bash
trusty init
```

## `trusty hallu`

Hallucinated import detection.

```bash
# Check staged changes for hallucinated imports
trusty hallu

# Check specific commits
trusty hallu --from HEAD~1 --to HEAD

# Write results to file
trusty hallu --output hallu-results.json
```

**Key flags:** `--staged, --from, --to, --output`

## `trusty install-hook`

Install pre-commit/pre-push git hooks.

```bash
# Install a pre-commit hook that runs trusty scan --staged
trusty install-hook

# Install a pre-push hook instead
trusty install-hook --type pre-push

# Force overwrite existing hook
trusty install-hook --force

# Uninstall a hook
trusty install-hook --uninstall
```

**Key flags:** `--type, --force, --uninstall`

## `trusty report`

Generate report in various formats.

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

**Key flags:** `--format, --min-score, --staged, --output`

## `trusty security`

Vulnerability scan (SQL injection, XSS, hardcoded secrets, etc.).

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

**Key flags:** `--staged, --from, --to, --min-severity, --output`

## `trusty logic`

Logic error detection (off-by-one, inverted conditionals, wrong variable usage, etc.).

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

**Key flags:** `--staged, --from, --to, --min-severity, --output`

## `trusty testgen`

Generate behavioral test contracts from function signatures.

```bash
# Generate behavioral tests for changed functions
trusty testgen

# Generate and run tests
trusty testgen --run

# Output tests to a specific directory
trusty testgen --output ./tests
```

**Key flags:** `--staged, --from, --to`

## `trusty fuzz`

Property-based fuzz testing with random input generation.

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

**Key flags:** `--staged, --dir, --iterations`

## `trusty fingerprint`

Statistical AI-code fingerprinting (8 weighted signals, 0-100 score).

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

**Key flags:** `--staged, --all, --from, --to`

## `trusty intent`

LLM-based intent verification — flag mismatches between commit messages and code.

```bash
# Verify code matches commit intent (requires LLM API key)
trusty intent

# Check staged changes against intent
trusty intent --staged

# Check specific commits
trusty intent --from HEAD~1 --to HEAD
```

**Key flags:** `--staged, --from, --to`

## `trusty watch`

Auto-scan on file change using fsnotify.

```bash
# Watch current directory and auto-scan on changes
trusty watch

# Watch a specific directory
trusty watch ./internal/scanner

# Watch multiple directories
trusty watch ./pkg/... ./cmd/...
```

## `trusty completion`

Generate shell completion scripts (cobra built-in).

```bash
trusty completion bash > /etc/bash_completion.d/trusty
trusty completion zsh > /usr/local/share/zsh/site-functions/_trusty
trusty completion fish > ~/.config/fish/completions/trusty.fish
```

## `trusty pr-comment`

Post formatted scan results as a GitHub PR comment via API.

```bash
trusty scan --output results.json
trusty pr-comment results.json
```

## `trusty tui`

Interactive Bubble Tea TUI for browsing findings per file.

```bash
# Launch interactive TUI with a fresh scan
trusty tui

# Browse existing scan results
trusty tui results.json
```

## `trusty audit`

View/query the append-only JSONL audit trail.

```bash
# View recent audit entries
trusty audit

# Show last 50 entries
trusty audit --limit 50

# Filter by status
trusty audit --status failed

# Output as JSON
trusty audit --json
```

**Key flags:** `--limit, --status, --since, --json`

## `trusty sbom`

Generate CycloneDX JSON SBOM from go.mod/go.sum.

```bash
# Generate CycloneDX SBOM from go.mod
trusty sbom

# Generate SBOM for all Go modules in workspace
trusty sbom --all

# Write to file
trusty sbom --output bom.json
```

**Key flags:** `--all, --output`

## `trusty policy`

Evaluate YAML policies or OPA policies against scan results.

```bash
# Evaluate YAML policy against live scan results
trusty policy --policy policy.yml

# Evaluate against existing findings
trusty scan --output findings.json
trusty policy --policy policy.yml --input findings.json

# Evaluate via OPA binary
trusty policy --policy policy.rego --opa
```

**Key flags:** `--policy, --input, --opa`

## `trusty dashboard`

Generate self-contained HTML dashboard with Chart.js score trends.

```bash
# Generate HTML dashboard from audit data
trusty dashboard

# Custom output path
trusty dashboard --output dashboard.html

# Output raw data as JSON
trusty dashboard --json
```

**Key flags:** `--output, --json`

## `trusty merge`

Combined scan + policy + regression gate. Exits 0 only if all three pass.

```bash
# Run scan + policy + regression as a single merge gate
trusty merge

# Set minimum trust score
trusty merge --min-score 80

# Enforce team policy
trusty merge --policy-file ./team-policy.yml

# Track regression history
trusty merge --track
```

**Key flags:** `--min-score, --policy-file, --track`

## `trusty web`

Live web dashboard server with SSE + REST API + optional SSO.

```bash
# Start the live web dashboard server
trusty web

# Custom port
trusty web --port 9090

# Enable SSO authentication
trusty web --sso --sso-config sso.yml
```

**Key flags:** `--port, --sso, --sso-config`

## `trusty slack`

Post scan results as rich Slack messages via Incoming Webhooks.

```bash
trusty scan --output results.json
trusty slack results.json

# Use a specific webhook URL
trusty slack results.json --webhook-url https://hooks.slack.com/services/...
```

**Key flags:** `--webhook-url`

## `trusty jira`

Create Jira issues per-file with findings via Jira REST API.

```bash
trusty scan --output results.json
trusty jira results.json

# Specify project key
trusty jira results.json --project MYPROJ
```

**Key flags:** `--project`

## `trusty mr-comment`

Post formatted scan results to GitLab merge requests.

```bash
trusty scan --output results.json
trusty mr-comment results.json
```

## `trusty ci`

Auto-detect CI platform from env vars and run scan + comment pipeline.

```bash
trusty ci
```

Detects GitHub Actions, GitLab CI, Jenkins, CircleCI from env vars. Runs scan and posts PR/MR comment on supported platforms.

## `trusty validate`

Validate config, git repo, LLM keys, and cache files (no short-circuit).

```bash
# Validate all checks
trusty validate

# Use custom config path
trusty validate --config .trusty.yml
```

**Key flags:** `--config`

Checks: config file validity, git repository status, LLM API key presence, cache file integrity.
