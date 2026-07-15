# AGENTS.md — Trusty Development Guide

## Quick Reference

```bash
go build ./...          # Build all packages
go vet ./...            # Static analysis checks
go run ./cmd/trusty/    # Run the CLI
```

## Project Structure

```
cmd/trusty/           — CLI entry point (cobra). All 30 commands defined here.
  main.go             — (67 lines) Package, vars, root command, main()
  commands.go         — (498 lines) All cobra.Command definitions + registration
  helpers.go          — (83 lines) loadConfig, loadScanResult, severity helpers
  handlers_scan.go    — (389 lines) Core scan command handlers
  handlers_analysis.go— (230 lines) Fingerprint, intent, testgen, fuzz handlers
  handlers_admin.go   — (269 lines) CI, validate, audit, SBOM, upgrade handlers
  handlers_integration.go — (366 lines) Slack, Jira, MR, merge, web, fix handlers
internal/
  scanner/            — Core scan engines
    scanner.go        — Orchestrator (3 tiers + security + logic + cache + regression)
    diff.go           — Git diff parsing
    static.go         — Tier 1: AST-based static analysis
    semantic.go       — Tier 2: LLM-based semantic analysis
    verify.go         — Tier 3: Behavioral verification
    security.go       — Security vulnerability scanner
    logic.go          — (182 lines) Types, NewLogicDetector, Detect
    logic_go.go       — (211 lines) Go AST check functions
    logic_edge.go     — (179 lines) Edge case and infinite loop checks
    testgen.go        — Test contract generation (_trusty_test.go)
    fuzz.go           — Property-based fuzz testing (_fuzz_test.go)
    fingerprint.go    — (92 lines) Core Fingerprinter types + Analyze
    fingerprint_signals.go — (369 lines) Signal analysis methods
    fingerprint_helpers.go — (131 lines) Pattern matching helpers
    intent.go         — Intent extraction (LLM-based commit/code mismatch detection)
    cache.go          — Incremental content-hash cache (.trusty-cache.json)
    regression.go     — Regression tracking (.trusty-history.json)
    watch.go          — Fsnotify-based file watcher
  hallucination/      — Hallucination import detection
  audit/              — Audit trail (JSONL append-only log)
  sbom/               — CycloneDX SBOM generation
  dashboard/          — HTML dashboard from audit data
  sso/                — SSO/SAML config + middleware
  report/             — Output formatting (json, sarif, html, score)
  config/             — .trusty.yml parsing
  llm/                — LLM provider abstraction (openai, anthropic, ollama)
  policy/             — Team policy overlay + YAML policy engine
  prcomment/          — GitHub PR comment posting
  plugin/             — Plugin system (Checker interface + .so loader)
  ci/                 — CI platform auto-detection + pipeline runner
  validate/           — Environment and config validation
  hook/               — Pre-commit/pre-push git hook management
  merge/              — Auto-merge gate (scan + policy + regression)
  server/             — Live web dashboard server (SSE + REST API)
  slack/              — Slack webhook notification
  jira/               — Jira ticket creation
  mrcomment/          — GitLab MR comment posting
  tui/                — Bubble Tea TUI for browsing findings
  types/              — Shared type definitions
Makefile              — Build/test timing, profiling, coverage, lint
Dockerfile            — Multi-stage Docker build
docs/                 — Detailed documentation (commands, architecture, etc.)
helm/trusty/          — Helm chart (deployment, service, config)
.gitlab-ci.yml        — GitLab CI template
vscode-trusty/        — VS Code extension scaffolding
.github/actions/trusty/ — GitHub composite action
```

## CLI Commands

See [docs/commands.md](docs/commands.md) for full documentation.

## Documentation

Detailed docs are in the `docs/` directory:

- [docs/commands.md](docs/commands.md) — All commands, flags, examples
- [docs/architecture.md](docs/architecture.md) — 3-tier engine, trust score, project tree
- [docs/development.md](docs/development.md) — Dev setup, refactoring, Makefile, env vars
- [docs/configuration.md](docs/configuration.md) — `.trusty.yml` config reference
- [docs/ci-integration.md](docs/ci-integration.md) — GitHub Actions, GitLab CI integration

## Code Conventions

- No comments in production code unless necessary.
- Use existing patterns from neighboring files.
- Imports: stdlib first, then third-party, then internal.
- Errors: wrap with `fmt.Errorf("context: %w", err)`.
- No external test packages — use internal test packages (`package foo`, not `package foo_test`).
- New scanner features go in `internal/scanner/` as a new file.
- New output formats go in `internal/report/`.
- New LLM providers go in `internal/llm/` and register in `provider.go`.
- `filepath.Clean()` used on all user-supplied paths for security.
- All Go files must be under 500 lines.

## Config (.trusty.yml)

```yaml
llm:
  provider: openai          # openai, anthropic, ollama
  model: gpt-4o
rules:
  hallucination:
    severity: error
  logic_errors:
    severity: warning
  security:
    severity: error
output:
  format: json              # json, sarif, html
```

## Key Design Decisions

- `trusty scan` runs all scanners (static, hallucination, security, logic) as tier 1.
- Findings from `security` and `logic` are aggregated per-file alongside static analysis results.
- Cache uses SHA256 content hash, persisted to `.trusty-cache.json`. Disable with `--no-cache`.
- Fuzz tests generate `_fuzz_test.go` files with `defer recover()` wrappers.
- Test contracts generate `_trusty_test.go` files (not `_test.go`) to avoid conflicts.
- Fingerprint uses 8 weighted signals; scores >= 70 = "likely-ai".
- Intent requires LLM API key; passes commit messages as context.
- **Exit codes**: all detection commands exit 1 when issues found — suitable for CI gating.
- **Diff file**: `scan --diff-file` accepts a pre-generated git diff from file/stdin, bypassing git repo dependency.
- **Output file**: `--output` / `-o` flag writes JSON to file instead of stdout.
- **Shell completions**: available natively via cobra: `trusty completion bash | source`
- **Regression tracking**: `scan --track` stores score history in `.trusty-history.json`.
- **Team policies**: `scan --policy-file` / `--policy-url` overlays YAML policy on local config.
- **Distributed scan**: `scan --all-packages` discovers Go modules in subdirectories.
- **Plugin system**: `internal/plugin/` provides Checker interface + Go plugin loader.
- **PR commenting**: `pr-comment <file.json>` posts formatted results as GitHub PR comment.
- **TUI mode**: `trusty tui` launches a Bubble Tea terminal UI.
- **Audit trail**: `trusty audit` reads/writes `.trusty-audit.jsonl` — append-only JSONL.
- **SBOM**: `trusty sbom` generates CycloneDX JSON from `go.mod`/`go.sum`.
- **Policy engine**: `trusty policy` evaluates YAML policies with OPA integration.
- **Dashboard**: `trusty dashboard` generates self-contained HTML with Chart.js.
- **SSO/SAML**: `internal/sso/` provides OIDC/SAML/GitHub/Google auth middleware.
- **Git hooks**: `trusty install-hook` writes pre-commit/pre-push hook scripts.
- **Merge gate**: `trusty merge` runs scan + policy + regression; exits 0 only if all pass.
- **Web server**: `trusty web` HTTP server with SSE real-time updates + optional SSO.
- **Slack**: `trusty slack` sends rich messages via Incoming Webhooks.
- **Jira**: `trusty jira` creates issues per-file via Jira REST API.
- **GitLab MR**: `trusty mr-comment` posts formatted results to GitLab MR.
- **CI auto-detection**: `trusty ci` detects GitHub/GitLab/Jenkins/CircleCI from env vars.
- **Validate**: `trusty validate` checks config, git, LLM key, cache — no short-circuit.
- **Comprehensive tests**: unit tests for scanner/static, security, logic, config, report, ci.
- **cmd/trusty split**: 1841-line main.go split into 7 files (< 500 lines each).
- **scanner split**: fingerprint.go (584 lines → 3 files), logic.go (562 lines → 3 files).
- **Makefile**: `make time-build` / `make time-test` for performance tracking.
- **os.Exit refactoring**: all `os.Exit(1)` converted to `return fmt.Errorf(...)`.
- **Docker**: Multi-stage Dockerfile (golang:1.24-alpine → alpine:3.19, 8MB).
- **Helm**: `helm/trusty/` chart with deployment, service, config, secrets.

## Module Path

`github.com/WorldOccupier/trusty`

## Environment Variables

- `OPENAI_API_KEY` — OpenAI API key (default provider)
- `ANTHROPIC_API_KEY` — Anthropic API key
- `CI` — when `true`, enables CI mode
- `GITHUB_TOKEN` — GitHub API token (for PR commenting)
- `GITLAB_TOKEN` — GitLab API token (for MR commenting)
- `GITHUB_ACTIONS` / `GITLAB_CI` / `JENKINS_URL` / `CIRCLECI` — CI detection
