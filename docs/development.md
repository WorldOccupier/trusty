# Development

## Refactoring Decisions

The original `cmd/trusty/main.go` was split into 7 files by concern:

| File | Lines | Purpose |
|------|-------|---------|
| `main.go` | 67 | Package imports, global vars, root command, `main()` |
| `commands.go` | 498 | All 30 cobra.Command definitions + registration |
| `helpers.go` | 83 | `loadConfig`, `loadScanResult`, severity helpers |
| `handlers_scan.go` | 389 | Core scan command handlers |
| `handlers_analysis.go` | 230 | Fingerprint, intent, testgen, fuzz handlers |
| `handlers_admin.go` | 269 | CI, validate, audit, SBOM, upgrade handlers |
| `handlers_integration.go` | 366 | Slack, Jira, MR, merge, web, fix handlers |

The original `internal/scanner/fingerprint.go` (584 lines) was split into 3 files:
- `fingerprint.go` (92 lines): types, NewFingerprinter, Analyze
- `fingerprint_signals.go` (369 lines): 7 signal analysis methods
- `fingerprint_helpers.go` (131 lines): pattern matching helpers

The original `internal/scanner/logic.go` (562 lines) was split into 3 files:
- `logic.go` (182 lines): types, NewLogicDetector, Detect
- `logic_go.go` (211 lines): Go AST check functions
- `logic_edge.go` (179 lines): edge case and infinite loop checks

All Go files are < 500 lines.

### Navigation

- **Add a command**: edit `commands.go` (definition) + relevant handler file (implementation)
- **Change root behavior**: edit `main.go` only
- **Review handler logic**: open specific handler file without scrolling past 500 lines

## Dev Tooling (Makefile)

A `Makefile` provides build timing, test timing, profiling, and code quality targets:

```bash
# Build timing (cold vs warm)
make time-build
# Example output:
#   Cold build (no cache): 3.70s
#   Warm build (with cache): 0.14s

# Test timing
make time-test

# Run all tests
make test

# Race detector
make test-race

# Benchmarks with memory allocation stats
make bench

# Code coverage
make coverage

# Profiling
make profile-cpu       # CPU profile of scanner benchmarks
make profile-mem       # Memory profile
make profile-trace     # Execution trace
make profile-web       # Open CPU profile in browser

# Code quality
make vet
make lint              # Requires golangci-lint

# File size analysis
make files             # Show largest Go files (top 20)

# Clean build artifacts and caches
make clean
```

Build performance tracking enables regression detection — if a commit introduces a build slowdown, `make time-build` catches it immediately.

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

## Environment Variables

- `OPENAI_API_KEY` — OpenAI API key (default provider)
- `ANTHROPIC_API_KEY` — Anthropic API key (when `provider: anthropic`)
- `CI` — when `true`, enables CI mode (set automatically in CI)
- `GITHUB_TOKEN` — GitHub API token (for PR commenting)
- `GITLAB_TOKEN` — GitLab API token (for MR commenting)
- `GITHUB_ACTIONS` — set by GitHub Actions; detected by `ci` command
- `GITLAB_CI` — set by GitLab CI; detected by `ci` command
- `JENKINS_URL` / `JENKINS_HOME` — set by Jenkins; detected by `ci` command
- `CIRCLECI` — set by CircleCI; detected by `ci` command
