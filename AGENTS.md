# AGENTS.md — Trusty Development Guide

## Quick Reference

```bash
go build ./...          # Build all packages
go vet ./...            # Static analysis checks
go run ./cmd/trusty/    # Run the CLI
```

## Project Structure

```
cmd/trusty/main.go    — CLI entry point (cobra). All 10 commands defined here.
internal/
  scanner/            — Core scan engines
    scanner.go        — Orchestrator (3 tiers + security + logic + cache)
    diff.go           — Git diff parsing
    static.go         — Tier 1: AST-based static analysis
    semantic.go       — Tier 2: LLM-based semantic analysis
    verify.go         — Tier 3: Behavioral verification
    security.go       — Security vulnerability scanner (SQLi, XSS, secrets, etc.)
    logic.go          — Logic error detector (off-by-one, inverted conditionals, etc.)
    testgen.go        — Test contract generation (_trusty_test.go)
    fuzz.go           — Property-based fuzz testing (_fuzz_test.go)
    fingerprint.go    — AI-code fingerprinting (statistical pattern analysis)
    intent.go         — Intent extraction (LLM-based commit/code mismatch detection)
    cache.go          — Incremental content-hash cache (.trusty-cache.json)
    watch.go          — Fsnotify-based file watcher
  hallucination/      — Hallucinated import detection (Go/npm/PyPI registries)
  report/             — Output formatting
    json.go, sarif.go, html.go, score.go
  config/             — .trusty.yml parsing
    config.go
  llm/                — LLM provider abstraction
    provider.go       — Interface + factory (openai, anthropic, ollama)
    openai.go, anthropic.go, ollama.go
  types/              — Shared type definitions
    types.go
.github/actions/trusty/  — GitHub composite action
```

## CLI Commands

| Command       | Description | Key Flags |
|---------------|-------------|-----------|
| `scan`        | 3-tier scan (static + LLM + behavioral) | `--staged, --from, --to, --base, --head, --format, --output, --min-score, --no-cache, --diff-file` |
| `hallu`       | Hallucinated import detection | `--staged, --from, --to, --output` |
| `report`      | Generate report (json/sarif/html) | `--format, --min-score, --staged, --output` |
| `security`    | Vulnerability scan | `--staged, --from, --to, --min-severity, --output` |
| `logic`       | Logic error detection | `--staged, --from, --to, --min-severity, --output` |
| `testgen`     | Generate test contracts | `--staged, --from, --to` |
| `fuzz`        | Property-based fuzz testing | `--staged, --dir, --iterations` |
| `fingerprint` | AI-code fingerprinting | `--staged, --all, --from, --to` |
| `intent`      | Intent verification via LLM | `--staged, --from, --to` |
| `watch`       | Auto-scan on file change | `[dirs...]` |
| `init`        | Scaffold .trusty.yml | (none) |
| `completion`  | Shell completions (bash/zsh/fish) | (cobra built-in) |

**Exit codes**: All detection commands exit 1 when findings are present (not just below score threshold). Use for CI gating.

## Code Conventions

- No comments in production code unless necessary.
- Use existing patterns from neighboring files.
- Imports: stdlib first, then third-party, then internal.
- Errors: wrap with `fmt.Errorf("context: %w", err)`.
- No external test packages — use internal test packages (`package foo`, not `package foo_test`).
- New scanner features go in `internal/scanner/` as a new file.
- New output formats go in `internal/report/`.
- New LLM providers go in `internal/llm/` and register in `provider.go`.

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
- **Exit codes**: all detection commands (`scan`, `security`, `logic`, `hallu`, `intent`, `fuzz`) exit 1 when issues found — suitable for CI gating.
- **Diff file**: `scan --diff-file` accepts a pre-generated git diff from file/stdin, bypassing git repo dependency. `ParseDiffContent()` in `diff.go` is the exported parser.
- **Output file**: `--output` / `-o` flag on `scan`, `report`, `security`, `logic`, `hallu` writes JSON output to a file instead of stdout. `scan --format html --output report.html` also works.
- **Shell completions**: available natively via cobra: `trusty completion bash | source`

## Module Path

`github.com/WorldOccupier/trusty`

## Environment Variables

- `OPENAI_API_KEY` — OpenAI API key (default provider)
- `ANTHROPIC_API_KEY` — Anthropic API key (when `provider: anthropic`)
- `CI` — when `true`, enables CI mode (set automatically in GitHub Actions)
