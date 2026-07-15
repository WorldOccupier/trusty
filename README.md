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

# Run a demo with sample AI-generated code issues
trusty demo

# Scan with LLM analysis (requires API key)
export OPENAI_API_KEY="sk-..."
trusty scan --format sarif --min-score 80

# Interactive config setup
trusty init --interactive
```

## Performance

| Metric | Value |
|--------|-------|
| Cold build | 3.70s |
| Warm build | 0.14s |
| Binary size (stripped) | ~11MB |
| Scan 100 files | < 500ms |
| CI setup time | 2s (binary download) |

## Features

### Core Scanning
| Feature | Status |
|---------|--------|
| 3-tier scan engine (static + LLM + behavioral) | ✅ |
| Trust score (0-100) | ✅ |
| Multi-language (Go, Python, JS/TS) | ✅ |
| Security vulnerability scanning | ✅ |
| Logic error detection | ✅ |
| Hallucinated import detection | ✅ |
| AI-code fingerprinting (8 signals) | ✅ |
| Intent verification via LLM | ✅ |
| Test contract generation | ✅ |
| Fuzz testing | ✅ |

### CLI & UX
| Feature | Status |
|---------|--------|
| 30 CLI commands | ✅ |
| SARIF / JSON / HTML output | ✅ |
| Watch mode (fsnotify) | ✅ |
| TUI for browsing findings | ✅ |
| Shell completions | ✅ |
| `trusty demo` — sample project with known issues | ✅ |
| `trusty explain` — detailed finding explanations | ✅ |
| `trusty init --interactive` — guided setup | ✅ |
| VS Code extension | ✅ |
| VS Code auto-scan on save | ✅ |

### Integrations
| Feature | Status |
|---------|--------|
| GitHub Actions (composite action) | ✅ |
| GitLab CI (`.gitlab-ci.yml`) | ✅ |
| GitHub PR commenting | ✅ |
| GitLab MR commenting | ✅ |
| Slack webhook notifications | ✅ |
| Jira ticket creation | ✅ |
| CI auto-detection (GitHub/GitLab/Jenkins/CircleCI) | ✅ |

### Enterprise
| Feature | Status |
|---------|--------|
| Audit trail (append-only JSONL) | ✅ |
| CycloneDX SBOM generation | ✅ |
| Policy-as-code (YAML DSL + OPA) | ✅ |
| Self-contained HTML dashboard | ✅ |
| SSO/SAML middleware | ✅ |
| Auto-fix suggestions | ✅ |
| Scan comparison / diff | ✅ |
| Self-update (`trusty upgrade`) | ✅ |
| Pre-commit hooks | ✅ |
| Auto-merge gate | ✅ |
| Live web server (SSE + REST API) | ✅ |
| Helm chart | ✅ |
| Docker multi-stage build | ✅ |

## Documentation

| Topic | Link |
|-------|------|
| All CLI commands, flags, and examples | [docs/commands.md](docs/commands.md) |
| Architecture, trust score, project tree | [docs/architecture.md](docs/architecture.md) |
| Development setup, refactoring, Makefile | [docs/development.md](docs/development.md) |
| `.trusty.yml` config reference | [docs/configuration.md](docs/configuration.md) |
| GitHub Actions, GitLab CI integration | [docs/ci-integration.md](docs/ci-integration.md) |
| Feature plan and roadmap | [docs/roadmap.md](docs/roadmap.md) |

## Why Trusty?

[![codecov](https://codecov.io/gh/WorldOccupier/trusty/graph/badge.svg?token=TRUSTY_TOKEN)](https://codecov.io/gh/WorldOccupier/trusty)

- **AI-generated code has 1.7x more issues** than human code (Stanford/MIT 2026)
- **1.75x more logic errors**, **1.57x more security findings**
- **67% of devs spend extra time debugging AI code** that's "almost right"
- **75% of tech leaders expect severe AI-code debt** by 2027

## License

MIT — Free for personal and commercial use.
