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

- **3-tier scan engine**: Static analysis (ms), LLM semantic (s), behavioral verification (s-min)
- **Trust score**: Quantitative 0-100 score — auto-merge safe (90+), full review (< 50)
- **Security scanning**: SQL injection, XSS, hardcoded secrets, insecure crypto
- **Logic error detection**: Off-by-one, inverted conditionals, wrong variable usage
- **Hallucination detection**: Fake imports, non-existent APIs for Go/npm/PyPI
- **AI-code fingerprinting**: Statistical detection with 8 weighted signals
- **Auto-fix**: Apply fix suggestions directly to source files
- **30 CLI commands**: Scan, report, watch, TUI, CI integrations, and more
- **CI/CD ready**: GitHub Actions, GitLab CI, Jenkins, CircleCI auto-detection
- **Enterprise**: Audit trail, SBOM, policy-as-code, SSO, Helm chart, Slack/Jira integrations

## Documentation

| Topic | Link |
|-------|------|
| All CLI commands, flags, and examples | [docs/commands.md](docs/commands.md) |
| Architecture, trust score, project tree | [docs/architecture.md](docs/architecture.md) |
| Development setup, refactoring, Makefile | [docs/development.md](docs/development.md) |
| `.trusty.yml` config reference | [docs/configuration.md](docs/configuration.md) |
| GitHub Actions, GitLab CI integration | [docs/ci-integration.md](docs/ci-integration.md) |

## Why Trusty?

- **AI-generated code has 1.7x more issues** than human code (Stanford/MIT 2026)
- **1.75x more logic errors**, **1.57x more security findings**
- **67% of devs spend extra time debugging AI code** that's "almost right"
- **75% of tech leaders expect severe AI-code debt** by 2027

## License

MIT — Free for personal and commercial use.
